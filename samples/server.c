/*
 * Sample server to be tested with samples/client.c
 *
 * Copyright (c) 2020, Nutanix Inc. All rights reserved.
 *     Author: Thanos Makatos <thanos@nutanix.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "common.h"
#include "libvfio-user.h"
#include "rte_hash_crc.h"

struct dma_regions {
    struct iovec iova;
    uint32_t prot;
};

#define NR_DMA_REGIONS  96

struct server_data {
    time_t bar0;
    void *bar1;
    size_t bar1_size;
    struct dma_regions regions[NR_DMA_REGIONS];
    struct {
        uint64_t pending_bytes;
        vfu_migr_state_t state;
    } migration;
};

static void
_log(vfu_ctx_t *vfu_ctx UNUSED, UNUSED int level, char const *msg)
{
    fprintf(stderr, "server[%d]: %s\n", getpid(), msg);
}

static int
arm_timer(vfu_ctx_t *vfu_ctx, time_t t)
{
    struct itimerval new = {.it_value.tv_sec = t - time(NULL) };
    vfu_log(vfu_ctx, LOG_DEBUG, "arming timer to trigger in %ld seconds",
            new.it_value.tv_sec);
    if (setitimer(ITIMER_REAL, &new, NULL) != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to arm timer: %m");
        return -1;
    }
    return 0;
}

static ssize_t
bar0_access(vfu_ctx_t *vfu_ctx, char * const buf, size_t count, loff_t offset,
            const bool is_write)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (count != sizeof(time_t) || offset != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad BAR0 access %#llx-%#llx",
                (unsigned long long)offset,
                (unsigned long long)offset + count - 1);
        errno = EINVAL;
        return -1;
    }

    if (is_write) {
        if (server_data->migration.state == VFU_MIGR_STATE_RUNNING) {
            int ret = arm_timer(vfu_ctx, *(time_t*)buf);
            if (ret < 0) {
                return ret;
            }
        }
        memcpy(&server_data->bar0, buf, count);
    } else {
        time_t delta = time(NULL) - server_data->bar0;
        memcpy(buf, &delta, count);
    }

    return count;
}

static ssize_t
bar1_access(vfu_ctx_t *vfu_ctx, char * const buf,
            size_t count, loff_t offset,
            const bool is_write)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (offset + count > server_data->bar1_size) {
        vfu_log(vfu_ctx, LOG_ERR, "bad BAR1 access %#llx-%#llx",
                (unsigned long long)offset,
                (unsigned long long)offset + count - 1);
        errno = EINVAL;
        return -1;
    }

    if (is_write) {
        if (server_data->migration.state == VFU_MIGR_STATE_PRE_COPY) {
            /* dirty the whole thing */
            server_data->migration.pending_bytes = server_data->bar1_size;
        }
        memcpy(server_data->bar1 + offset, buf, count);
    } else {
        memcpy(buf, server_data->bar1, count);
    }

    return count;
}

bool irq_triggered = false;
static void _sa_handler(int signum)
{
    int _errno = errno;
    if (signum == SIGALRM) {
        irq_triggered = true;
    }
    errno = _errno;
}

static void
dma_register(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int idx;

    for (idx = 0; idx < NR_DMA_REGIONS; idx++) {
        if (server_data->regions[idx].iova.iov_base == NULL &&
            server_data->regions[idx].iova.iov_len == 0)
            break;
    }
    if (idx >= NR_DMA_REGIONS) {
        errx(EXIT_FAILURE, "Failed to add dma region, slots full");
    }

    server_data->regions[idx].iova = info->iova;
    server_data->regions[idx].prot = info->prot;
}

static void
dma_unregister(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int idx;

    for (idx = 0; idx < NR_DMA_REGIONS; idx++) {
        if (server_data->regions[idx].iova.iov_len == info->iova.iov_len &&
            server_data->regions[idx].iova.iov_base == info->iova.iov_base) {
            server_data->regions[idx].iova.iov_base = NULL;
            server_data->regions[idx].iova.iov_len = 0;
        }
    }
}

/*
 * FIXME this function does DMA write/read using messages. This should be done
 * on a region that is not memory mappable or an area of a region that is not
 * sparsely memory mappable. We should also have a test where the server does
 * DMA directly on the client memory.
 */
static void do_dma_io(vfu_ctx_t *vfu_ctx, struct server_data *server_data,
                      int region, bool use_messages)
{
    const int size = 1024;
    const int count = 4;
    unsigned char buf[size * count];
    uint32_t crc1, crc2;
    dma_sg_t *sg;
    void *addr;
    int ret;

    sg = alloca(dma_sg_size());

    assert(vfu_ctx != NULL);

    struct iovec iov = {0};

    /* Write some data, chunked into multiple calls to exercise offsets. */
    for (int i = 0; i < count; ++i) {
        addr = server_data->regions[region].iova.iov_base + i * size;
        ret = vfu_addr_to_sgl(vfu_ctx, (vfu_dma_addr_t)addr, size, sg, 1,
                              PROT_WRITE);
                              
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to map %p-%p", addr, addr + size - 1);
        }

        memset(&buf[i * size], 'A' + i, size);

        if (use_messages) {
            vfu_log(vfu_ctx, LOG_DEBUG, "%s: MESSAGE WRITE addr %p size %d",
                    __func__, addr, size);
            ret = vfu_sgl_write(vfu_ctx, sg, 1, &buf[i * size]);
            if (ret < 0) {
                err(EXIT_FAILURE, "vfu_sgl_write failed");
            }
        } else {
            vfu_log(vfu_ctx, LOG_DEBUG, "%s: DIRECT WRITE  addr %p size %d",
                    __func__, addr, size);
            ret = vfu_sgl_get(vfu_ctx, sg, &iov, 1, 0);
            if (ret < 0) {
                err(EXIT_FAILURE, "vfu_sgl_get failed");
            }
            assert(iov.iov_len == (size_t)size);
            memcpy(iov.iov_base, &buf[i * size], size);

            /*
             * When directly writing to client memory the server is responsible
             * for tracking dirty pages. We assert that all dirty writes are
             * within the first page of region 1. In fact, all regions are only
             * one page in size.
             * 
             * Note: this is not strictly necessary in this example, since we
             * later call `vfu_sgl_put`, which marks pages dirty if the SGL was
             * acquired with `PROT_WRITE`. However, `vfu_sgl_mark_dirty` is
             * useful in cases where the server needs to mark guest memory dirty
             * without releasing the memory with `vfu_sgl_put`.
             */
            vfu_sgl_mark_dirty(vfu_ctx, sg, 1);
            assert(region == 1);
            assert(i * size < (int)PAGE_SIZE);

            vfu_sgl_put(vfu_ctx, sg, &iov, 1);
        }
    }

    crc1 = rte_hash_crc(buf, sizeof(buf), 0);

    /* Read the data back at double the chunk size. */
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < count; i += 2) {
        addr = server_data->regions[region].iova.iov_base + i * size;
        ret = vfu_addr_to_sgl(vfu_ctx, (vfu_dma_addr_t)addr, size * 2, sg, 1,
                              PROT_READ);
        if (ret < 0) {
            err(EXIT_FAILURE, "failed to map %p-%p", addr, addr + 2 * size - 1);
        }

        if (use_messages) {
            vfu_log(vfu_ctx, LOG_DEBUG, "%s: MESSAGE READ  addr %p size %d",
                    __func__, addr, 2 * size);
            ret = vfu_sgl_read(vfu_ctx, sg, 1, &buf[i * size]);
            if (ret < 0) {
                err(EXIT_FAILURE, "vfu_sgl_read failed");
            }
        } else {
            vfu_log(vfu_ctx, LOG_DEBUG, "%s: DIRECT READ   addr %p size %d",
                    __func__, addr, 2 * size);
            ret = vfu_sgl_get(vfu_ctx, sg, &iov, 1, 0);
            if (ret < 0) {
                err(EXIT_FAILURE, "vfu_sgl_get failed");
            }
            assert(iov.iov_len == 2 * (size_t)size);
            memcpy(&buf[i * size], iov.iov_base, 2 * size);
            vfu_sgl_put(vfu_ctx, sg, &iov, 1);
        }
    }

    crc2 = rte_hash_crc(buf, sizeof(buf), 0);

    if (crc1 != crc2) {
        errx(EXIT_FAILURE, "DMA write and DMA read mismatch");
    } else {
        vfu_log(vfu_ctx, LOG_DEBUG, "%s: %s success", __func__,
                use_messages ? "MESSAGE" : "DIRECT");
    }
}

static int device_reset(vfu_ctx_t *vfu_ctx UNUSED, vfu_reset_type_t type UNUSED)
{
    vfu_log(vfu_ctx, LOG_DEBUG, "device reset callback");
    return 0;
}

static int
migration_device_state_transition(vfu_ctx_t *vfu_ctx, vfu_migr_state_t state)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int ret;
    struct itimerval new = { { 0 }, };

    vfu_log(vfu_ctx, LOG_DEBUG, "migration: transition to device state %d",
            state);

    switch (state) {
        case VFU_MIGR_STATE_STOP_AND_COPY:
            vfu_log(vfu_ctx, LOG_DEBUG, "disable timer");
            if (setitimer(ITIMER_REAL, &new, NULL) != 0) {
                err(EXIT_FAILURE, "failed to disable timer");
            }
            server_data->migration.pending_bytes = server_data->bar1_size + sizeof(time_t); /* FIXME BAR0 region size */
            break;
        case VFU_MIGR_STATE_PRE_COPY:
            /* TODO must be less than size of data region in migration region */
            server_data->migration.pending_bytes = server_data->bar1_size;
            break;
        case VFU_MIGR_STATE_STOP:
            /* FIXME should gracefully fail */
            assert(server_data->migration.pending_bytes == 0);
            break;
        case VFU_MIGR_STATE_RESUME:
            break;
        case VFU_MIGR_STATE_RUNNING:
            ret = arm_timer(vfu_ctx, server_data->bar0);
            if (ret < 0) {
                return ret;
            }
            break;
        default:
            assert(false); /* FIXME */
    }
    server_data->migration.state = state;
    return 0;
}

static uint64_t
migration_get_pending_bytes(vfu_ctx_t *vfu_ctx)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    return server_data->migration.pending_bytes;
}

static int
migration_prepare_data(vfu_ctx_t *vfu_ctx, uint64_t *offset, uint64_t *size)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    *offset = 0;
    if (size != NULL) {
       *size = server_data->migration.pending_bytes;
    }
    return 0;
}

static ssize_t
migration_read_data(vfu_ctx_t *vfu_ctx, void *buf,
                    uint64_t size, uint64_t offset)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (server_data->migration.state != VFU_MIGR_STATE_PRE_COPY &&
        server_data->migration.state != VFU_MIGR_STATE_STOP_AND_COPY)
    {
        return size;
    }

    /*
     * For ease of implementation we expect the client to read all migration
     * data in one go; partial reads are not supported. This is allowed by VFIO
     * however we don't yet support it. Similarly, when resuming, partial
     * writes are supported by VFIO, however we don't in this sample.
     *
     * If in pre-copy state we copy BAR1, if in stop-and-copy state we copy
     * both BAR1 and BAR0. Since we always copy BAR1 in the stop-and-copy state,
     * copying BAR1 in the pre-copy state is pointless. Fixing this requires
     * more complex state tracking which exceeds the scope of this sample.
     */

    if (offset != 0 || size != server_data->migration.pending_bytes) {
        errno = EINVAL;
        return -1;
    }

    memcpy(buf, server_data->bar1, server_data->bar1_size);
    if (server_data->migration.state == VFU_MIGR_STATE_STOP_AND_COPY) {
        memcpy(buf + server_data->bar1_size, &server_data->bar0,
               sizeof(server_data->bar0));
    }
    server_data->migration.pending_bytes = 0;

    return size;
}

static ssize_t
migration_write_data(vfu_ctx_t *vfu_ctx, void *data,
                     uint64_t size, uint64_t offset)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    char *buf = data;
    int ret;

    assert(server_data != NULL);
    assert(data != NULL);

    if (offset != 0 || size < server_data->bar1_size) {
        vfu_log(vfu_ctx, LOG_DEBUG, "XXX bad migration data write %#llx-%#llx",
                (unsigned long long)offset,
                (unsigned long long)offset + size - 1);
        errno = EINVAL;
        return -1;
    }

    memcpy(server_data->bar1, buf, server_data->bar1_size);
    buf += server_data->bar1_size;
    size -= server_data->bar1_size;
    if (size == 0) {
        return 0;
    }
    if (size != sizeof(server_data->bar0)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(&server_data->bar0, buf, sizeof(server_data->bar0));
    ret = bar0_access(vfu_ctx, buf, sizeof(server_data->bar0), 0, true);
    assert(ret == (int)size); /* FIXME */

    return 0;
}


static int
migration_data_written(UNUSED vfu_ctx_t *vfu_ctx, UNUSED uint64_t count)
{
    /*
     * We apply migration state directly in the migration_write_data callback,
     * so we don't need to do anything here. We would have to apply migration
     * state in this callback if the migration region was memory mappable, in
     * which case we wouldn't know when the client wrote migration data.
     */

    return 0;
}

static size_t
nr_pages(size_t size)
{
    return (size / sysconf(_SC_PAGE_SIZE) +
            (size % sysconf(_SC_PAGE_SIZE) > 1));
}

static size_t
page_align(size_t size)
{
    return  nr_pages(size) * sysconf(_SC_PAGE_SIZE);
}

int main(int argc, char *argv[])
{
    char template[] = "/tmp/libvfio-user.XXXXXX";
    int ret;
    bool verbose = false;
    int opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    const size_t bar1_size = 0x3000;
    size_t migr_regs_size, migr_data_size, migr_size;
    struct server_data server_data = {
        .migration = {
            .state = VFU_MIGR_STATE_RUNNING
        }
    };
    vfu_ctx_t *vfu_ctx;
    vfu_trans_t trans = VFU_TRANS_SOCK;
    int tmpfd;
    const vfu_migration_callbacks_t migr_callbacks = {
        .version = VFU_MIGR_CALLBACKS_VERS,
        .transition = &migration_device_state_transition,
        .get_pending_bytes = &migration_get_pending_bytes,
        .prepare_data = &migration_prepare_data,
        .read_data = &migration_read_data,
        .data_written = &migration_data_written,
        .write_data = &migration_write_data
    };

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            default: /* '?' */
                errx(EXIT_FAILURE, "Usage: %s [-v] <socketpath>", argv[0]);
        }
    }

    if (optind >= argc) {
        errx(EXIT_FAILURE, "missing vfio-user socket path");
    }

    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        err(EXIT_FAILURE, "failed to register signal handler");
    }

    if (strcmp(argv[optind], "pipe") == 0) {
        trans = VFU_TRANS_PIPE;
    }

    vfu_ctx = vfu_create_ctx(trans, argv[optind], 0, &server_data,
                             VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "failed to initialize device emulation");
    }

    ret = vfu_setup_log(vfu_ctx, _log, verbose ? LOG_DEBUG : LOG_ERR);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup log");
    }

    ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "vfu_pci_init() failed") ;
    }

    vfu_pci_set_id(vfu_ctx, 0xdead, 0xbeef, 0xcafe, 0xbabe);

    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX, sizeof(time_t),
                           &bar0_access, VFU_REGION_FLAG_RW, NULL, 0, -1, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup BAR0 region");
    }

    umask(0022);

    /*
     * Setup BAR1 to be 3 pages in size where only the first and the last pages
     * are mappable. The client can still mmap the 2nd page, we can't prohibit
     * this under Linux. If we really want to prohibit it we have to use
     * separate files for the same region.
     *
     * We choose to use a single file which contains both BAR1 and the migration
     * registers. They could also be completely different files.
     */
    if ((tmpfd = mkstemp(template)) == -1) {
        err(EXIT_FAILURE, "failed to create backing file");
    }

    unlink(template);

    server_data.bar1_size = bar1_size;

    /*
     * The migration registers aren't memory mappable, so in order to make the
     * rest of the migration region memory mappable we must effectively reserve
     * an entire page.
     */
    migr_regs_size = vfu_get_migr_register_area_size();
    migr_data_size = page_align(bar1_size + sizeof(time_t));
    migr_size = migr_regs_size + migr_data_size;

    if (ftruncate(tmpfd, server_data.bar1_size + migr_size) == -1) {
        err(EXIT_FAILURE, "failed to truncate backing file");
    }
    server_data.bar1 = mmap(NULL, server_data.bar1_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, tmpfd, 0);
    if (server_data.bar1 == MAP_FAILED) {
        err(EXIT_FAILURE, "failed to mmap BAR1");
    }
    struct iovec bar1_mmap_areas[] = {
        { .iov_base  = (void*)0, .iov_len = 0x1000 },
        { .iov_base  = (void*)0x2000, .iov_len = 0x1000 }
    };
    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR1_REGION_IDX,
                           server_data.bar1_size, &bar1_access,
                           VFU_REGION_FLAG_RW, bar1_mmap_areas, 2,
                           tmpfd, 0);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup BAR1 region");
    }

    /* setup migration */

    struct iovec migr_mmap_areas[] = {
        [0] = {
            .iov_base  = (void *)migr_regs_size,
            .iov_len = migr_data_size
        },
    };

    /*
     * The migration region comes after bar1 in the backing file, so offset is
     * server_data.bar1_size.
     */
    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_MIGR_REGION_IDX, migr_size,
                           NULL, VFU_REGION_FLAG_RW, migr_mmap_areas,
                           ARRAY_SIZE(migr_mmap_areas), tmpfd,
                           server_data.bar1_size);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup migration region");
    }

    ret = vfu_setup_device_migration_callbacks(vfu_ctx, &migr_callbacks,
                                               migr_regs_size);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device migration");
    }

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device reset callbacks");
    }

    ret = vfu_setup_device_dma(vfu_ctx, &dma_register, &dma_unregister);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device DMA callbacks");
    }

    ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup irq counts");
    }

    ret = vfu_realize_ctx(vfu_ctx);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to realize device");
    }

    ret = vfu_attach_ctx(vfu_ctx);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to attach device");
    }

    do {
        ret = vfu_run_ctx(vfu_ctx);
        if (ret == -1 && errno == EINTR) {
            if (irq_triggered) {
                irq_triggered = false;
                ret = vfu_irq_trigger(vfu_ctx, 0);
                if (ret < 0) {
                    err(EXIT_FAILURE, "vfu_irq_trigger() failed");
                }

                printf("doing dma io\n");

                /*
                 * We initiate some dummy DMA by directly accessing the client's
                 * memory. In this case, we keep track of dirty pages ourselves,
                 * as the client has no knowledge of what and when we have
                 * written to its memory.
                 */
                do_dma_io(vfu_ctx, &server_data, 1, false);
                
                /*
                 * We also do some dummy DMA via explicit messages to show how
                 * DMA is done if the client's RAM isn't mappable or the server
                 * implementation prefers it this way. In this case, the client
                 * is responsible for tracking pages that are dirtied, as it is
                 * the one actually performing the writes.
                 */
                do_dma_io(vfu_ctx, &server_data, 0, true);

                ret = 0;
            }
        }
    } while (ret == 0);

    if (ret == -1 &&
        errno != ENOTCONN && errno != EINTR && errno != ESHUTDOWN) {
        errx(EXIT_FAILURE, "failed to realize device emulation");
    }

    vfu_destroy_ctx(vfu_ctx);
    return EXIT_SUCCESS;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
