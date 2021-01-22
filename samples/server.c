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

#define _GNU_SOURCE
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <openssl/md5.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/time.h>

#include "common.h"
#include "libvfio-user.h"
#include "tran_sock.h"

struct dma_regions {
    uint64_t addr;
    uint64_t len;
    uint32_t prot;
};

#define NR_DMA_REGIONS  96

struct server_data {
    time_t bar0;
    void *bar1;
    size_t bar1_size;
    struct dma_regions regions[NR_DMA_REGIONS];
    struct {
        __u64 pending_bytes;

        /*
         * TODO must be maximum size of migration data read, we'll use that to
         * create the migration region.
         */
        size_t migr_data_len;

        vfu_migr_state_t state;
    } migration;
};

static void
_log(vfu_ctx_t *vfu_ctx UNUSED, UNUSED int level, char const *msg)
{
    fprintf(stderr, "server: %s\n", msg);
}

static int
arm_timer(vfu_ctx_t *vfu_ctx, time_t t)
{
    struct itimerval new = {.it_value.tv_sec = t - time(NULL) };
    vfu_log(vfu_ctx, LOG_DEBUG, "arming timer to trigger in %ld seconds",
            new.it_value.tv_sec);
    if (setitimer(ITIMER_REAL, &new, NULL) != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to arm timer: %m");
        return -errno;
    }
    return 0;
}

ssize_t
bar0_access(vfu_ctx_t *vfu_ctx, char * const buf, size_t count, loff_t offset,
            const bool is_write)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (count != sizeof(time_t) || offset != 0) {
        vfu_log(vfu_ctx, LOG_ERR, "bad BAR0 access %#lx-%#lx",
                offset, offset + count - 1);
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

ssize_t
bar1_access(vfu_ctx_t *vfu_ctx, char * const buf,
            size_t count, loff_t offset,
            const bool is_write)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (offset + count > server_data->bar1_size) {
        vfu_log(vfu_ctx, LOG_ERR, "bad BAR1 access %#lx-%#lx",
                offset, offset + count - 1);
        errno = EINVAL;
        return -1;
    }

    if (is_write) {
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
map_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len, uint32_t prot)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int idx;

    for (idx = 0; idx < NR_DMA_REGIONS; idx++) {
        if (server_data->regions[idx].addr == 0 &&
            server_data->regions[idx].len == 0)
            break;
    }
    if (idx >= NR_DMA_REGIONS) {
        errx(EXIT_FAILURE, "Failed to add dma region, slots full\n");
    }

    server_data->regions[idx].addr = iova;
    server_data->regions[idx].len = len;
    server_data->regions[idx].prot = prot;
}

static int
unmap_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int idx;

    for (idx = 0; idx < NR_DMA_REGIONS; idx++) {
        if (server_data->regions[idx].addr == iova &&
            server_data->regions[idx].len == len) {
            server_data->regions[idx].addr = 0;
            server_data->regions[idx].len = 0;
            return 0;
        }
    }

    return -EINVAL;
}

void get_md5sum(unsigned char *buf, int len, unsigned char *md5sum)
{
	MD5_CTX ctx;

    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, len);
    MD5_Final(md5sum, &ctx);

    return;
}

/*
 * FIXME this function does DMA write/read using messages. This should be done
 * on a region that is not memory mappable or an area of a region that is not
 * sparsely memory mappable. We should also have a test where the server does
 * DMA directly on the client memory.
 */
static void do_dma_io(vfu_ctx_t *vfu_ctx, struct server_data *server_data)
{
    int count = 4096;
    unsigned char buf[count];
    unsigned char md5sum1[MD5_DIGEST_LENGTH], md5sum2[MD5_DIGEST_LENGTH];
    int i, ret;
    dma_sg_t sg;

    assert(vfu_ctx != NULL);

    ret = vfu_addr_to_sg(vfu_ctx, server_data->regions[0].addr, count, &sg,
                         1, PROT_WRITE);
    if (ret < 0) {
        errx(EXIT_FAILURE, "failed to map %#lx-%#lx: %s\n",
             server_data->regions[0].addr,
             server_data->regions[0].addr + count -1, strerror(-ret));
    }

    memset(buf, 'A', count);
    get_md5sum(buf, count, md5sum1);
    printf("%s: WRITE addr %#lx count %d\n", __func__,
           server_data->regions[0].addr, count);
    ret = vfu_dma_write(vfu_ctx, &sg, buf);
    if (ret < 0) {
        errx(EXIT_FAILURE, "vfu_dma_write failed: %s\n", strerror(-ret));
    }

    memset(buf, 0, count);
    printf("%s: READ  addr %#lx count %d\n", __func__,
           server_data->regions[0].addr, count);
    ret = vfu_dma_read(vfu_ctx, &sg, buf);
    if (ret < 0) {
        errx(EXIT_FAILURE, "vfu_dma_read failed: %s\n", strerror(-ret));
    }
    get_md5sum(buf, count, md5sum2);
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (md5sum2[i] != md5sum1[i]) {
            errx(EXIT_FAILURE, "DMA write and DMA read mismatch\n");
        }
    }
}

static int device_reset(vfu_ctx_t *vfu_ctx UNUSED)
{
    printf("device reset callback\n");

    return 0;
}

static int
migration_device_state_transition(vfu_ctx_t *vfu_ctx, vfu_migr_state_t state)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    int ret;

    printf("migration: transition to device state %d\n", state);

    switch (state) {
        case VFU_MIGR_STATE_STOP_AND_COPY:
            server_data->migration.pending_bytes = sizeof(time_t); /* FIXME BAR0 region size */
            break;
        case VFU_MIGR_STATE_PRE_COPY:
            /* TODO must be less than size of data region in migration region */
            server_data->migration.pending_bytes = server_data->bar1_size;
            break;
        case VFU_MIGR_STATE_STOP:
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

static __u64
migration_get_pending_bytes(vfu_ctx_t *vfu_ctx)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    return server_data->migration.pending_bytes;
}

static int
migration_prepare_data(vfu_ctx_t *vfu_ctx, __u64 *offset, __u64 *size)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    if (server_data->migration.state == VFU_MIGR_STATE_PRE_COPY) {
        assert(server_data->bar1_size >= server_data->migration.pending_bytes);
        *offset = server_data->bar1_size - server_data->migration.pending_bytes;
    } else if (server_data->migration.state == VFU_MIGR_STATE_STOP_AND_COPY) {
        *offset = 0;
    } else {
        assert(false); /* FIXME fail gracefully */
    }

    /*
     * Don't provide all migration data in one go in order to make it a bit
     * more interesting.
     */
    *size = MIN(server_data->migration.pending_bytes, server_data->migration.migr_data_len / 4);
    return 0;
}

static size_t
migration_read_data(vfu_ctx_t *vfu_ctx, void *buf, __u64 size, __u64 offset)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    uint8_t *p;
    size_t bar_size;

    /* FIXME need to validate data range */
    vfu_log(vfu_ctx, LOG_DEBUG, "read migration data %#llx-%#llx, %#llx remaining",
                offset, offset + size - 1, server_data->migration.pending_bytes);

    assert(size <= server_data->migration.pending_bytes);

    /*
     * If in pre-copy state we copy BAR1, if in stop-and-copy state we copy
     * BAR0. This behavior is purely an artifact of this server implementation
     * simply to make it as simple as possible. Note that the client might go
     * from state running to stop-and-copy, completely skipping the pre-copy
     * state. This is legitimate but we don't support it for now.
     *
     * FIXME implement transitioning from the running state straight to the
     * stop-and-copy state.
     */

    if (server_data->migration.state == VFU_MIGR_STATE_PRE_COPY) {
        p = server_data->bar1;
        bar_size = server_data->bar1_size;
    } else if (server_data->migration.state == VFU_MIGR_STATE_STOP_AND_COPY) {
        p = (uint8_t*)&server_data->bar0;
        bar_size = sizeof server_data->bar0;
    } else {
        /*
         * Reading from the migration region in any other state is undefined
         * (I think).
         */
        return 0;
    }
    if (offset > bar_size) {
        errno = EINVAL;
        return -1;
    }
    if (offset + size > bar_size) {
        size = bar_size - offset;
    }
    memcpy(buf, p + offset, size);
    server_data->migration.pending_bytes -= size;

    return size;
}

static size_t
migration_write_data(vfu_ctx_t *vfu_ctx, void *data, __u64 size, __u64 offset)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    assert(server_data != NULL);
    assert(data != NULL);

    /*
     * During pre-copy state we save BAR1 and during stop-and-copy state we
     * save BAR0.
     */
    vfu_log(vfu_ctx, LOG_DEBUG,
            "apply device migration data %#llx-%#llx",
            offset, offset + size - 1);

    if (offset < server_data->bar1_size) {
        __u64 _size = MIN(size, server_data->bar1_size - offset);
        memcpy(server_data->bar1 + offset, data, _size);
        offset += _size;
        size -= _size;
    }

    if (offset >= server_data->bar1_size && size > 0) {
        int ret;

        /* FIXME should be able to write any valid subrange */
        assert(offset - server_data->bar1_size == 0);
        assert(size == sizeof server_data->bar0);

        ret = bar0_access(vfu_ctx, data, sizeof server_data->bar0, 0, true);

        assert(ret == (int)size); /* FIXME */
    }

    return 0;
}


static int
migration_data_written(UNUSED vfu_ctx_t *vfu_ctx, UNUSED __u64 count,
                       UNUSED __u64 offset)
{
    /*
     * We apply migration state directly in the migration_write_data callback,
     * we don't need to do anything here. We would have to apply migration
     * state in this callback if the migration region was memory mappable, in
     * which we wouldn't know when the client wrote migration data.
     */

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    bool verbose = false;
    char opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    size_t bar1_size = 0x3000;
    struct server_data server_data = {
        .migration = {
            /* one page so that we can memory map it */
            .migr_data_len = bar1_size + sizeof(time_t),
            .state = VFU_MIGR_STATE_RUNNING
        }
    };
    vfu_ctx_t *vfu_ctx;
    FILE *fp;

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            default: /* '?' */
                errx(EXIT_FAILURE, "Usage: %s [-v] <socketpath>\n", argv[0]);
        }
    }

    if (optind >= argc) {
        errx(EXIT_FAILURE, "missing vfio-user socket path");
    }

    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        err(EXIT_FAILURE, "failed to register signal handler");
    }

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, argv[optind], 0, &server_data,
                             VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "failed to initialize device emulation\n");
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
                           &bar0_access, VFU_REGION_FLAG_RW, NULL, 0, -1);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup BAR0 region");
    }

    /*
     * Setup BAR1 to be 3 pages in size where only the first and the last pages
     * are mappable. The client can still mmap the 2nd page, we can't prohibit
     * this under Linux. If we really want to probihit it we have to use
     * separate files for the same region.
     */
    if ((fp = tmpfile()) == NULL) {
        err(EXIT_FAILURE, "failed to create BAR1 file");
    }
    server_data.bar1_size = 0x3000;
    if (ftruncate(fileno(fp), server_data.bar1_size) == -1) {
        err(EXIT_FAILURE, "failed to truncate BAR1 file");
    }
    server_data.bar1 = mmap(NULL, server_data.bar1_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fileno(fp), 0);
    if (server_data.bar1 == MAP_FAILED) {
        err(EXIT_FAILURE, "failed to mmap BAR1");
    }
    struct iovec mmap_areas[] = {
        { .iov_base  = (void*)0, .iov_len = 0x1000 },
        { .iov_base  = (void*)0x2000, .iov_len = 0x1000 }
    };
    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR1_REGION_IDX,
                           server_data.bar1_size, &bar1_access,
                           VFU_REGION_FLAG_RW, mmap_areas, 2, fileno(fp));
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup BAR1 region");
    }

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device reset callbacks");
    }

    ret = vfu_setup_device_dma_cb(vfu_ctx, &map_dma, &unmap_dma);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device DMA callbacks");
    }

    ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup irq counts");
    }

    vfu_migration_t migration = {
        .size = server_data.migration.migr_data_len,
        .mmap_areas = mmap_areas,
        .nr_mmap_areas = 2,
        .callbacks = {
            .transition = &migration_device_state_transition,
            .get_pending_bytes = &migration_get_pending_bytes,
            .prepare_data = &migration_prepare_data,
            .read_data = &migration_read_data,
            .data_written = &migration_data_written,
            .write_data = &migration_write_data
        }
    };

    ret = vfu_setup_device_migration(vfu_ctx, &migration);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to setup device migration");
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
        if (ret == -EINTR) {
            if (irq_triggered) {
                irq_triggered = false;
                vfu_irq_trigger(vfu_ctx, 0);

                ret = vfu_irq_message(vfu_ctx, 0);
                if (ret < 0) {
                    err(EXIT_FAILURE, "vfu_irq_message() failed");
                }

                do_dma_io(vfu_ctx, &server_data);
                ret = 0;
            }
        }
    } while (ret == 0);

    if (ret != -ENOTCONN && ret != -EINTR && ret != -ESHUTDOWN) {
        errx(EXIT_FAILURE, "failed to realize device emulation: %s\n",
             strerror(-ret));
    }

    vfu_destroy_ctx(vfu_ctx);
    return EXIT_SUCCESS;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
