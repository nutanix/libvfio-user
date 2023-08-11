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
#include "private.h"
#include "rte_hash_crc.h"
#include "tran_sock.h"

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
        uint64_t bytes_transferred;
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
static void do_dma_io(vfu_ctx_t *vfu_ctx, struct server_data *server_data)
{
    int count = 4096;
    unsigned char buf[count];
    uint32_t crc1, crc2;
    dma_sg_t *sg;
    int ret;

    sg = alloca(dma_sg_size());

    assert(vfu_ctx != NULL);

    ret = vfu_addr_to_sgl(vfu_ctx,
                          (vfu_dma_addr_t)server_data->regions[0].iova.iov_base,
                          count, sg, 1, PROT_WRITE);
    if (ret < 0) {
        err(EXIT_FAILURE, "failed to map %p-%p",
            server_data->regions[0].iova.iov_base,
            server_data->regions[0].iova.iov_base + count -1);
    }

    memset(buf, 'A', count);
    crc1 = rte_hash_crc(buf, count, 0);
    vfu_log(vfu_ctx, LOG_DEBUG, "%s: WRITE addr %p count %d", __func__,
           server_data->regions[0].iova.iov_base, count);
    ret = vfu_sgl_write(vfu_ctx, sg, 1, buf);
    if (ret < 0) {
        err(EXIT_FAILURE, "vfu_sgl_write failed");
    }

    memset(buf, 0, count);
    vfu_log(vfu_ctx, LOG_DEBUG, "%s: READ  addr %p count %d", __func__,
           server_data->regions[0].iova.iov_base, count);
    ret = vfu_sgl_read(vfu_ctx, sg, 1, buf);
    if (ret < 0) {
        err(EXIT_FAILURE, "vfu_sgl_read failed");
    }
    crc2 = rte_hash_crc(buf, count, 0);

    if (crc1 != crc2) {
        errx(EXIT_FAILURE, "DMA write and DMA read mismatch");
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
            server_data->migration.bytes_transferred = 0;
            break;
        case VFU_MIGR_STATE_PRE_COPY:
            server_data->migration.bytes_transferred = 0;
            break;
        case VFU_MIGR_STATE_STOP:
            /* FIXME should gracefully fail */
            if (server_data->migration.state == VFU_MIGR_STATE_STOP_AND_COPY) {
                assert(server_data->migration.bytes_transferred ==
                       server_data->bar1_size + sizeof(time_t));
            }
            break;
        case VFU_MIGR_STATE_RESUME:
            server_data->migration.bytes_transferred = 0;
            break;
        case VFU_MIGR_STATE_RUNNING:
            assert(server_data->migration.bytes_transferred ==
                   server_data->bar1_size + sizeof(time_t));
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

static ssize_t
migration_read_data(vfu_ctx_t *vfu_ctx, void *buf, uint64_t size)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);

    /*
     * If in pre-copy state we copy BAR1, if in stop-and-copy state we copy
     * both BAR1 and BAR0. Since we always copy BAR1 in the stop-and-copy state,
     * copying BAR1 in the pre-copy state is pointless. Fixing this requires
     * more complex state tracking which exceeds the scope of this sample.
     */

    uint32_t total_read = server_data->bar1_size;

    if (server_data->migration.state == VFU_MIGR_STATE_STOP_AND_COPY) {
        total_read += sizeof(server_data->bar0);
    }

    if (server_data->migration.bytes_transferred == total_read || size == 0) {
        vfu_log(vfu_ctx, LOG_DEBUG, "no data left to read");
        return 0;
    }

    uint32_t read_start = server_data->migration.bytes_transferred;
    uint32_t read_end = MIN(read_start + size, total_read); // exclusive
    assert(read_end > read_start);

    uint32_t bytes_read = read_end - read_start;

    if (read_end <= server_data->bar1_size) {
        // case 1: entire read lies within bar1
        // TODO check the following is always allowed

        memcpy(buf, server_data->bar1 + read_start, bytes_read);
    } else if (
        read_start < server_data->bar1_size // starts in bar1
        && read_end > server_data->bar1_size // ends in bar0
    ) {
        // case 2: part of the read in bar1 and part of the read in bar0
        // TODO check the following is always allowed

        uint32_t length_in_bar1 = server_data->bar1_size - read_start;
        uint32_t length_in_bar0 = read_end - server_data->bar1_size;
        assert(length_in_bar1 + length_in_bar0 == bytes_read);
        
        memcpy(buf, server_data->bar1 + read_start, length_in_bar1);
        memcpy(buf + length_in_bar1, &server_data->bar0, length_in_bar0);
    } else if (read_start >= server_data->bar1_size) {
        // case 3: entire read lies within bar0
        // TODO check the following is always allowed

        read_start -= server_data->bar1_size;
        read_end -= server_data->bar1_size;

        memcpy(buf, &server_data->bar0 + read_start, bytes_read);
    }

    server_data->migration.bytes_transferred += bytes_read;

    return bytes_read;
}

static ssize_t
migration_write_data(vfu_ctx_t *vfu_ctx, void *data, uint64_t size)
{
    struct server_data *server_data = vfu_get_private(vfu_ctx);
    char *buf = data;

    assert(server_data != NULL);
    assert(data != NULL);

    uint32_t total_write = server_data->bar1_size + sizeof(server_data->bar0);

    if (server_data->migration.bytes_transferred == total_write || size == 0) {
        return 0;
    }

    uint32_t write_start = server_data->migration.bytes_transferred;
    uint32_t write_end = MIN(write_start + size, total_write); // exclusive
    assert(write_end > write_start);

    uint32_t bytes_written = write_end - write_start;

    if (write_end <= server_data->bar1_size) {
        // case 1: entire write lies within bar1

        memcpy(server_data->bar1 + write_start, buf, bytes_written);
    } else if (write_start >= server_data->bar1_size) {
        // case 2: entire write lies within bar0

        write_start -= server_data->bar1_size;
        write_end -= server_data->bar1_size;

        memcpy(&server_data->bar0 + write_start, buf, bytes_written);
    } else {
        // case 3: part of the write in bar1 and part of the write in bar0

        uint32_t length_in_bar1 = server_data->bar1_size - write_start;
        uint32_t length_in_bar0 = write_end - server_data->bar1_size;
        assert(length_in_bar1 + length_in_bar0 == bytes_written);
        
        memcpy(server_data->bar1 + write_start, buf, length_in_bar1);
        memcpy(&server_data->bar0, buf + length_in_bar1, length_in_bar0);
    }

    server_data->migration.bytes_transferred += bytes_written;

    return bytes_written;
}

int main(int argc, char *argv[])
{
    char template[] = "/tmp/libvfio-user.XXXXXX";
    int ret;
    bool verbose = false;
    int opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    const size_t bar1_size = 0x3000;
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
        .read_data = &migration_read_data,
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
     */
    if ((tmpfd = mkstemp(template)) == -1) {
        err(EXIT_FAILURE, "failed to create backing file");
    }

    unlink(template);

    server_data.bar1_size = bar1_size;

    if (ftruncate(tmpfd, server_data.bar1_size) == -1) {
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

    ret = vfu_setup_device_migration_callbacks(vfu_ctx, &migr_callbacks);
    
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

                /*
                 * We also initiate some dummy DMA via an explicit message,
                 * again to show how DMA is done. This is used if the client's
                 * RAM isn't mappable or the server implementation prefers it
                 * this way.  Again, the client expects the server to send DMA
                 * messages right after it has triggered the IRQs.
                 */
                do_dma_io(vfu_ctx, &server_data);
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
