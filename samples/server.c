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

#include "../lib/muser.h"
#include "../lib/muser_priv.h"

struct dma_regions {
    uint64_t addr;
    uint64_t len;
};

#define NR_DMA_REGIONS  96

struct server_data {
    lm_ctx_t *lm_ctx;
    time_t bar0;
    uint8_t *bar1;
    struct dma_regions regions[NR_DMA_REGIONS];
    struct {
        __u64 pending_bytes;
        __u64 data_size;
        void *migr_data;
        size_t migr_data_len;
        lm_migr_state_t state; 
    } migration;
};

static void
_log(UNUSED void *pvt, UNUSED lm_log_lvl_t lvl, char const *msg)
{
    fprintf(stderr, "server: %s\n", msg);
}

static int
arm_timer(struct server_data *server_data, time_t t)
{
    struct itimerval new = {.it_value.tv_sec = t - time(NULL) };
    lm_log(server_data->lm_ctx, LM_DBG,
           "arming timer to trigger in %d seconds", new.it_value.tv_sec);
    if (setitimer(ITIMER_REAL, &new, NULL) != 0) {
        lm_log(server_data->lm_ctx, LM_ERR, "failed to arm timer: %m");
        return -errno;
    }
    return 0;
}

ssize_t
bar0_access(void *pvt, char * const buf, size_t count, loff_t offset,
            const bool is_write)
{
    struct server_data *server_data = pvt;

    if (count != sizeof(time_t) || offset != 0) {
        lm_log(server_data->lm_ctx, LM_ERR, "bad BAR0 access %#lx-%#lx",
               offset, offset + count - 1);
        errno = EINVAL;
        return -1;
    }

    if (is_write) {
        if (server_data->migration.state == LM_MIGR_STATE_RUNNING) {
            int ret = arm_timer(server_data, *(time_t*)buf);
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
bar1_access(UNUSED void *pvt, UNUSED char * const buf, UNUSED size_t count,
            UNUSED loff_t offset, UNUSED const bool is_write)
{
    assert(false);

    return -ENOTSUP;
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

static void map_dma(void *pvt, uint64_t iova, uint64_t len)
{
    struct server_data *server_data = pvt;
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
}

static int unmap_dma(void *pvt, uint64_t iova)
{
    struct server_data *server_data = pvt;
    int idx;

    for (idx = 0; idx < NR_DMA_REGIONS; idx++) {
        if (server_data->regions[idx].addr == iova) {
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
static void do_dma_io(lm_ctx_t *lm_ctx, struct server_data *server_data)
{
    int count = 4096;
    unsigned char buf[count];
    unsigned char md5sum1[MD5_DIGEST_LENGTH], md5sum2[MD5_DIGEST_LENGTH];
    int i, ret;
    dma_sg_t sg;

    assert(lm_ctx != NULL);

    ret = lm_addr_to_sg(lm_ctx, server_data->regions[0].addr, count, &sg,
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
    ret = lm_dma_write(lm_ctx, &sg, buf);
    if (ret < 0) {
        errx(EXIT_FAILURE, "lm_dma_write failed: %s\n", strerror(-ret));
    }

    memset(buf, 0, count);
    printf("%s: READ  addr %#lx count %d\n", __func__,
           server_data->regions[0].addr, count);
    ret = lm_dma_read(lm_ctx, &sg, buf);
    if (ret < 0) {
        errx(EXIT_FAILURE, "lm_dma_read failed: %s\n", strerror(-ret));
    }
    get_md5sum(buf, count, md5sum2);
    for(i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (md5sum2[i] != md5sum1[i]) {
            errx(EXIT_FAILURE, "DMA write and DMA read mismatch\n");
        }
    }
}

unsigned long map_area(UNUSED void *pvt, UNUSED unsigned long off,
                       UNUSED unsigned long len)
{
    assert(false);

    return 0;
}

static int device_reset(UNUSED void *pvt)
{
    printf("device reset callback\n");

    return 0;
}

static int
migration_device_state_transition(void *pvt, lm_migr_state_t state)
{
    int ret;
    struct server_data *server_data = pvt;

    printf("migration: transition to device state %d\n", state);

    switch (state) {
        case LM_MIGR_STATE_STOP_AND_COPY:
            /* TODO must be less than size of data region in migration region */
            server_data->migration.pending_bytes = sysconf(_SC_PAGESIZE);
            break;
        case LM_MIGR_STATE_STOP:
            assert(server_data->migration.pending_bytes == 0);
            break;
        case LM_MIGR_STATE_RESUME:
            break;
        case LM_MIGR_STATE_RUNNING:
            ret = arm_timer(server_data, server_data->bar0);
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
migration_get_pending_bytes(void *pvt)
{
    struct server_data *server_data = pvt;
    if (server_data->migration.data_size > 0) {
        assert(server_data->migration.data_size <= server_data->migration.pending_bytes);
        server_data->migration.pending_bytes -= server_data->migration.data_size;
    }
    return server_data->migration.pending_bytes;
}

static int
migration_prepare_data(void *pvt, __u64 *offset, __u64 *size)
{
    struct server_data *server_data = pvt;

    *offset = 0;
    *size = server_data->migration.data_size = MIN(server_data->migration.pending_bytes, server_data->migration.migr_data_len / 4);
    return 0;
}

static size_t
migration_read_data(void *pvt, void *buf, __u64 size, __u64 offset)
{
    struct server_data *server_data = pvt;

    if (server_data->migration.data_size < size) {
        lm_log(server_data->lm_ctx, LM_ERR,
               "invalid migration data read %#lx-%#lx",
               offset, offset + size - 1);
        return -EINVAL;
    }

    /* FIXME implement, client should be able to write any byte range */
    assert((offset == 0 && size >= sizeof server_data->bar0)
           || offset >= sizeof server_data->bar0);

    if (offset == 0 && size >= sizeof server_data->bar0) {
        memcpy(buf, &server_data->bar0, sizeof server_data->bar0);
    }
    return size;
}

static size_t
migration_write_data(void *pvt, void *data, __u64 size, __u64 offset)
{
    struct server_data *server_data = pvt;

    assert(server_data != NULL);
    assert(data != NULL);

    if (offset + size > server_data->migration.migr_data_len) {
        lm_log(server_data->lm_ctx, LM_ERR,
               "invalid write %#llx-%#llx", offset, offset + size - 1);
    }

    memcpy(server_data->migration.migr_data + offset, data, size);

    return 0;
}


static int
migration_data_written(void *pvt, __u64 count, __u64 offset)
{
    int ret;
    struct server_data *server_data = pvt;

    assert(server_data != NULL);

    if (offset + count > server_data->migration.migr_data_len) {
        lm_log(server_data->lm_ctx, LM_ERR,
               "bad migration data range %#llx-%#llx",
               offset, offset + count - 1);
        return -EINVAL;
    }

    if (offset == 0 && count >= sizeof server_data->bar0) {

        /* apply device state */
        /* FIXME must arm timer only after device is resumed!!! */
        ret = bar0_access(pvt, server_data->migration.migr_data,
                          sizeof server_data->bar0, 0, true);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int main(int argc, char *argv[]){
    int ret;
    bool verbose = false;
    char opt;
    struct sigaction act = {.sa_handler = _sa_handler};
    struct server_data server_data = {
        .migration = {
            /* one page so that we can memory map it */
            .migr_data_len = sysconf(_SC_PAGESIZE),
            .state = LM_MIGR_STATE_RUNNING
        }
    };
    int nr_sparse_areas = 2, size = 1024, i;
    struct lm_sparse_mmap_areas *sparse_areas;
    lm_ctx_t *lm_ctx;

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
        errx(EXIT_FAILURE, "missing MUSER socket path");
    }

    server_data.bar1 = malloc(sysconf(_SC_PAGESIZE));
    if (server_data.bar1 == NULL) {
        err(EXIT_FAILURE, "BAR1");
    }

    sparse_areas = calloc(1, sizeof(*sparse_areas) +
			  (nr_sparse_areas * sizeof(struct lm_mmap_area)));
    if (sparse_areas == NULL) {
        err(EXIT_FAILURE, "MMAP sparse areas ENOMEM\n");
    }
    sparse_areas->nr_mmap_areas = nr_sparse_areas;
    for (i = 0; i < nr_sparse_areas; i++) {
        sparse_areas->areas[i].start += size;
        sparse_areas->areas[i].size = size;
    }

    lm_dev_info_t dev_info = {
        .trans = LM_TRANS_SOCK,
        .log = verbose ? _log : NULL,
        .log_lvl = LM_DBG,
        .pci_info = {
            .reg_info[LM_DEV_BAR0_REG_IDX] = {
                .flags = LM_REG_FLAG_RW,
                .size = sizeof(time_t),
                .fn = &bar0_access
            },
            .reg_info[LM_DEV_BAR1_REG_IDX] = {
                .flags = LM_REG_FLAG_RW,
                .size = sysconf(_SC_PAGESIZE),
                .fn = &bar1_access,
                .mmap_areas = sparse_areas,
		        .map = map_area
            },
            .reg_info[LM_DEV_MIGRATION_REG_IDX] = { /* migration region */
                .flags = LM_REG_FLAG_RW,
                /* 
                 * FIXME don't declare support for migration via a region, this
                 * is a VFIO artifact, make it something different. We still
                 * have to make the migration data memory mappable.
                 */
                .size = sizeof(struct vfio_device_migration_info) + server_data.migration.migr_data_len,
                .mmap_areas = sparse_areas,
            },
            .irq_count[LM_DEV_INTX_IRQ_IDX] = 1,
        },
        .uuid = argv[optind],
        .reset = device_reset,
        .map_dma = map_dma,
        .unmap_dma = unmap_dma,
        .pvt = &server_data,
        .migration_callbacks = {
            .transition = &migration_device_state_transition,
            .get_pending_bytes = &migration_get_pending_bytes,
            .prepare_data = &migration_prepare_data,
            .read_data = &migration_read_data,
            .data_written = &migration_data_written,
            .write_data = &migration_write_data
        }
    };

    sigemptyset(&act.sa_mask);
    if (sigaction(SIGALRM, &act, NULL) == -1) {
        err(EXIT_FAILURE, "failed to register signal handler");
    }

    server_data.lm_ctx = lm_ctx = lm_ctx_create(&dev_info);
    if (lm_ctx == NULL) {
        err(EXIT_FAILURE, "failed to initialize device emulation\n");
    }

    server_data.migration.migr_data = aligned_alloc(server_data.migration.migr_data_len,
                                                    server_data.migration.migr_data_len);
    if (server_data.migration.migr_data == NULL) {
        errx(EXIT_FAILURE, "failed to allocate migration data");
    }

    do {
        ret = lm_ctx_drive(lm_ctx);
        if (ret == -EINTR) {
            if (irq_triggered) {
                irq_triggered = false;
                lm_irq_trigger(lm_ctx, 0);

                ret = lm_irq_message(lm_ctx, 0);
                if (ret < 0) {
                    err(EXIT_FAILURE, "lm_irq_message() failed");
                }

                do_dma_io(lm_ctx, &server_data);
                ret = 0;
            }
        }
    } while (ret == 0);
    if (ret != -ENOTCONN && ret != -EINTR && ret != -ESHUTDOWN) {
        errx(EXIT_FAILURE, "failed to realize device emulation: %s\n",
             strerror(-ret));
    }
    lm_ctx_destroy(lm_ctx);
    free(server_data.bar1);
    free(sparse_areas);
    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
