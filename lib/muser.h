/*
 * Copyright (c) 2019 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          Felipe Franciosi <felipe@nutanix.com>
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

#ifndef LIB_MUSER_H
#define LIB_MUSER_H

#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pci.h"

/**
 * lm_fops_t - driver callbacks
 *
 * @read:  read device configuration space
 * @write: write device configuration space
 * @mmap:  mmap device configuration space
 * @reset: reset the device
 */
typedef struct {
    ssize_t (*read) (void *pvt, const int index, char *buf, size_t count,
                     loff_t pos);
    ssize_t (*write) (void *pvt, const int index, char *buf, size_t count,
                      loff_t pos);
    unsigned long (*mmap) (void *pvt, unsigned long pgoff);
    int (*reset) (void *pvt);
} lm_fops_t;


/**
 * Callback function signatures for each regions.
 *
 * @lm_bar_access_t:     typedef for BAR access function.
 * @lm_non_bar_access_t: typedef for non-BAR(rom, pci config,
 *			 vga) access functions.
 */
typedef ssize_t (lm_bar_access_t) (void *pvt, const int region_index,
                                   char * const buf, size_t count,
                                   loff_t offset, const bool is_write);
typedef ssize_t (lm_non_bar_access_t) (void *pvt, char * const buf,
                                       size_t count, loff_t offset,
                                       const bool is_write);
typedef struct {
    uint32_t            irq_count[LM_DEV_NUM_IRQS];
    lm_reg_info_t	    reg_info[LM_DEV_NUM_REGS];

    /* Optional PCI region access callbacks. */
    lm_bar_access_t	    *bar_fn;
    lm_non_bar_access_t *rom_fn;
    lm_non_bar_access_t *pci_config_fn;
    lm_non_bar_access_t *vga_fn;
} lm_pci_info_t;

/**
 *  Callback function signature for log function
 *
 * @lm_log_fn_t: typedef for log function.
 */
typedef void (lm_log_fn_t) (void *pvt, const char *const msg);

/**
 * Device information structure, used to create the lm_ctx.
 * To be filled and passed to lm_ctx_run()
 */
typedef struct {
    char            *uuid;
    void		    *pvt;
    /*
     * whether an extended PCI configuration space should be created
     */
    bool            extended;
    int			    nr_dma_regions;
    lm_log_fn_t		*log;
    lm_log_lvl_t	log_lvl;
    lm_fops_t		fops;
    lm_pci_hdr_id_t	id;
    lm_pci_hdr_cc_t	cc;
    lm_pci_info_t	pci_info;
} lm_dev_info_t;

/**
 * Creates libmuser context.
 *
 * Arguments:
 * @dev_info: device information used to create the context.
 */
lm_ctx_t *lm_ctx_create(lm_dev_info_t * dev_info);

/**
 * Destroys libmuser context.
 *
 * Arguments:
 * @lm_ctx: libmuser context to destroy.
 */
void lm_ctx_destroy(lm_ctx_t * lm_ctx);

/**
 * Once the lm_ctx is configured lm_ctx_drive() drives it. This function waits
 * for commands comming from muser.ko and then processes it..
 *
 * Arguments:
 * @lm_ctx: libmuser context to drive.
 */

int lm_ctx_drive(lm_ctx_t * lm_ctx);


/**
 * Creates mapping of BAR's into the callers vmem. It should be called from
 * lm_fops_t->mmap.
 *
 * Arguments:
 * @lm_ctx: libmuser context to create mapping from.
 */
void *lm_mmap(lm_ctx_t * lm_ctx, size_t length, off_t offset);

/**
 * Trigger interrupt.
 *
 * Arguments:
 * @lm_ctx: libmuser context to trigger interrupt.
 * @vector: vector to tirgger interrupt on.
 */
int lm_irq_trigger(lm_ctx_t * lm_ctx, uint32_t vector);

/* Helper functions */

int lm_ctx_run(lm_ctx_t * const ctx);

uint8_t *lm_get_pci_non_std_config_space(lm_ctx_t * const lm_ctx);

int lm_addr_to_sg(lm_ctx_t * const ctx, dma_addr_t dma_addr, uint32_t len,
                  dma_scattergather_t * sg, int max_sg);

int
lm_map_sg(lm_ctx_t * const ctx, int prot, const dma_scattergather_t * sg,
          struct iovec *iov, int cnt);

void
lm_unmap_sg(lm_ctx_t * const ctx, const dma_scattergather_t * sg,
            struct iovec *iov, int cnt);

int
lm_get_region(lm_ctx_t * const ctx, const loff_t pos,
              const size_t count, loff_t * const off);

#ifdef DEBUG
void
dump_buffer(lm_ctx_t const *const lm_ctx, char const *const prefix,
            unsigned char const *const buf, const uint32_t count);
#endif

#endif                          /* LIB_MUSER_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
