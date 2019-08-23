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

#ifndef LIBMUSER_PCI_H
#define LIBMUSER_PCI_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/pci_regs.h>

struct lm_ctx;
typedef struct lm_ctx lm_ctx_t;

typedef uint64_t dma_addr_t;

typedef struct {
    int region;
    int length;
    uint64_t offset;
} dma_scattergather_t;

typedef struct lm_ctx lm_ctx_t;
typedef struct lm_reg_info lm_reg_info_t;
typedef struct lm_pci_config_space lm_pci_config_space_t;

typedef enum {
    LM_ERR,
    LM_INF,
    LM_DBG
} lm_log_lvl_t;

/*
 * These are already defined in include/uapi/linux/pci_regs.h, however that
 * file doesn't seem to installed.
 */
#define PCI_CFG_SPACE_SIZE      256
#define PCI_CFG_SPACE_EXP_SIZE  4096

enum {
    LM_DEV_BAR0_REG_IDX,
    LM_DEV_BAR1_REG_IDX,
    LM_DEV_BAR2_REG_IDX,
    LM_DEV_BAR3_REG_IDX,
    LM_DEV_BAR4_REG_IDX,
    LM_DEV_BAR5_REG_IDX,
    LM_DEV_ROM_REG_IDX,
    LM_DEV_CFG_REG_IDX,
    LM_DEV_VGA_REG_IDX,
    LM_DEV_NUM_REGS = 9
};

/*
 * TODO lots of the sizes of each member are defined in pci_regs.h, use those
 * instead?
 */

typedef union {
    uint32_t raw;
    struct {
        uint16_t vid;
        uint16_t sid;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_ss_t;
_Static_assert(sizeof(lm_pci_hdr_ss_t) == 0x4, "bad SS size");

typedef union {
    uint8_t raw;
} __attribute__ ((packed)) lm_pci_hdr_bist_t;
_Static_assert(sizeof(lm_pci_hdr_bist_t) == 0x1, "bad BIST size");

typedef union {
    uint32_t raw;
    union {
        struct {
            unsigned int region_type:1;
            unsigned int locatable:2;
            unsigned int prefetchable:1;
            unsigned int base_address:28;
        } __attribute__ ((packed)) mem;
        struct {
            unsigned int region_type:1;
            unsigned int reserved:1;
            unsigned int base_address:30;
        } __attribute__ ((packed)) io;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_bar_t;
_Static_assert(sizeof(lm_bar_t) == 0x4, "bad BAR size");

typedef union {
    uint8_t raw;
} __attribute__ ((packed)) lm_pci_hdr_htype_t;
_Static_assert(sizeof(lm_pci_hdr_htype_t) == 0x1, "bad HTYPE size");

typedef union {
    uint8_t raw[3];
    struct {
        uint8_t pi;
        uint8_t scc;
        uint8_t bcc;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_cc_t;
_Static_assert(sizeof(lm_pci_hdr_cc_t) == 0x3, "bad CC size");

/* device status */
typedef union {
    uint16_t raw;
    struct {
        unsigned int res1:3;
        unsigned int is:1;
        unsigned int cl:1;
        unsigned int c66:1;
        unsigned int res2:1;
        unsigned int fbc:1;
        unsigned int dpd:1;
        unsigned int devt:2;
        unsigned int sta:1;
        unsigned int rta:1;
        unsigned int rma:1;
        unsigned int sse:1;
        unsigned int dpe:1;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_sts_t;
_Static_assert(sizeof(lm_pci_hdr_sts_t) == 0x2, "bad STS size");

typedef union {
    uint16_t raw;
    struct {
        uint8_t iose:1;
        uint8_t mse:1;
        uint8_t bme:1;
        uint8_t sce:1;
        uint8_t mwie:1;
        uint8_t vga:1;
        uint8_t pee:1;
        uint8_t zero:1;
        uint8_t see:1;
        uint8_t fbe:1;
        uint8_t id:1;
        uint8_t res1:5;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_cmd_t;
_Static_assert(sizeof(lm_pci_hdr_cmd_t) == 0x2, "bad CMD size");

typedef union {
    uint32_t raw;
    struct {
        uint16_t vid;
        uint16_t did;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_id_t;
_Static_assert(sizeof(lm_pci_hdr_id_t) == 0x4, "bad ID size");

typedef union {
    uint16_t raw;
    struct {
        uint8_t iline;
        uint8_t ipin;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_intr_t;
_Static_assert(sizeof(lm_pci_hdr_intr_t) == 0x2, "bad INTR size");

typedef union {
    uint8_t raw[PCI_STD_HEADER_SIZEOF];
    struct {
        lm_pci_hdr_id_t id;
        lm_pci_hdr_cmd_t cmd;
        lm_pci_hdr_sts_t sts;
        uint8_t rid;
        lm_pci_hdr_cc_t cc;
        uint8_t cls;
        uint8_t mlt;
        lm_pci_hdr_htype_t htype;
        lm_pci_hdr_bist_t bist;
#define PCI_BARS_NR 6
        lm_bar_t bars[PCI_BARS_NR];
        uint32_t ccptr;
        lm_pci_hdr_ss_t ss;
        uint32_t erom;
        uint8_t cap;
        uint8_t res1[7];
        lm_pci_hdr_intr_t intr;
        uint8_t mgnt;
        uint8_t mlat;
    } __attribute__ ((packed));
} __attribute__ ((packed)) lm_pci_hdr_t;
_Static_assert(sizeof(lm_pci_hdr_t) == 0x40, "bad PCI header size");

typedef struct {
    uint8_t raw[PCI_CFG_SPACE_SIZE - PCI_STD_HEADER_SIZEOF];
} __attribute__ ((packed)) lm_pci_non_std_config_space_t;
_Static_assert(sizeof(lm_pci_non_std_config_space_t) == 0xc0,
               "bad non-standard PCI configuration space size");

struct lm_pci_config_space {
    union {
        uint8_t raw[PCI_CFG_SPACE_SIZE];
        struct {
            lm_pci_hdr_t hdr;
            lm_pci_non_std_config_space_t non_std;
        } __attribute__ ((packed));
    } __attribute__ ((packed));
    uint8_t extended[];
} __attribute__ ((packed));
_Static_assert(sizeof(struct lm_pci_config_space) == 0x100,
               "bad PCI configuration space size");

// Region flags.
#define LM_REG_FLAG_READ    (1 << 0)
#define LM_REG_FLAG_WRITE   (1 << 1)
#define LM_REG_FLAG_MMAP    (1 << 2)    // TODO: how this relates to IO bar?
#define LM_REG_FLAG_RW      (LM_REG_FLAG_READ | LM_REG_FLAG_WRITE)
#define LM_REG_FLAG_MEM     (1 << 3)    // if unset, bar is IO

typedef ssize_t (lm_region_access_t) (void *pvt, char * const buf, size_t count,
                                      loff_t offset, const bool is_write);

struct lm_reg_info {
    uint32_t            flags;
    uint32_t            size;
    uint64_t            offset;
    lm_region_access_t  *fn;
};

enum {
    LM_DEV_INTX_IRQ_IDX,
    LM_DEV_MSI_IRQ_IDX,
    LM_DEV_MSIX_IRQ_IDX,
    LM_DEV_ERR_IRQ_IDX,
    LM_DEV_REQ_IRQ_IDX,
    LM_DEV_NUM_IRQS = 5
};

/*
 * Returns a pointer to the non-standard part of the PCI configuration space.
 */
lm_pci_config_space_t *lm_get_pci_config_space(lm_ctx_t * const lm_ctx);

lm_reg_info_t *lm_get_region_info(lm_ctx_t * const lm_ctx);

/*
 * TODO the rest of these functions don't need to be public, put them in a
 * private header file so libmuser.c can use them.
 * TODO replace the "muser" prefix
 */
int
muser_pci_hdr_access(lm_ctx_t * const lm_ctx, size_t * const count,
                     loff_t * const pos, const bool write,
                     unsigned char *const buf);



#endif                          /* LIBMUSER_PCI_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
