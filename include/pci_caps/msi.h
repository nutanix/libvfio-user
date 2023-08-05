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

#ifndef LIB_VFIO_USER_PCI_CAPS_MSI_H
#define LIB_VFIO_USER_PCI_CAPS_MSI_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Message Control for MSI */
struct mc {
    unsigned int msie:1;    /* RW */
    unsigned int mmc:3;     /* RO */
    unsigned int mme:3;     /* RW */
    unsigned int c64:1;     /* RO */
    unsigned int pvm:1;     /* RO */
    unsigned int res1:7;    /* not implemented, extended message data control */
} __attribute__ ((packed));
_Static_assert(sizeof(struct mc) == 0x2, "bad MC size");

/* Message Address for MSI */
struct ma {
    unsigned int res1:2;    /* read must return 0, write has no effect */
    unsigned int addr:30;   /* RW */
} __attribute__ ((packed));
_Static_assert(sizeof(struct ma) == 0x4, "bad MA size");

struct msicap {
    struct cap_hdr hdr;
    struct mc mc;
    struct ma ma;
    uint32_t mua;           /* RW */
    uint16_t md;            /* RW */
    uint16_t padding;       /* not implemented, extended message data */
    uint32_t mmask;         /* RW */
    uint32_t mpend;         /* RO */
}  __attribute__ ((packed));
_Static_assert(sizeof(struct msicap) == 0x18, "bad MSICAP size");
_Static_assert(offsetof(struct msicap, hdr) == 0, "bad offset");

#ifdef __cplusplus
}
#endif

#endif /* VFU_CAP_MSI_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
