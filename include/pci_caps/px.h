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

/*
 * PCI Express capability */

#ifndef LIB_VFIO_USER_PCI_CAPS_PX_H
#define LIB_VFIO_USER_PCI_CAPS_PX_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pxcaps {
    unsigned int ver:4;
    unsigned int dpt:4;
    unsigned int si:1;
    unsigned int imn:5;
    unsigned int res1:2;
} __attribute__((packed));
_Static_assert(sizeof(struct pxcaps) == 0x2, "bad PXCAPS size");

struct pxdcap {
    unsigned int mps:3;
    unsigned int pfs:2;
    unsigned int etfs:1;
    unsigned int l0sl:3;
    unsigned int l1l:3;
    unsigned int per:1;
    unsigned int res1:2;
    unsigned int csplv:8;
    unsigned int cspls:2;
    unsigned int flrc:1;
    unsigned int res2:3;
} __attribute__((packed));
_Static_assert(sizeof(struct pxdcap) == 0x4, "bad PXDCAP size");

union pxdc {
    uint16_t raw;
    struct {
        unsigned int cere:1;
        unsigned int nfere:1;
        unsigned int fere:1;
        unsigned int urre:1;
        unsigned int ero:1;
        unsigned int mps:3;
        unsigned int ete:1;
        unsigned int pfe:1;
        unsigned int appme:1;
        unsigned int ens:1;
        unsigned int mrrs:3;
        unsigned int iflr:1;
     } __attribute__((packed));
} __attribute__((packed));
_Static_assert(sizeof(union pxdc) == 0x2, "bad PXDC size");

/* TODO not defining for now since all values are 0 for reset */
struct pxds {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxds) == 0x2, "bad PXDS size");

struct pxlcap {
    unsigned int stuff:32;
} __attribute__((packed));
_Static_assert(sizeof(struct pxlcap) == 0x4, "bad PXLCAP size");

struct pxlc {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxlc) == 0x2, "bad PXLC size");

struct pxls {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxls) == 0x2, "bad PXLS size");

struct pxdcap2 {
    unsigned int ctrs:4;
    unsigned int ctds:1;
    unsigned int arifs:1;
    unsigned int aors:1;
    unsigned int aocs32:1;
    unsigned int aocs64:1;
    unsigned int ccs128:1;
    unsigned int nprpr:1;
    unsigned int ltrs:1;
    unsigned int tphcs:2;
    unsigned int obffs:2;
    unsigned int effs:1;
    unsigned int eetps:1;
    unsigned int meetp:2;
    unsigned int res1:8;
} __attribute__((packed));
_Static_assert(sizeof(struct pxdcap2) == 0x4, "bad PXDCAP2 size");

struct pxdc2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxdc2) == 0x2, "bad PXDC2 size");

/*
 * TODO the definition of this struct varies, check PCI Express 2.1
 * specification. Maybe we should only define the idividual registers but not
 * the whole struct.
 */
struct pxcap {
    struct cap_hdr hdr;
    struct pxcaps pxcaps;
    struct pxdcap pxdcap;
    union pxdc pxdc;
    struct pxds pxds;
    struct pxlcap pxlcap;
    struct pxlc pxlc;
    struct pxls pxls;
    uint8_t pad[0x10];
    struct pxdcap2 pxdcap2;
    struct pxdc2 pxdc2;
} __attribute__((packed));
_Static_assert(sizeof(struct pxcap) == 0x2a,
		"bad PCI Express Capability size");
_Static_assert(offsetof(struct pxcap, hdr) == 0, "bad offset");

#ifdef __cplusplus
}
#endif

#endif /* LIB_VFIO_USER_PCI_CAPS_PX_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
