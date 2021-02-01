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
 * PCI Express capability
 */

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

struct pxscap {
    unsigned int stuff:32;
} __attribute__((packed));
_Static_assert(sizeof(struct pxscap) == 0x4, "bad PXSCAP size");

struct pxsc {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxsc) == 0x2, "bad PXSC size");

struct pxss {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxss) == 0x2, "bad PXSS size");

struct pxrc {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxrc) == 0x2, "bad PXRC size");

struct pxrcap {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxrcap) == 0x2, "bad PXRCAP size");

struct pxrs {
    unsigned int stuff:32;
} __attribute__((packed));
_Static_assert(sizeof(struct pxrs) == 0x4, "bad PXRS size");

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

struct pxds2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxds2) == 0x2, "bad PXDS2 size");

struct pxlcap2 {
    unsigned int stuff:32;
} __attribute__((packed));
_Static_assert(sizeof(struct pxlcap2) == 0x4, "bad PXLCAP2 size");

struct pxlc2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxlc2) == 0x2, "bad PXLC2 size");

struct pxls2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxls2) == 0x2, "bad PXLS2 size");

struct pxscap2 {
    unsigned int stuff:32;
} __attribute__((packed));
_Static_assert(sizeof(struct pxscap2) == 0x4, "bad PXSCAP2 size");

struct pxsc2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxsc2) == 0x2, "bad PXSC2 size");

struct pxss2 {
    unsigned int stuff:16;
} __attribute__((packed));
_Static_assert(sizeof(struct pxss2) == 0x2, "bad PXSS2 size");

/*
 * PCI_CAP_EXP_ENDPOINT_SIZEOF_V2 from pci_regs.h is a false friend: earlier
 * kernel versions defined the size as if the device was a Root Complex
 * Integrated Endpoint (size 0x2c).
 *
 * Regardless, we define the full structure anyway.
 */
#define VFIO_USER_PCI_CAP_EXP_SIZEOF (0x3c)

/*
 * PCI Express capability, defined in PCI Express 7.8.
 *
 * The relevant fields and size of this capability varies depending upon the
 * type. While we can expect, at least for now, all users to implement a PCI
 * Express Endpoint, we'll define the entire struct, on the presumption that
 * there is no issue with having additional space in the capability.
 */
struct pxcap {
    struct cap_hdr hdr;
    /* PCI Express Capabilities Register */
    struct pxcaps pxcaps;
    /* Device Capabilities */
    struct pxdcap pxdcap;
    /* Device Control */
    union pxdc pxdc;
    /* Device Status */
    struct pxds pxds;
    /* Link Capabilities */
    struct pxlcap pxlcap;
    /* Link Control */
    struct pxlc pxlc;
    /* Link Status */
    struct pxls pxls;
    /* Slot Capabilities */
    struct pxscap pxscap;
    /* Slot Control */
    struct pxsc pxsc;
    /* Slot Status */
    struct pxss pxss;
    /* Root Control */
    struct pxrc pxrc;
    /* Root Capabilities */
    struct pxrcap pxrcap;
    /* Root Status */
    struct pxrs pxrs;
    /* Device Capabilities 2 */
    struct pxdcap2 pxdcap2;
    /* Device Control 2 */
    struct pxdc2 pxdc2;
    /* Device Status 2 */
    struct pxds2 pxds2;
    /* Link Capabilities 2 */
    struct pxlcap2 pxlcap2;
    /* Link Control 2 */
    struct pxlc2 pxlc2;
    /* Link Status 2 */
    struct pxls2 pxls2;
    /* Slot Capabilities 2 */
    struct pxscap2 pxscap2;
    /* Slot Control 2 */
    struct pxsc2 pxsc2;
    /* Slot Status 2 */
    struct pxss2 pxss2;
} __attribute__((packed));
_Static_assert(sizeof(struct pxcap) == VFIO_USER_PCI_CAP_EXP_SIZEOF,
		"bad PCI Express Capability size");
_Static_assert(offsetof(struct pxcap, hdr) == 0, "bad offset");

#ifdef __cplusplus
}
#endif

#endif /* LIB_VFIO_USER_PCI_CAPS_PX_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
