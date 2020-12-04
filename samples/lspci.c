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

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <assert.h>

#include "libvfio-user.h"

int main(void)
{
    int i, j;
    char *buf;
    const int bytes_per_line = 0x10;
	vfu_pci_hdr_id_t id = { 0 };
	vfu_pci_hdr_ss_t ss = { 0 };
	vfu_pci_hdr_cc_t cc = { 0 };
	vfu_cap_t pm = {.pm = {.hdr.id = PCI_CAP_ID_PM, .pmcs.nsfrst = 0x1}};
    vfu_cap_t *caps[1] = {&pm};
    vfu_ctx_t *vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, "",
                                        LIBVFIO_USER_FLAG_ATTACH_NB, NULL,
                                        VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "failed to create libvfio-user context");
    }
    if (vfu_pci_setup_config_hdr(vfu_ctx, id, ss, cc, VFU_PCI_TYPE_CONVENTIONAL, 0) < 0) {
        err(EXIT_FAILURE, "failed to setup PCI configuration space header");
    }
    if (vfu_pci_setup_caps(vfu_ctx, caps, 1) < 0) {
        err(EXIT_FAILURE, "failed to setup PCI capabilities");
    }
    if (vfu_realize_ctx(vfu_ctx) < 0) {
        err(EXIT_FAILURE, "failed to realize device");
    }
    buf = (char*)vfu_pci_get_config_space(vfu_ctx);;
    printf("00:00.0 bogus PCI device\n");
    for (i = 0; i < PCI_CFG_SPACE_SIZE / bytes_per_line; i++) {
        printf("%02x:", i * bytes_per_line);
        for (j = 0; j < bytes_per_line; j++) {
            printf(" %02x", buf[i * bytes_per_line + j] & 0xff);
        }
        printf("\n");
    } 

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
