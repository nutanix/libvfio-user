/*
 * Copyright (c) 2020 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
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

static bool
cap_is_valid(uint16_t id)
{
    return id >= PCI_EXT_CAP_ID_ERR && id <= PCI_EXT_CAP_ID_MAX;
}

static const struct cap_handler {
    char *name;
    uint16_t size;
    cap_access *fn;
} cap_handlers[PCI_EXT_CAP_ID_MAX + 1] = {
    [PCI_EXT_CAP_ID_VNDR] = {"Vendor-Specific", 0, NULL},
};

int
extended_caps_create(vfu_ctx_t *vfu_ctx, struct pcie_extended_cap **caps,
                     size_t count) {

    vfu_pci_config_space_t *config_space;
    int i;
    struct pcie_extended_cap_hdr *prev, *cur;
    int ret = 0;
    size_t prev_size;

	assert(vfu_ctx != NULL);
    assert(caps != NULL);
    assert(count > 0);

    config_space = vfu_pci_get_config_space(vfu_ctx);
    for (i = 0, prev = NULL; i < count; i++) {

        size_t size;

        if (!cap_is_valid(caps[i]->hdr.id)) {
            return -EINVAL;
        }

        if (caps[i]->hdr.id == PCI_EXT_CAP_ID_VNDR) {
            size = caps[i]->vsec.hdr.len;
        } else if (cap_handler[caps[i]->hdr.id].size == 0) {
            return -ENOTSUP;
        } else {
            size = cap_handler[caps[i]->hdr.id].size;
        }

        if (prev == NULL) {
            cur = config_space->extended;
        } else {
            cur = ((uint16_t*)prev) + prev_size;
        }

        memcpy(cur, cap[i], size);
        cur->next_cap_off = 0;

        if (prev != NULL) {
            prev->next_cap_off = cur - config_space->extended;
        }

        vfu_log(vfu_ctx, LOG_DEBUG,
                "initialized PCI extended capability %s %#x-%#x\n",
                cap_handlers[id].name, cur - prev, cur - prev + size - 1);

        prev = cur;
        prev_size = size;            
    }
    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
