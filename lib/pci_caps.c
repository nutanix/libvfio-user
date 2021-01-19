/*
 * Copyright (c) 2021 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          Swapnil Ingle <swapnil.ingle@nutanix.com>
 *          Felipe Franciosi <felipe@nutanix.com>
 *          John Levon <john.levon@nutanix.com>
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
 * Capability handling. We handle reads and writes to standard capabilities
 * ourselves, and optionally for vendor capabilities too. For each access (via
 * pci_config_space_access() -> pci_cap_access()), if we find that we're
 * reading from a particular capability offset:
 *
 * - if VFU_CAP_FLAG_CALLBACK is set, we call the config space region callback
 *   given by the user
 * - else we memcpy() the capability data back out to the client
 *
 * For writes:
 *
 * - if VFU_CAP_FLAG_READONLY is set, we fail the write
 * - if VFU_CAP_FLAG_CALLBACK is set, we call the config space region callback
 *   given by the user
 * - else we call the cap-specific callback to handle the write.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "common.h"
#include "libvfio-user.h"
#include "pci_caps.h"
#include "pci.h"
#include "private.h"

static void *
cap_data(vfu_ctx_t *vfu_ctx, struct pci_cap *cap)
{
    return (void *)pci_config_space_ptr(vfu_ctx, cap->off);
}

static size_t
cap_size(uint8_t id, uint8_t *data)
{
    switch (id) {
    case PCI_CAP_ID_PM:
        return PCI_PM_SIZEOF;
    case PCI_CAP_ID_EXP:
        return PCI_CAP_EXP_ENDPOINT_SIZEOF_V2;
    case PCI_CAP_ID_MSIX:
        return PCI_CAP_MSIX_SIZEOF;
    case PCI_CAP_ID_VNDR:
        return ((struct vsc *)data)->size;
    default:
        return 0;
    }
}

static ssize_t
handle_pmcs_write(vfu_ctx_t *vfu_ctx, struct pmcap *pm,
                  const struct pmcs *const pmcs)
{
	if (pm->pmcs.ps != pmcs->ps) {
		vfu_log(vfu_ctx, LOG_DEBUG, "power state set to %#x\n", pmcs->ps);
	}
	if (pm->pmcs.pmee != pmcs->pmee) {
		vfu_log(vfu_ctx, LOG_DEBUG, "PME enable set to %#x\n", pmcs->pmee);
	}
	if (pm->pmcs.dse != pmcs->dse) {
		vfu_log(vfu_ctx, LOG_DEBUG, "data select set to %#x\n", pmcs->dse);
	}
	if (pm->pmcs.pmes != pmcs->pmes) {
		vfu_log(vfu_ctx, LOG_DEBUG, "PME status set to %#x\n", pmcs->pmes);
	}
	pm->pmcs = *pmcs;
	return 0;
}

static ssize_t
cap_write_pm(vfu_ctx_t *vfu_ctx, struct pci_cap *cap, char * buf,
             size_t count, loff_t offset)
{
    struct pmcap *pm = cap_data(vfu_ctx, cap);

	switch (offset - cap->off) {
	case offsetof(struct pmcap, pc):
		if (count != sizeof (struct pc)) {
			return -EINVAL;
		}
        assert(false); /* FIXME implement */
        break;
	case offsetof(struct pmcap, pmcs):
		if (count != sizeof (struct pmcs)) {
			return -EINVAL;
		}
		handle_pmcs_write(vfu_ctx, pm, (struct pmcs *)buf);
        return sizeof (struct pmcs);
	}
	return -EINVAL;
}

static ssize_t
handle_mxc_write(vfu_ctx_t *vfu_ctx, struct msixcap *msix,
                 const struct mxc *const mxc)
{
	assert(msix != NULL);
	assert(mxc != NULL);

	if (mxc->mxe != msix->mxc.mxe) {
		vfu_log(vfu_ctx, LOG_DEBUG, "%s MSI-X\n",
                mxc->mxe ? "enable" : "disable");
		msix->mxc.mxe = mxc->mxe;
	}

	if (mxc->fm != msix->mxc.fm) {
		if (mxc->fm) {
			vfu_log(vfu_ctx, LOG_DEBUG, "all MSI-X vectors masked\n");
		} else {
			vfu_log(vfu_ctx, LOG_DEBUG,
                   "vector's mask bit determines whether vector is masked\n");
		}
		msix->mxc.fm = mxc->fm;
	}

	return sizeof(struct mxc);
}

static ssize_t
cap_write_msix(vfu_ctx_t *vfu_ctx, struct pci_cap *cap, char *buf,
               size_t count, loff_t offset)
{
    struct msixcap *msix = cap_data(vfu_ctx, cap);

	if (count == sizeof(struct mxc)) {
		switch (offset - cap->off) {
		case offsetof(struct msixcap, mxc):
			return handle_mxc_write(vfu_ctx, msix, (struct mxc *)buf);
		default:
			vfu_log(vfu_ctx, LOG_ERR,
                    "invalid MSI-X write offset %ld\n", offset);
			return -EINVAL;
		}
	}
	vfu_log(vfu_ctx, LOG_ERR, "invalid MSI-X write size %lu\n", count);
	return -EINVAL;
}

static int
handle_px_pxdc_write(vfu_ctx_t *vfu_ctx, struct pxcap *px,
                     const union pxdc *const p)
{
	assert(px != NULL);
	assert(p != NULL);

	if (p->cere != px->pxdc.cere) {
		px->pxdc.cere = p->cere;
		vfu_log(vfu_ctx, LOG_DEBUG, "CERE %s\n", p->cere ? "enable" : "disable");
	}

	if (p->nfere != px->pxdc.nfere) {
		px->pxdc.nfere = p->nfere;
		vfu_log(vfu_ctx, LOG_DEBUG, "NFERE %s\n",
                p->nfere ? "enable" : "disable");
	}

	if (p->fere != px->pxdc.fere) {
		px->pxdc.fere = p->fere;
		vfu_log(vfu_ctx, LOG_DEBUG, "FERE %s\n", p->fere ? "enable" : "disable");
	}

	if (p->urre != px->pxdc.urre) {
		px->pxdc.urre = p->urre;
		vfu_log(vfu_ctx, LOG_DEBUG, "URRE %s\n", p->urre ? "enable" : "disable");
	}

	if (p->ero != px->pxdc.ero) {
		px->pxdc.ero = p->ero;
		vfu_log(vfu_ctx, LOG_DEBUG, "ERO %s\n", p->ero ? "enable" : "disable");
	}

	if (p->mps != px->pxdc.mps) {
		px->pxdc.mps = p->mps;
		vfu_log(vfu_ctx, LOG_DEBUG, "MPS set to %d\n", p->mps);
	}

	if (p->ete != px->pxdc.ete) {
		px->pxdc.ete = p->ete;
		vfu_log(vfu_ctx, LOG_DEBUG, "ETE %s\n", p->ete ? "enable" : "disable");
	}

	if (p->pfe != px->pxdc.pfe) {
		px->pxdc.pfe = p->pfe;
		vfu_log(vfu_ctx, LOG_DEBUG, "PFE %s\n", p->pfe ? "enable" : "disable");
	}

	if (p->appme != px->pxdc.appme) {
		px->pxdc.appme = p->appme;
		vfu_log(vfu_ctx, LOG_DEBUG, "APPME %s\n",
                p->appme ? "enable" : "disable");
	}

	if (p->ens != px->pxdc.ens) {
		px->pxdc.ens = p->ens;
		vfu_log(vfu_ctx, LOG_DEBUG, "ENS %s\n", p->ens ? "enable" : "disable");
	}

	if (p->mrrs != px->pxdc.mrrs) {
		px->pxdc.mrrs = p->mrrs;
		vfu_log(vfu_ctx, LOG_DEBUG, "MRRS set to %d\n", p->mrrs);
	}

	if (p->iflr) {
		vfu_log(vfu_ctx, LOG_DEBUG,
			"initiate function level reset\n");
	}

	return 0;
}

static int
handle_px_write_2_bytes(vfu_ctx_t *vfu_ctx, struct pxcap *px, char *buf,
                        loff_t off)
{
	switch (off) {
	case offsetof(struct pxcap, pxdc):
		return handle_px_pxdc_write(vfu_ctx, px, (union pxdc *)buf);
	}
	return -EINVAL;
}

static ssize_t
cap_write_px(vfu_ctx_t *vfu_ctx, struct pci_cap *cap, char *buf,
             size_t count, loff_t offset)
{
    struct pxcap *px = cap_data(vfu_ctx, cap);

	int err = -EINVAL;
	switch (count) {
	case 2:
		err = handle_px_write_2_bytes(vfu_ctx, px, buf, offset - cap->off);
		break;
	}
	if (err != 0) {
		return err;
	}
	return count;
}

static ssize_t
cap_write_vendor(vfu_ctx_t *vfu_ctx, struct pci_cap *cap UNUSED, char *buf,
                 size_t count, loff_t offset)
{
    memcpy(pci_config_space_ptr(vfu_ctx, offset), buf, count);
    return count;
}

static bool
ranges_intersect(size_t off1, size_t size1, size_t off2, size_t size2)
{
    return (off1 < (off2 + size2) && (off1 + size1) >= off2);
}

struct pci_cap *
cap_find_by_offset(vfu_ctx_t *vfu_ctx, loff_t offset, size_t count)
{
    size_t i;

    for (i = 0; i < vfu_ctx->pci.nr_caps; i++) {
        struct pci_cap *cap = &vfu_ctx->pci.caps[i];
        if (ranges_intersect(offset, count, cap->off, cap->size)) {
            return cap;
        }
    }

    return NULL;
}

ssize_t
pci_cap_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
               bool is_write)
{
    struct pci_cap *cap = cap_find_by_offset(vfu_ctx, offset, count);

    assert(cap != NULL);
    assert((size_t)offset >= cap->off);
    assert(count <= cap->size);

    if (is_write && (cap->flags & VFU_CAP_FLAG_READONLY)) {
        vfu_log(vfu_ctx, LOG_ERR, "write of %zu bytes to read-only capability "
                "%u (%s)\n", count, cap->id, cap->name);
        return -EINVAL;
    }

    if (cap->flags & VFU_CAP_FLAG_CALLBACK) {
        return pci_nonstd_access(vfu_ctx, buf, count, offset, is_write);
    }

    if (!is_write) {
        memcpy(buf, pci_config_space_ptr(vfu_ctx, offset), count);
        return count;
    }

    if (offset - cap->off < cap->hdr_size) {
        vfu_log(vfu_ctx, LOG_ERR,
                "disallowed write to header for cap %d (%s)\n",
                cap->id, cap->name);
        return -EINVAL;
    }

    return cap->cb(vfu_ctx, cap, buf, count, offset);
}

/*
 * Place the new capability after the previous (or after the standard header if
 * this is the first capability).
 *
 * If cap->off is already provided, place it directly, but first check it
 * doesn't overlap an existing capability, or the PCI header. We still also need
 * to link it into the list. There's no guarantee that the list is ordered by
 * offset after doing so.
 */
static int
cap_place(vfu_ctx_t *vfu_ctx, struct pci_cap *cap, void *data)
{
    vfu_pci_config_space_t *config_space;
    uint8_t *prevp;
    size_t offset;

    config_space = vfu_pci_get_config_space(vfu_ctx);

    prevp = &config_space->hdr.cap;

    if (cap->off != 0) {
        if (cap->off < PCI_STD_HEADER_SIZEOF) {
            vfu_log(vfu_ctx, LOG_ERR, "invalid offset %#lx for capability "
                    "%u (%s)\n", cap->off, cap->id, cap->name);
            return EINVAL;
        }

        if (cap_find_by_offset(vfu_ctx, cap->off, cap->size) != NULL) {
            vfu_log(vfu_ctx, LOG_ERR, "overlap found for capability "
                    "%u (%s)\n", cap->id, cap->name);
            return EINVAL;
        }

        while (*prevp != 0) {
            prevp = pci_config_space_ptr(vfu_ctx, *prevp + PCI_CAP_LIST_NEXT);
        }
    } else if (*prevp == 0) {
        cap->off = PCI_STD_HEADER_SIZEOF;
    } else {
        for (offset = *prevp; offset != 0; offset = *prevp) {
            uint8_t id;
            size_t size;

            id = *pci_config_space_ptr(vfu_ctx, offset + PCI_CAP_LIST_ID);
            prevp = pci_config_space_ptr(vfu_ctx, offset + PCI_CAP_LIST_NEXT);

            if (*prevp == 0) {
                size = cap_size(id, pci_config_space_ptr(vfu_ctx, offset));
                cap->off = ROUND_UP(offset + size, 4);
                break;
            }
        }
    }

    if (cap->off + cap->size >
        vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size) {
        vfu_log(vfu_ctx, LOG_ERR, "no config space left for capability "
                "%u (%s) of size %zu bytes at offset %#lx\n", cap->id,
                cap->name, cap->size, cap->off);
        return ENOSPC;
    }

    memcpy(cap_data(vfu_ctx, cap), data, cap->size);
    /* Make sure the previous cap's PCI_CAP_LIST_NEXT points to us. */
    *prevp = cap->off;
    /* Make sure our PCI_CAP_LIST_NEXT is zeroed. */
    *pci_config_space_ptr(vfu_ctx, cap->off + PCI_CAP_LIST_NEXT) = 0;
    return 0;
}

ssize_t
vfu_pci_add_capability(vfu_ctx_t *vfu_ctx, size_t pos, int flags, void *data)
{
    size_t space_size = vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size;
    struct pci_cap cap;
    int ret;

    assert(vfu_ctx != NULL);

    if (flags & ~(VFU_CAP_FLAG_EXTENDED | VFU_CAP_FLAG_CALLBACK |
        VFU_CAP_FLAG_READONLY)) {
        return ERROR(EINVAL);
    }

    if ((flags & VFU_CAP_FLAG_CALLBACK) && (flags & VFU_CAP_FLAG_READONLY)) {
        return ERROR(EINVAL);
    }

    if ((flags & VFU_CAP_FLAG_CALLBACK) &&
        vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX].cb == NULL) {
        return ERROR(EINVAL);
    }

    if ((flags & VFU_CAP_FLAG_EXTENDED)) {
        return ERROR(ENOTSUP);
    }

    if (vfu_ctx->pci.nr_caps == VFU_MAX_CAPS) {
        return ERROR(ENOSPC);
    }

    cap.id = ((struct cap_hdr *)data)->id;
    cap.hdr_size = sizeof (struct cap_hdr);
    cap.size = cap_size(cap.id, data);
    cap.flags = flags;
    cap.off = pos;

    if (cap.off + cap.size >= space_size) {
        return ERROR(EINVAL);
    }

    switch (cap.id) {
    case PCI_CAP_ID_PM:
        cap.name = "PM";
        cap.cb = cap_write_pm;
        break;
    case PCI_CAP_ID_EXP:
        cap.name = "PCI Express";
        cap.cb = cap_write_px;
        break;
    case PCI_CAP_ID_MSIX:
        cap.name = "MSI-X";
        cap.cb = cap_write_msix;
        break;
    case PCI_CAP_ID_VNDR:
        cap.name = "Vendor Specific";
        cap.cb = cap_write_vendor;
        cap.hdr_size = sizeof (struct vsc);
        break;
    default:
		vfu_log(vfu_ctx, LOG_ERR, "unsupported capability %#x\n", cap.id);
        return ERROR(ENOTSUP);
    }

    ret = cap_place(vfu_ctx, &cap, data);

    if (ret != 0) {
        return ERROR(ret);
    }

    memcpy(&vfu_ctx->pci.caps[vfu_ctx->pci.nr_caps], &cap, sizeof (cap));
    vfu_ctx->pci.nr_caps++;
    return cap.off;
}

size_t
vfu_pci_find_next_capability(vfu_ctx_t *vfu_ctx, bool extended,
                             size_t offset, int cap_id)
{
    size_t space_size = vfu_ctx->reg_info[VFU_PCI_DEV_CFG_REGION_IDX].size;
    vfu_pci_config_space_t *config_space;

    assert(vfu_ctx != NULL);

    if (extended) {
        errno = ENOTSUP;
        return 0;
    }

    if (offset + PCI_CAP_LIST_NEXT >= space_size) {
        errno = EINVAL;
        return 0;
    }

    config_space = vfu_pci_get_config_space(vfu_ctx);

    if (offset == 0) {
        offset = config_space->hdr.cap;
    } else {
        offset = *pci_config_space_ptr(vfu_ctx, offset + PCI_CAP_LIST_NEXT);
    }

    if (offset == 0) {
        errno = ENOENT;
        return 0;
    }

    for (;;) {
        uint8_t id, next;

        /* Sanity check. */
        if (offset + PCI_CAP_LIST_NEXT >= space_size) {
            errno = EINVAL;
            return 0;
        }

        id = *pci_config_space_ptr(vfu_ctx, offset + PCI_CAP_LIST_ID);
        next = *pci_config_space_ptr(vfu_ctx, offset + PCI_CAP_LIST_NEXT);

        if (id == cap_id) {
            return offset;
        }

        offset = next;

        if (offset == 0) {
            errno = ENOENT;
            return 0;
        }
    }
}

size_t
vfu_pci_find_capability(vfu_ctx_t *vfu_ctx, bool extended, int cap_id)
{
    return vfu_pci_find_next_capability(vfu_ctx, extended, 0, cap_id);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
