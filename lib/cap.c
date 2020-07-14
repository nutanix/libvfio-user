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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "muser.h"
#include "cap.h"

struct cap {
    uint8_t         start;
    uint8_t         end;
    /*
     * TODO lm_cap_t is a union so we're waisting some memory. If we replace the
     * list with a buffer then this issue goes away.
     */
    lm_cap_t        cap;
};

struct caps {
    struct cap  caps[LM_MAX_CAPS];
    struct cap  *caps_by_id[LM_MAX_CAPS];
    int         nr_caps;
};

/*
 * Tells whether a capability is being accessed.
 */
static bool
cap_is_accessed(struct cap *caps, int nr_caps, loff_t offset)
{
    /*
     * Ignore if it's at the standard PCI header. The first capability starts
     * right after that.
     */
    if (offset < PCI_STD_HEADER_SIZEOF) {
        return false;
    }

    /* ignore if there are no capabilities */
    if (!nr_caps) {
        return false;
    }

    assert(caps);

    /*
     * Ignore if it's before the first capability. This check is probably
     * redundant since we assume that the first capability starts right after
     * the standard PCI header.
     * TODO should we check that it doesn't cross into the first capability?
     */
    if (offset < caps[0].start) {
        return false;
    }

    /* ignore if it's past the last capability */
    if (offset > caps[nr_caps - 1].end) {
        return false;
    }
    return true;
}

/*
 * Returns the PCI capability that is contained within the specified region
 * (offset + count).
 */
static struct cap *
cap_find(struct cap *caps, int nr_caps, loff_t offset, size_t count)
{
    struct cap *cap;

    cap = caps;
    while (cap < caps + nr_caps) {
        /*
         * TODO this assumes that at most one capability is read. It might be
         * legitimate to read an arbitrary number of bytes, which we could
         * support. For now lets explicitly fail such cases.
         */
        if (offset >= cap->start && offset + count - 1 <= cap->end) {
            return cap;
        }
        cap++;
    }
    /* this means that the access spans more than a capability */
    return NULL;
}

static bool
cap_is_valid(uint8_t id)
{
    /* TODO 0 is a valid capability ID (Null Capability), check
     * https://pcisig.com/sites/default/files/files/PCI_Code-ID_r_1_11__v24_Jan_2019.pdf:
     *
     */
    return id >= PCI_CAP_ID_PM && id <= PCI_CAP_ID_MAX;
}

union pci_cap*
cap_find_by_id(struct caps *caps, uint8_t id)
{
    if (!cap_is_valid(id)) {
        errno = EINVAL;
        return NULL;
    }

    if (caps->caps_by_id[id] == NULL) {
        errno = ENOENT;
        return NULL;
    }

    return &caps->caps_by_id[id]->cap.cap;
}

/*
 * Tells whether the header of a PCI capability is accessed.
 */
static bool
cap_header_is_accessed(struct cap *cap, loff_t offset)
{
    assert(cap);
    return offset - cap->start <= 1;
}

/*
 * Reads the header of a PCI capability.
 */
static int
cap_header_access(struct caps *caps, struct cap *cap, char *buf,
                  loff_t offset, size_t count, bool is_write)
{
    int n;

    /*
     * We don't allow ID and next to be written. TODO not sure what the PCI
     * spec says about this, need to check.
     */
    if (is_write) {
        return -EINVAL;
    }

    assert(caps);
    assert(cap);
    n = 0;
    /*
     * We handle reads to ID and next, the rest is handled by the callback.
     */
    if (offset == cap->start && count > 0) { /* ID */
        buf[n++] = cap->cap.id;
        offset++;
        count--;
    }
    if (offset == cap->start + 1 && count > 0) { /* next */

        if ((cap - caps->caps) / sizeof *cap == (size_t)(caps->nr_caps - 1)) {
            buf[n++] = 0;
        } else {
            buf[n++] = (cap + 1)->start;
        }

        offset++;
        count--;
    }
    return n;
}

typedef ssize_t (cap_access) (lm_ctx_t *lm_ctx, union pci_cap *cap, char *buf,
                              size_t count, loff_t offset, bool is_write);

static ssize_t
handle_pmcs_write(lm_ctx_t *lm_ctx, struct pmcap *pm,
                  const struct pmcs *const pmcs)
{

	if (pm->pmcs.ps != pmcs->ps) {
		lm_log(lm_ctx, LM_DBG, "power state set to %#x\n", pmcs->ps);
	}
	if (pm->pmcs.pmee != pmcs->pmee) {
		lm_log(lm_ctx, LM_DBG, "PME enable set to %#x\n", pmcs->pmee);
	}
	if (pm->pmcs.dse != pmcs->dse) {
		lm_log(lm_ctx, LM_DBG, "data select set to %#x\n", pmcs->dse);
	}
	if (pm->pmcs.pmes != pmcs->pmes) {
		lm_log(lm_ctx, LM_DBG, "PME status set to %#x\n", pmcs->pmes);
	}
	pm->pmcs = *pmcs;
	return 0;
}

static ssize_t
handle_pm_write(lm_ctx_t *lm_ctx, struct pmcap *pm, char *const buf,
                const size_t count, const loff_t offset)
{
	switch (offset) {
	case offsetof(struct pmcap, pc):
		if (count != sizeof(struct pc)) {
			return -EINVAL;
		}
        assert(false); /* FIXME implement */
	case offsetof(struct pmcap, pmcs):
		if (count != sizeof(struct pmcs)) {
			return -EINVAL;
		}
		return handle_pmcs_write(lm_ctx, pm, (struct pmcs *)buf);
	}
	return -EINVAL;
}

static ssize_t
handle_pm(lm_ctx_t *lm_ctx, union pci_cap *cap, char *const buf,
          const size_t count, const loff_t offset, const bool is_write)
{
	if (is_write) {
		return handle_pm_write(lm_ctx, &cap->pm, buf, count, offset);
	}

	memcpy(buf, ((char *)&cap->pm) + offset, count);

	return count;
}

static ssize_t
handle_mxc_write(lm_ctx_t *lm_ctx, struct msixcap *msix,
                 const struct mxc *const mxc)
{
	assert(msix != NULL);
	assert(mxc != NULL);

	if (mxc->mxe != msix->mxc.mxe) {
		lm_log(lm_ctx, LM_DBG, "%s MSI-X\n", mxc->mxe ? "enable" : "disable");
		msix->mxc.mxe = mxc->mxe;
	}

	if (mxc->fm != msix->mxc.fm) {
		if (mxc->fm) {
			lm_log(lm_ctx, LM_DBG, "all MSI-X vectors masked\n");
		} else {
			lm_log(lm_ctx, LM_DBG,
                   "vector's mask bit determines whether vector is masked\n");
		}
		msix->mxc.fm = mxc->fm;
	}

	return sizeof(struct mxc);
}

static ssize_t
handle_msix_write(lm_ctx_t *lm_ctx, struct msixcap *msix, char *const buf,
                  const size_t count, const loff_t offset)
{
	if (count == sizeof(struct mxc)) {
		switch (offset) {
		case offsetof(struct msixcap, mxc):
			return handle_mxc_write(lm_ctx, msix, (struct mxc *)buf);
		default:
			lm_log(lm_ctx, LM_ERR, "invalid MSI-X write offset %ld\n", offset);
			return -EINVAL;
		}
	}
	lm_log(lm_ctx, LM_ERR, "invalid MSI-X write size %lu\n", count);
	return -EINVAL;
}

static ssize_t
handle_msix(lm_ctx_t *lm_ctx, union pci_cap *cap, char *const buf, size_t count,
            loff_t offset, const bool is_write)
{
	if (is_write) {
		return handle_msix_write(lm_ctx, &cap->msix, buf, count, offset);
	}

	memcpy(buf, ((char *)&cap->msix) + offset, count);

	return count;
}

static int
handle_px_pxdc_write(lm_ctx_t *lm_ctx, struct pxcap *px, const union pxdc *const p)
{
	assert(px != NULL);
	assert(p != NULL);

	if (p->cere != px->pxdc.cere) {
		px->pxdc.cere = p->cere;
		lm_log(lm_ctx, LM_DBG, "CERE %s\n", p->cere ? "enable" : "disable");
	}

	if (p->nfere != px->pxdc.nfere) {
		px->pxdc.nfere = p->nfere;
		lm_log(lm_ctx, LM_DBG, "NFERE %s\n", p->nfere ? "enable" : "disable");
	}

	if (p->fere != px->pxdc.fere) {
		px->pxdc.fere = p->fere;
		lm_log(lm_ctx, LM_DBG, "FERE %s\n", p->fere ? "enable" : "disable");
	}

	if (p->urre != px->pxdc.urre) {
		px->pxdc.urre = p->urre;
		lm_log(lm_ctx, LM_DBG, "URRE %s\n", p->urre ? "enable" : "disable");
	}

	if (p->ero != px->pxdc.ero) {
		px->pxdc.ero = p->ero;
		lm_log(lm_ctx, LM_DBG, "ERO %s\n", p->ero ? "enable" : "disable");
	}

	if (p->mps != px->pxdc.mps) {
		px->pxdc.mps = p->mps;
		lm_log(lm_ctx, LM_DBG, "MPS set to %d\n", p->mps);
	}

	if (p->ete != px->pxdc.ete) {
		px->pxdc.ete = p->ete;
		lm_log(lm_ctx, LM_DBG, "ETE %s\n", p->ete ? "enable" : "disable");
	}

	if (p->pfe != px->pxdc.pfe) {
		px->pxdc.pfe = p->pfe;
		lm_log(lm_ctx, LM_DBG, "PFE %s\n", p->pfe ? "enable" : "disable");
	}

	if (p->appme != px->pxdc.appme) {
		px->pxdc.appme = p->appme;
		lm_log(lm_ctx, LM_DBG, "APPME %s\n", p->appme ? "enable" : "disable");
	}

	if (p->ens != px->pxdc.ens) {
		px->pxdc.ens = p->ens;
		lm_log(lm_ctx, LM_DBG, "ENS %s\n", p->ens ? "enable" : "disable");
	}

	if (p->mrrs != px->pxdc.mrrs) {
		px->pxdc.mrrs = p->mrrs;
		lm_log(lm_ctx, LM_DBG, "MRRS set to %d\n", p->mrrs);
	}

	if (p->iflr) {
		lm_log(lm_ctx, LM_DBG,
			"initiate function level reset\n");
	}

	return 0;
}

static int
handle_px_write_2_bytes(lm_ctx_t *lm_ctx, struct pxcap *px, char *const buf,
                        loff_t off)
{
	switch (off) {
	case offsetof(struct pxcap, pxdc):
		return handle_px_pxdc_write(lm_ctx, px, (union pxdc *)buf);
	}
	return -EINVAL;
}

static ssize_t
handle_px_write(lm_ctx_t *lm_ctx, struct pxcap *px, char *const buf,
                size_t count, loff_t offset)
{
	int err = -EINVAL;
	switch (count) {
	case 2:
		err = handle_px_write_2_bytes(lm_ctx, px, buf, offset);
		break;
	}
	if (err != 0) {
		return err;
	}
	return count;
}

static ssize_t
handle_exp(lm_ctx_t *lm_ctx, union pci_cap *cap, char *const buf, size_t count,
          loff_t offset, const bool is_write)
{
	if (is_write) {
		return handle_px_write(lm_ctx, &cap->px, buf, count, offset);
	}

	memcpy(buf, ((char *)&cap->px) + offset, count);

	return count;
}

static const struct cap_handler {
    char *name;
    size_t size;
    cap_access *fn;
} cap_handlers[PCI_CAP_ID_MAX + 1] = {
    [PCI_CAP_ID_PM] = {"PM", PCI_PM_SIZEOF, handle_pm},
    [PCI_CAP_ID_EXP] = {"PCI Express", PCI_CAP_EXP_ENDPOINT_SIZEOF_V2, handle_exp},
    [PCI_CAP_ID_MSIX] = {"MSI-X", PCI_CAP_MSIX_SIZEOF, handle_msix},
};

ssize_t
cap_maybe_access(lm_ctx_t *lm_ctx, struct caps *caps, char *buf, size_t count,
                 loff_t offset, bool is_write)
{
    struct cap *cap;

    if (!caps) {
        return 0;
    }

    if (!count) {
        return 0;
    }

    if (!cap_is_accessed(caps->caps, caps->nr_caps, offset)) {
        return 0;
    }

    /* we're now guaranteed that the access is within some capability */
    cap = cap_find(caps->caps, caps->nr_caps, offset, count);

    if (!cap) {
        return 0;
    }

    if (cap_header_is_accessed(cap, offset)) {
        return cap_header_access(caps, cap, buf, offset, count, is_write);
    }
    if (count > 0) {
        return cap_handlers[cap->cap.id].fn(lm_ctx, &cap->cap.cap, buf, count,
                                            offset - cap->start, is_write);
    }
    return 0;
}

struct caps *
caps_create(lm_ctx_t *lm_ctx, lm_cap_t **lm_caps, int nr_caps)
{
    uint8_t prev_end;
    int i, err = 0;
    struct caps *caps = NULL;

    if (nr_caps <= 0 || nr_caps >= LM_MAX_CAPS) {
        err = EINVAL;
        goto out;
    }

    assert(lm_caps != NULL);

    caps = calloc(1, sizeof *caps);
    if (!caps) {
        err = errno;
        goto out;
    }

    prev_end = PCI_STD_HEADER_SIZEOF - 1;
    for (i = 0; i < nr_caps; i++) {
        uint8_t cap_id;
        size_t cap_size;

        cap_id = lm_caps[i]->id;
        if (!cap_is_valid(cap_id)) {
            err = EINVAL;
            goto out;
        }

        cap_size = cap_handlers[cap_id].size;
        if (cap_size == 0) {
            err = EINVAL;
            goto out;
        }

        /*
         * FIXME we assume that a capability with a given ID can appear only
         * once, check the spec.
         */
        if (caps->caps_by_id[cap_id] != NULL) {
            err = EINVAL;
            goto out;
        }
        caps->caps_by_id[cap_id] = &caps->caps[i];

        caps->caps[i].cap = *lm_caps[i];
        caps->caps[i].start = prev_end + 1;
        caps->caps[i].end = prev_end = caps->caps[i].start + cap_size - 1;

        lm_log(lm_ctx, LM_DBG, "initialized capability %s %#x-%#x\n",
               cap_handlers[cap_id].name, caps->caps[i].start,
               caps->caps[i].end);
    }
    caps->nr_caps = nr_caps;

out:
    if (err) {
        free(caps);
        caps = NULL;
    }
    return caps;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
