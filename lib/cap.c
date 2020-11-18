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
    uint8_t start;
    uint8_t end;
};

struct caps {
    struct cap      caps[LM_MAX_CAPS]; /* FIXME only needs to be as big as nr_caps */
    unsigned int    nr_caps;
};

/*
 * Tells whether a capability is being accessed.
 */
static bool
cap_is_accessed(struct cap *caps, int nr_caps, size_t count, loff_t offset)
{
    if (nr_caps == 0) {
        return false;
    }

    assert(caps != NULL);

    if (offset < caps[0].start) {
        /* write starts before first capability */

        if (offset + count <= caps[0].start) {
            /* write ends before first capability */
            return false;
        }

        /*
         * FIXME write starts before capabilities but extends into them. I don't
         * think that the while loop in lm_access will allow this in the first
         * place.
         */
        assert(false);
    } else if (offset > caps[nr_caps - 1].end) {
        /* write starts after last capability */
        return false;
    }

    if (offset + count > (size_t)(caps[nr_caps - 1].end + 1)) {
        /*
         * FIXME write starts within capabilities but extends past them, I think
         * that this _is_ possible, e.g. MSI-X is 12 bytes (PCI_CAP_MSIX_SIZEOF)
         * and the host writes to first 8 bytes and then writes 8 more.
         */
        assert(false);
    }
    return true;
}

/*
 * Returns the PCI capability that is contained within the specified region
 * (offset + count).
 */
static uint8_t *
cap_find(lm_pci_config_space_t *config_space, struct caps *caps, loff_t offset,
         size_t count)
{
    struct cap *cap;

    assert(config_space != NULL);
    assert(caps != NULL);

    cap = caps->caps;
    while (cap < caps->caps + caps->nr_caps) {
        /*
         * FIXME ensure that at most one capability is written to. It might
         * legitimate to write to two capabilities at the same time.
         */
        if (offset >= cap->start && offset <= cap->end) {
            if (offset + count - 1 > cap->end) {
                assert(false);
            }
            return config_space->raw + cap->start;
        }
        cap++;
    }
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

uint8_t *
cap_find_by_id(lm_ctx_t *lm_ctx, uint8_t id)
{
    uint8_t *pos;
    lm_pci_config_space_t *config_space;

    if (!cap_is_valid(id)) {
        errno = EINVAL;
        return NULL;
    }

    config_space = lm_get_pci_config_space(lm_ctx);

    if (config_space->hdr.cap == 0) {
        errno = ENOENT;
        return NULL;
    }

    pos = config_space->raw + config_space->hdr.cap;
    while (true) {
        if (*(pos + PCI_CAP_LIST_ID) == id) {
            return pos;
        }
        if (*(pos + PCI_CAP_LIST_NEXT) == 0) {
            break;
        }
        pos = config_space->raw + *(pos + PCI_CAP_LIST_NEXT);
    }
    errno = ENOENT;        
    return NULL;
}

/*
 * Tells whether the header of a PCI capability is accessed.
 */
static bool
cap_header_is_accessed(uint8_t cap_offset, loff_t offset)
{
    return offset - cap_offset <= 1;
}

typedef ssize_t (cap_access) (lm_ctx_t *lm_ctx, uint8_t *cap, char *buf,
                              size_t count, loff_t offset);

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
handle_pm_write(lm_ctx_t *lm_ctx, uint8_t *cap, char *const buf,
                const size_t count, const loff_t offset)
{
    struct pmcap *pm = (struct pmcap *)cap;

	switch (offset) {
	case offsetof(struct pmcap, pc):
		if (count != sizeof(struct pc)) {
			return -EINVAL;
		}
        assert(false); /* FIXME implement */
        break;
	case offsetof(struct pmcap, pmcs):
		if (count != sizeof(struct pmcs)) {
			return -EINVAL;
		}
		return handle_pmcs_write(lm_ctx, pm, (struct pmcs *)buf);
	}
	return -EINVAL;
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
handle_msix_write(lm_ctx_t *lm_ctx, uint8_t *cap, char *const buf,
                  const size_t count, const loff_t offset)
{
    struct msixcap *msix = (struct msixcap *)cap;

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
handle_px_write(lm_ctx_t *lm_ctx, uint8_t *cap, char *const buf,
                size_t count, loff_t offset)
{
    struct pxcap *px = (struct pxcap *)cap;

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

static const struct cap_handler {
    char *name;
    size_t size;
    cap_access *fn;
} cap_handlers[PCI_CAP_ID_MAX + 1] = {
    [PCI_CAP_ID_PM] = {"PM", PCI_PM_SIZEOF, handle_pm_write},
    [PCI_CAP_ID_EXP] = {"PCI Express", PCI_CAP_EXP_ENDPOINT_SIZEOF_V2,
                        handle_px_write},
    [PCI_CAP_ID_MSIX] = {"MSI-X", PCI_CAP_MSIX_SIZEOF, handle_msix_write},
};

ssize_t
cap_maybe_access(lm_ctx_t *lm_ctx, struct caps *caps, char *buf, size_t count,
                 loff_t offset)
{
    lm_pci_config_space_t *config_space;
    uint8_t *cap;

    if (caps == NULL) {
        return 0;
    }

    if (count == 0) {
        return 0;
    }

    if (!cap_is_accessed(caps->caps, caps->nr_caps, count, offset)) {
        return 0;
    }

    /* we're now guaranteed that the access is within some capability */
    config_space = lm_get_pci_config_space(lm_ctx);
    cap = cap_find(config_space, caps, offset, count);
    assert(cap != NULL); /* FIXME */

    if (cap_header_is_accessed(cap - config_space->raw, offset)) {
        /* FIXME how to deal with writes to capability header? */
        assert(false);
    }
    return cap_handlers[cap[PCI_CAP_LIST_ID]].fn(lm_ctx, cap, buf, count,
                                                 offset - (loff_t)(cap - config_space->raw));
}

struct caps *
caps_create(lm_ctx_t *lm_ctx, lm_cap_t **lm_caps, int nr_caps)
{
    int i, err = 0;
    uint8_t *prev;
    uint8_t next;
    lm_pci_config_space_t *config_space;
    struct caps *caps;

    if (nr_caps <= 0 || nr_caps >= LM_MAX_CAPS) {
        errno = EINVAL;
        return NULL;
    }

    assert(lm_caps != NULL);

    caps = calloc(1, sizeof *caps);
    if (caps == NULL) {
        err = ENOMEM;
        goto out;
    }

    config_space = lm_get_pci_config_space(lm_ctx);
    /* points to the next field of the previous capability */
    prev = &config_space->hdr.cap;

    /* relative offset that points where the next capability should be placed */
    next = PCI_STD_HEADER_SIZEOF;

    for (i = 0; i < nr_caps; i++) {
        uint8_t *cap = (uint8_t*)lm_caps[i];
        uint8_t id = cap[PCI_CAP_LIST_ID];
        size_t size;

        if (!cap_is_valid(id)) {
            err = EINVAL;
            goto out;
        }

        size = cap_handlers[id].size;
        if (size == 0) {
            err = EINVAL;
            goto out;
        }

        caps->caps[i].start = next;
        caps->caps[i].end = next + size - 1;

        memcpy(&config_space->hdr.raw[next], cap, size);
        *prev = next;
        prev = &config_space->hdr.raw[next + PCI_CAP_LIST_NEXT];
        *prev = 0;
        next += size;
        assert(next % 4 == 0); /* FIXME */

        lm_log(lm_ctx, LM_DBG, "initialized capability %s %#x-%#x\n",
               cap_handlers[id].name, caps->caps[i].start, caps->caps[i].end);
    }
    caps->nr_caps = nr_caps;

out:
    if (err) {
        free(caps);
        caps = NULL;
        errno = err;
    }
    return caps;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
