#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "muser.h"
#include "cap.h"

struct cap {
    uint8_t         start;
    uint8_t         end;
    uint8_t         id;
    lm_cap_access_t *fn;
};

struct caps {
    struct cap   caps[LM_MAX_CAPS];
    int             nr_caps;
};

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

static struct cap*
cap_find(struct cap *caps, int nr_caps, loff_t offset, size_t count)
{
    struct cap *cap;
    bool found = false;

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
        buf[n++] = cap->id;
        offset++;
        count--;
    }
    if (offset == cap->start + 1 && count > 0) { /* next */

        if ((cap - caps->caps) / sizeof *cap == caps->nr_caps - 1) {
            buf[n++] = 0;
        } else {
            buf[n++] = (cap + 1)->start;
        }

        offset++;
        count--;
    }
    return n;
}

ssize_t
cap_maybe_access(struct caps *caps, void *pvt, char *buf, size_t count,
                 loff_t offset, bool is_write)
{
    bool found;
    struct cap *cap;
    int n;

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
        return -EINVAL;
    }

    if (cap_header_is_accessed(cap, offset)) {
        return cap_header_access(caps, cap, buf, offset, count, is_write);
    }
    if (count > 0) {
        return cap->fn(pvt, cap->id, buf, count, offset - cap->start, is_write);
    }
    return 0;
}

static bool
cap_is_valid(uint8_t id)
{
    return id >= PCI_CAP_ID_PM && id <= PCI_CAP_ID_MAX;
}

struct caps*
caps_create(lm_cap_t *lm_caps, int nr_caps)
{
    uint8_t prev_end;
    int i, err = 0;
    struct caps *caps = NULL;

    if (nr_caps <= 0 || nr_caps >= LM_MAX_CAPS) {
        err = EINVAL;
        goto out;
    }

    assert(lm_caps);

    caps = calloc(1, sizeof *caps);
    if (!caps) {
        err = errno;
        goto out;
    }

    prev_end = PCI_STD_HEADER_SIZEOF - 1;
    for (i = 0; i < nr_caps; i++) {
        if (!cap_is_valid(lm_caps[i].id) || !lm_caps[i].fn || !lm_caps[i].size) {
            err = EINVAL;
            goto out;
        }

        caps->caps[i].id = lm_caps[i].id;
        caps->caps[i].fn = lm_caps[i].fn;
        /* FIXME PCI capabilities must be dword aligned. */
        caps->caps[i].start = prev_end + 1;
        caps->caps[i].end = prev_end = caps->caps[i].start + lm_caps[i].size - 1;
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
