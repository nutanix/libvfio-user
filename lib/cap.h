#include "muser.h"

struct caps;

/**
 * Initializes PCI capabilities.
 *
 * Returns <0 on error, 0 if no capabilities are to be added, and >0 if all
 * capabilities have been added.
 */
struct caps*
caps_create(lm_cap_t *caps, int nr_caps);

/*
 * Conditionally accesses the PCI capabilities. Returns:
 *  0: if no PCI capabilities are accessed,
 * >0: if a PCI capability was accessed, with the return value indicating the
       number of bytes accessed, and
 * <0: negative error code on error.
 */
ssize_t
cap_maybe_access(struct caps *caps, void *pvt, char *buf, size_t count,
                 loff_t offset, bool is_write);

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
