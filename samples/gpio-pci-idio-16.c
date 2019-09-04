/* gpio-pci-idio-16 */

#include <stdio.h>

#include "../lib/muser.h"

ssize_t
bar2_access(void *pvt, char * const buf, size_t count, loff_t offset,
           const bool is_write)
{
    static char n;

    if (offset == 0 && !is_write)
        buf[0] = n++ / 3;

    return count;
}

int main(int argc, char **argv)
{
    lm_dev_info_t dev_info = {
        .pci_info = {
            .id = {.vid = 0x494F, .did = 0x0DC8 },
            .reg_info[LM_DEV_BAR2_REG_IDX] = {
                .flags = LM_REG_FLAG_RW,
                .size = 0x100,
                .fn = &bar2_access
            },
            .irq_count[LM_DEV_INTX_IRQ_IDX] = 1,
        },
        .uuid = argv[1],
    };

    return lm_ctx_run(&dev_info);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
