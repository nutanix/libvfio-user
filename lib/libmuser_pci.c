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
#include <assert.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>

#include <linux/pci_regs.h>
#include <linux/vfio.h>

#include "muser.h"
#include "muser_priv.h"
#include "pci.h"
#include "common.h"

static inline void
muser_pci_hdr_write_bar(lm_ctx_t *lm_ctx, uint16_t bar_index, const char *buf)
{
    uint32_t cfg_addr;
    unsigned long mask;
    lm_reg_info_t *reg_info = lm_get_region_info(lm_ctx);
    lm_pci_hdr_t *hdr;

    assert(lm_ctx);

    if (reg_info[bar_index].size == 0) {
        return;
    }

    hdr = &lm_get_pci_config_space(lm_ctx)->hdr;

    cfg_addr = *(uint32_t *) buf;

    lm_log(lm_ctx, LM_DBG, "BAR%d addr 0x%x\n", bar_index, cfg_addr);

    if (cfg_addr == 0xffffffff) {
        cfg_addr = ~(reg_info[bar_index].size) + 1;
    }

    if ((reg_info[bar_index].flags & LM_REG_FLAG_MEM)) {
        mask = PCI_BASE_ADDRESS_MEM_MASK;
    } else {
        mask = PCI_BASE_ADDRESS_IO_MASK;
    }
    cfg_addr |= (hdr->bars[bar_index].raw & ~mask);

    hdr->bars[bar_index].raw = htole32(cfg_addr);
}

#define BAR_INDEX(offset) ((offset - PCI_BASE_ADDRESS_0) >> 2)

static int
handle_command_write(lm_ctx_t *ctx, lm_pci_config_space_t *pci,
                     const char *buf, size_t count)
{
    uint16_t v;

    assert(ctx);

    if (count != 2) {
        lm_log(ctx, LM_ERR, "bad write command size %d\n", count);
        return -EINVAL;
    }

    assert(pci);
    assert(buf);

    v = *(uint16_t*)buf;

    if ((v & PCI_COMMAND_IO) == PCI_COMMAND_IO) {
        if (!pci->hdr.cmd.iose) {
            pci->hdr.cmd.iose = 0x1;
            lm_log(ctx, LM_INF, "I/O space enabled\n");
        }
        v &= ~PCI_COMMAND_IO;
    } else {
        if (pci->hdr.cmd.iose) {
            pci->hdr.cmd.iose = 0x0;
            lm_log(ctx, LM_INF, "I/O space disabled\n");
        }
    }

    if ((v & PCI_COMMAND_MEMORY) == PCI_COMMAND_MEMORY) {
        if (!pci->hdr.cmd.mse) {
            pci->hdr.cmd.mse = 0x1;
            lm_log(ctx, LM_INF, "memory space enabled\n");
        }
        v &= ~PCI_COMMAND_MEMORY;
    } else {
        if (pci->hdr.cmd.mse) {
            pci->hdr.cmd.mse = 0x0;
            lm_log(ctx, LM_INF, "memory space disabled\n");
        }
    }

    if ((v & PCI_COMMAND_MASTER) == PCI_COMMAND_MASTER) {
        if (!pci->hdr.cmd.bme) {
            pci->hdr.cmd.bme = 0x1;
            lm_log(ctx, LM_INF, "bus master enabled\n");
        }
        v &= ~PCI_COMMAND_MASTER;
    } else {
        if (pci->hdr.cmd.bme) {
            pci->hdr.cmd.bme = 0x0;
            lm_log(ctx, LM_INF, "bus master disabled\n");
        }
    }

    if ((v & PCI_COMMAND_SERR) == PCI_COMMAND_SERR) {
        if (!pci->hdr.cmd.see) {
            pci->hdr.cmd.see = 0x1;
            lm_log(ctx, LM_INF, "SERR# enabled\n");
        }
        v &= ~PCI_COMMAND_SERR;
    } else {
        if (pci->hdr.cmd.see) {
            pci->hdr.cmd.see = 0x0;
            lm_log(ctx, LM_INF, "SERR# disabled\n");
        }
    }

    if ((v & PCI_COMMAND_INTX_DISABLE) == PCI_COMMAND_INTX_DISABLE) {
        if (!pci->hdr.cmd.id) {
            pci->hdr.cmd.id = 0x1;
            lm_log(ctx, LM_INF, "INTx emulation enabled\n");
        }
        v &= ~PCI_COMMAND_INTX_DISABLE;
    } else {
        if (pci->hdr.cmd.id) {
            pci->hdr.cmd.id = 0x0;
            lm_log(ctx, LM_INF, "INTx emulation disabled\n");
        }
    }

    if (v) {
        lm_log(ctx, LM_ERR, "unconsumed command flags %x\n", v);
        return -EINVAL;
    }

    return 0;
}

static int
handle_erom_write(lm_ctx_t *ctx, lm_pci_config_space_t *pci,
                  const char *buf, size_t count)
{
    uint32_t v;

    assert(ctx);
    assert(pci);

    if (count != 0x4) {
        lm_log(ctx, LM_ERR, "bad EROM count %d\n", count);
        return -EINVAL;
    }
    v = *(uint32_t*)buf;

    if (v == (uint32_t)PCI_ROM_ADDRESS_MASK) {
        lm_log(ctx, LM_INF, "write mask to EROM ignored\n");
    } else if (v == 0) {
        lm_log(ctx, LM_INF, "cleared EROM\n");
        pci->hdr.erom = 0;
    } else if (v == (uint32_t)~PCI_ROM_ADDRESS_ENABLE) {
        lm_log(ctx, LM_INF, "EROM disable ignored\n");
    } else {
        lm_log(ctx, LM_ERR, "bad write to EROM 0x%x bytes\n", v);
        return -EINVAL;
    }
    return 0;
}

static inline int
muser_pci_hdr_write(lm_ctx_t *lm_ctx, uint16_t offset,
                    const char *buf, size_t count)
{
    lm_pci_config_space_t *pci;
    int ret = 0;

    assert(lm_ctx);
    assert(buf);

    pci = lm_get_pci_config_space(lm_ctx);

    switch (offset) {
    case PCI_COMMAND:
        ret = handle_command_write(lm_ctx, pci, buf, count);
        break;
    case PCI_STATUS:
        lm_log(lm_ctx, LM_INF, "write to status ignored\n");
        break;
    case PCI_INTERRUPT_PIN:
        lm_log(lm_ctx, LM_ERR, "attempt to write read-only field IPIN\n");
        ret = -EINVAL;
        break;
    case PCI_INTERRUPT_LINE:
        pci->hdr.intr.iline = buf[0];
        lm_log(lm_ctx, LM_DBG, "ILINE=%0x\n", pci->hdr.intr.iline);
        break;
    case PCI_LATENCY_TIMER:
        pci->hdr.mlt = (uint8_t)buf[0];
        lm_log(lm_ctx, LM_INF, "set to latency timer to %hhx\n", pci->hdr.mlt);
        break;
    case PCI_BASE_ADDRESS_0:
    case PCI_BASE_ADDRESS_1:
    case PCI_BASE_ADDRESS_2:
    case PCI_BASE_ADDRESS_3:
    case PCI_BASE_ADDRESS_4:
    case PCI_BASE_ADDRESS_5:
        muser_pci_hdr_write_bar(lm_ctx, BAR_INDEX(offset), buf);
        break;
    case PCI_ROM_ADDRESS:
        ret = handle_erom_write(lm_ctx, pci, buf, count);
        break;
    default:
        lm_log(lm_ctx, LM_INF, "PCI config write %x@%x not handled\n",
               count, offset);
        ret = -EINVAL;
    }

#ifndef LM_TERSE_LOGGING
    dump_buffer(lm_ctx, "PCI header", pci->hdr.raw, 0xff);
#endif

    return ret;
}

/*
 * @pci_hdr: the PCI header
 * @reg_info: region info
 * @rw: the command
 * @write: whether this is a PCI header write
 * @count: output parameter that receives the number of bytes read/written
 */
static inline int
muser_do_pci_hdr_access(lm_ctx_t *lm_ctx, size_t *count,
                        loff_t *pos, bool is_write,
                        char *buf)
{
    size_t _count;
    loff_t _pos;
    int err = 0;

    assert(lm_ctx);
    assert(count);
    assert(pos);
    assert(buf);

    _pos = *pos - region_to_offset(LM_DEV_CFG_REG_IDX);
    _count = MIN(*count, PCI_STD_HEADER_SIZEOF - _pos);

    if (is_write) {
        err = muser_pci_hdr_write(lm_ctx, _pos, buf, _count);
    } else {
        memcpy(buf, lm_get_pci_config_space(lm_ctx)->hdr.raw + _pos, _count);
    }
    *pos += _count;
    *count -= _count;
    return err;
}

static inline bool
muser_is_pci_hdr_access(loff_t pos)
{
    const off_t off = (loff_t) region_to_offset(LM_DEV_CFG_REG_IDX);
    return pos - off >= 0 && pos - off < PCI_STD_HEADER_SIZEOF;
}

int
muser_pci_hdr_access(lm_ctx_t *lm_ctx, size_t *count,
                     loff_t *pos, bool is_write,
                     char *buf)
{
    assert(lm_ctx);
    assert(count);
    assert(pos);

    if (!muser_is_pci_hdr_access(*pos)) {
        return 0;
    }
    return muser_do_pci_hdr_access(lm_ctx, count, pos, is_write, buf);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
