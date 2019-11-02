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

#include <Python.h>

#include "muser.h"

static PyObject *region_access_callbacks[LM_DEV_NUM_REGS];

static int
handle_read(char *dst, PyObject *result, int count)
{
    int i;

    PyArg_Parse(result, "i", &i);
    Py_DECREF(result);
    memcpy(dst, &i, count);
    return 0;
}

/*
 * Function callback called by libmuser. We then call the Python function.
 *
 * FIXME need a way to provide private pointer.
 */
static ssize_t
region_access_wrap(void *pvt, char * const buf, size_t count, loff_t offset,
     const bool is_write, int region)
{
    PyObject *arglist;
    PyObject *result = NULL;
    uint64_t _buf = { 0 };

    if (region_access_callbacks[region] == NULL) {
        fprintf(stderr, "FIXME no callback for region %d\n", region);
        return -1;
    }

    if (is_write) {
        memcpy(&_buf, buf, count);
    }

    /* FIXME not sure about type of count and offset */
    arglist = Py_BuildValue("IKIKi", pvt, _buf, count, offset, is_write);
    if (arglist == NULL) {
        fprintf(stderr, "FIXME failed to build func args\n");
        return -1;
    }
    result = PyEval_CallObject(region_access_callbacks[region], arglist);
    Py_DECREF(arglist);
    if (result == NULL) {
        fprintf(stderr, "FIXME failed to call fn for region %d\n", region);
        return -1;
    }
    if (!is_write) {
        if (handle_read(buf, result, count)) {
            return -1;
        }
    }
    return count;
}

#define REGION_WRAP(region) \
    static ssize_t                                                      \
    r_##region##_wrap(void *p, char * const b, size_t c, loff_t o,  \
                          const bool w)                                 \
    {                                                                   \
        return region_access_wrap(p, b, c, o, w, region);               \
    }

REGION_WRAP(0)
REGION_WRAP(1)
REGION_WRAP(2)
REGION_WRAP(3)
REGION_WRAP(4)
REGION_WRAP(5)
REGION_WRAP(6)
REGION_WRAP(7)
REGION_WRAP(8)

static ssize_t (*region_access_wraps[LM_DEV_NUM_REGS])(void *, char *, size_t,
                                                       loff_t, bool) = {
    r_0_wrap,
    r_1_wrap,
    r_2_wrap,
    r_3_wrap,
    r_4_wrap,
    r_5_wrap,
    r_6_wrap,
    r_7_wrap,
    r_8_wrap
};

struct _region_info {
    char *perm;
    unsigned int size;
    PyObject *fn;
};

static const struct _region_info _0_ri;

static PyObject *log_fn;
static lm_log_lvl_t log_lvl = LM_ERR;

static void _log_fn(void *pvt, const char *const msg)
{
    PyObject *arglist;
    PyObject *result = NULL;

    arglist = Py_BuildValue("(s)", msg);
    result = PyEval_CallObject(log_fn, arglist);
    Py_DECREF(arglist);
    if (result != NULL) {
        Py_DECREF(result);
    }
}

static PyObject *
libmuser_run(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"vid", "did", "uuid", "log", "log_lvl",
                             "bar0", "bar1", "bar2", "bar3", "bar4", "bar5", "rom", "cfg", "vga",
                             "intx", "msi", "msix", "err", "req",
                             NULL};
    int err;
    lm_dev_info_t dev_info = { 0 };
    int i;
    struct _region_info _ri[LM_DEV_NUM_REGS] = { 0 };

    if (!PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "HHs|Oi(sIO)(sIO)(sIO)(sIO)(sIO)(sIO)(sIO)(sIO)(sIO)IIIII",
            kwlist,
            &dev_info.pci_info.id.vid,
            &dev_info.pci_info.id.did,
            &dev_info.uuid,
            &log_fn,
            &log_lvl,
            &_ri[0].perm, &_ri[0].size, &_ri[0].fn,
            &_ri[1].perm, &_ri[1].size, &_ri[1].fn,
            &_ri[2].perm, &_ri[2].size, &_ri[2].fn,
            &_ri[3].perm, &_ri[3].size, &_ri[3].fn,
            &_ri[4].perm, &_ri[4].size, &_ri[4].fn,
            &_ri[5].perm, &_ri[5].size, &_ri[5].fn,
            &_ri[6].perm, &_ri[6].size, &_ri[6].fn,
            &_ri[7].perm, &_ri[7].size, &_ri[7].fn,
            &_ri[8].perm, &_ri[8].size, &_ri[8].fn,
            &dev_info.pci_info.irq_count[0],
            &dev_info.pci_info.irq_count[1],
            &dev_info.pci_info.irq_count[2],
            &dev_info.pci_info.irq_count[3],
            &dev_info.pci_info.irq_count[4])) {
        return NULL;
    }

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        int j;
        uint32_t flags = 0;

        if (i == LM_DEV_CFG_REG_IDX && !memcmp(&_0_ri, &_ri[i], sizeof _0_ri)) {
            continue;
        }

        if (_ri[i].perm != NULL) {
            for (j = 0; j < strlen(_ri[i].perm); j++) {
                if (_ri[i].perm[j] == 'r') {
                    flags |= LM_REG_FLAG_READ;
                } else if (_ri[i].perm[j] == 'w') {
                    flags |= LM_REG_FLAG_WRITE;
                } else {
                    /* FIXME shouldn't print to stderr */
                    fprintf(stderr, "bad permission '%c'\n", _ri[i].perm[j]);
                    return NULL;
                }
            }
        }
        region_access_callbacks[i] = _ri[i].fn;
        dev_info.pci_info.reg_info[i].flags = flags;
        dev_info.pci_info.reg_info[i].size = _ri[i].size;
        dev_info.pci_info.reg_info[i].fn = region_access_wraps[i];
    }

    if (log_fn != NULL) {
        if (!PyCallable_Check(log_fn)) {
            return NULL;
        }
        dev_info.log = _log_fn;
        dev_info.log_lvl = log_lvl;
    }

    err = lm_ctx_run(&dev_info);
    return Py_BuildValue("i", err);
}

static PyMethodDef LibmuserMethods[] = {
    { "run",
      (PyCFunction)libmuser_run,
      METH_VARARGS | METH_KEYWORDS,
      "runs a device"
    },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC
initmuser(void)
{
    (void)Py_InitModule("muser", LibmuserMethods);
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
