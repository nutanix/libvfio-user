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

#include "private.h"

#ifndef check_expected_int
#define check_expected_int(parameter) \
    check_expected(parameter)
#endif

#ifndef check_expected_uint
#define check_expected_uint(parameter) \
    check_expected(parameter)
#endif

#ifndef expect_int_value
#define expect_int_value(function, parameter, value) \
    expect_value(function, parameter, value)
#endif

#ifndef expect_uint_value
#define expect_uint_value(function, parameter, value) \
    expect_value(function, parameter, value)
#endif

#ifndef expect_check_data
typedef uintmax_t CMockaValueData;

#define cast_ptr_to_cmocka_value(value)       ((uintptr_t) (value))
#define extract_uint_from_cmocka_value(value) (value)

#define expect_check_data(function, parameter, check_function, check_data) \
    expect_check(function, parameter, check_function, check_data)
#else
#define extract_uint_from_cmocka_value(value) ((value).uint_val)
#endif

void unpatch_all(void);

void patch(const char *name);

void mock_dma_register(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info);

void mock_dma_unregister(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info);

int mock_reset_cb(vfu_ctx_t *vfu_ctx, vfu_reset_type_t type);

int mock_notify_migr_state_trans_cb(vfu_ctx_t *vfu_ctx,
                                    vfu_migr_state_t vfu_state);

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
