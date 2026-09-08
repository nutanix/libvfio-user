/*
 * Copyright (c) 2026 Nutanix Inc. All rights reserved.
 *
 * Authors: Jihyeon Gim <potatogim@potatogim.net>
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
 * Compiler compatibility helpers shared by the installed libvfio-user headers.
 */

#ifndef LIB_VFIO_USER_COMPILER_H
#define LIB_VFIO_USER_COMPILER_H

/*
 * C++ has no _Static_assert; static_assert is the C++11 spelling.  This
 * lets the layout assertions in the installed headers compile in both
 * languages without depending on the consumer's C standard or
 * feature-test macros.
 */
#ifdef __cplusplus
#define VFU_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define VFU_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#endif /* LIB_VFIO_USER_COMPILER_H */
