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

/*
 * Private utilities used by the library and sample/test code.
 */

#ifndef LIB_VFIO_USER_COMMON_H
#define LIB_VFIO_USER_COMMON_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/uio.h>

#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))

#define ONE_TB              (1024UL * 1024 * 1024 * 1024)
#define PAGE_SIZE           (size_t)sysconf(_SC_PAGE_SIZE)
#define PAGE_ALIGNED(x)		(((x) & ((typeof(x))(PAGE_SIZE) - 1)) == 0)

#define BIT(nr)             (1UL << (nr))

#define ARRAY_SIZE(array)   (sizeof(array) / sizeof((array)[0]))

#define likely(e)   __builtin_expect(!!(e), 1)
#define unlikely(e) __builtin_expect(e, 0)

/* XXX NB 2nd argument must be power of two */
#define ROUND_DOWN(x, a)    ((x) & ~((a)-1))
#define ROUND_UP(x,a)       ROUND_DOWN((x)+(a)-1, a)

typedef unsigned long long ull_t;

static inline int
ERROR_INT(int err)
{
    errno = err;
    return -1;
}

static inline void *
ERROR_PTR(int err)
{
    errno = err;
    return NULL;
}

/* Saturating uint64_t addition. */
static inline uint64_t
satadd_u64(uint64_t a, uint64_t b)
{
    uint64_t res = a + b;
    return (res < a) ? UINT64_MAX : res;
}

/*
 * The size, in bytes, of the bitmap that represents the given range with the
 * given page size.
 * 
 * Returns -1 and sets errno if the given page size is invalid for the given 
 * range.
 */
static inline ssize_t
get_bitmap_size(size_t region_size, size_t pgsize)
{
    if (pgsize == 0) {
        return ERROR_INT(EINVAL);
    }
    if (region_size < pgsize) {
        return ERROR_INT(EINVAL);
    }

    size_t nr_pages = (region_size / pgsize) + (region_size % pgsize != 0);
    return ROUND_UP(nr_pages, sizeof(uint64_t) * CHAR_BIT) / CHAR_BIT;
}

/*
 * Closes the given file descriptor, and resets the value to -1. Preserves
 * errno. Skips closing if *fd is -1.
 */
static inline void
close_safely(int *fd)
{
    int saved_errno = errno;
    if (fd != NULL && *fd != -1) {
        /*
         * POSIX says that close may hit EINTR and leave the file descriptor in
         * undefined state. But retrying on EINTR is incorrect, since a
         * different thread might have re-opened a file on the same descriptor
         * if close actually did free the descriptor. In practice, Linux always
         * closes the file descriptor and POSIX has decided to align semantics
         * with Linux. Thus, calling close once and ignoring the error is the
         * most appropriate course of action.
         *
         * See also https://www.austingroupbugs.net/view.php?id=529
         */
        (void) close(*fd);
        *fd = -1;
    }
    errno = saved_errno;
}

static inline void
iov_free(struct iovec *iov)
{
    if (iov->iov_base != NULL) {
        free(iov->iov_base);
        iov->iov_base = NULL;
    }
    iov->iov_len = 0;
}

#ifdef UNIT_TEST

#define MOCK_DEFINE(f) \
    (__real_ ## f)

#define MOCK_DECLARE(r, f, ...) \
    r f(__VA_ARGS__); \
    r __real_ ## f(__VA_ARGS__); \
    r __wrap_ ## f(__VA_ARGS__);

#else /* UNIT_TEST */

#define MOCK_DEFINE(f) (f)

#define MOCK_DECLARE(r, f, ...) \
    r f(__VA_ARGS__);

#endif /* UNIT_TEST */

#endif /* LIB_VFIO_USER_COMMON_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
