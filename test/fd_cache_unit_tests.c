/*
 * Copyright (c) Meta Platforms, Inc. and affiliates
 *
 * Authors: Mattias Nissler <mnissler@meta.com>
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

#undef NDEBUG /* so assert() works in release builds */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "fd_cache.h"

/* See fd_cache.c */
extern bool kcmp_checked;
extern bool kcmp_available;

static int
make_tmpfile()
{
    char template[] = "libvfio_user_fd_cache_tests_tmp_XXXXXX";
    int fd;

    fd = mkstemp(template);
    assert(fd != -1);
    assert(unlink(template) == 0);

    return fd;
}

static void
test_tmpfile()
{
    int fd1, fd2, fd3;

    fd1 = make_tmpfile();
    fd2 = dup(fd1);
    assert(fd2 != -1);
    assert(fd2 != fd1);

    /* Confirm that the cache recognizes duplicated file descriptors. */
    fd1 = fd_cache_get(fd1);
    assert(fd1 != -1);
    fd2 = fd_cache_get(fd2);
    assert(fd2 != -1);
    assert(fd1 == fd2);

    /* Make sure an unrelated file descriptor doesn't get de-duplicated. */
    fd3 = make_tmpfile();
    assert(fd3 != -1);
    fd3 = fd_cache_get(fd3);
    assert(fd3 != -1);
    assert(fd1 != fd3);

    fd_cache_put(fd1);
    fd_cache_put(fd2);
    fd_cache_put(fd3);
}

static void
test_eventfd()
{
    int fd1, fd2;

    fd1 = eventfd(0, 0);
    assert(fd1 != -1);
    fd2 = dup(fd1);
    assert(fd2 != -1);

    fd1 = fd_cache_get(fd1);
    assert(fd1 != -1);
    fd2 = fd_cache_get(fd2);
    assert(fd2 != -1);

    /*
     * If we don't have kcmp, file descriptors for non-regular files can't be
     * de-duplicated reliably, so make sure the cache ignores them.
     */
    if (kcmp_available) {
        assert(fd1 == fd2);
    } else {
        assert(fd1 != fd2);
    }

    fd_cache_put(fd1);
    fd_cache_put(fd2);
}

int
main(void)
{
    test_tmpfile();
    test_eventfd();

    /* Enable fallback mode for the remaining test cases. */
    kcmp_checked = true;
    kcmp_available = false;

    /* Run tests again, with the fallback force-enabled. */
    test_tmpfile();
    test_eventfd();

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
