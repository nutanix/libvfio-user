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

/*
 * Helper functions for de-duplicating file descriptors.
 *
 * VFIO-user clients may provide file descriptors when registering DMA regions
 * for the server to perform accesses directly to the underlying resource. In
 * the presence of IOMMUs or other memory address translation mechanisms, the
 * same underlying file can be used for many DMA regions. The client passes
 * many file descriptors in this case, which are typically all duplicates of a
 * small number of unique file descriptors the client has originally opened for
 * the underlying resources. Because file descriptors are a limited resource,
 * it makes sense for the server to de-duplicate the descriptors where possible
 * and only keep one representative copy.
 */

#ifndef LIB_VFIO_USER_FD_CACHE_H
#define LIB_VFIO_USER_FD_CACHE_H

/*
 * Get a de-duplicated copy of the given file descriptor.
 *
 * If the provided file descriptor is present in the cache, returns a
 * representative file descriptor. On cache miss, the file descriptor is added
 * to the cache.
 *
 * Note that the provided file descriptor is consumed if the function succeeds
 * but its ownership remains with the caller on failure.
 *
 * Returns a file descriptor equivalent to the provided descriptor, or -1 on
 * error. The returned descriptor must be released by calling fd_cache_put()
 * when the caller no longer needs the descriptor.
 *
 * Depending on whether the `kcmp` syscall is available and functions
 * correctly, this function might ignore certain kinds of file descriptors and
 * bypass the cache for them. They won't be de-duplicated, but the API surface
 * is still consistent: fd_cache_get always returns the passed fd in this case,
 * and fd_cache_put will just close the file descriptor.
 */
int
fd_cache_get(int fd);

/*
 * Release a file descriptor previously acquired from the cache.
 *
 * Returns 0 and sets fd to -1 on success, or returns -1 on error with errno
 * set. Specifically, ENOENT indicates that the provided file descriptor isn't
 * present in the cache. A -1 value in the fd argument is accepted and ignored
 * without taking action as a special case for convenience.
 */
int
fd_cache_put(int *fd);

/*
 * A utility function to test whether two file descriptors refer to the same
 * open file. This is only accurate for all cases when kcmp is available. When
 * it is not (because the kernel doesn't support it or it is blocked by
 * seccomp), we fall back to a heuristic, which isn't entirely accurate.
 * Specifically, it has false positives and may report file descriptors to be
 * equivalent when they are in fact not. In particular, this happens for
 * anon_inode based file descriptors that don't have a unique inode number, as
 * is the case for eventfd, for example.
 *
 * Returns 1 if the referenced files are different, 0 if the files appear to
 * match (with the caveats mentioned above) and -1 on error.
 */
int
fd_cache_is_same_file(int fd1, int fd2);

#endif /* LIB_VFIO_USER_FD_CACHE_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
