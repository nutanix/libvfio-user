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

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef HAVE_LINUX_KCMP_H
#include <linux/kcmp.h>
#endif

#include "btree.h"
#include "common.h"
#include "fd_cache.h"

/* The file descriptor cache is a global B-tree, protected by a mutex. */
static btree_t cache_tree;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Not static so the unit test can access these for fallback testing. */
bool kcmp_checked;
bool kcmp_available;

struct fd_cache_entry {
    int fd;
    dev_t dev;
    ino_t ino;
    int flags;
    int refcount;
};

#ifdef HAVE_LINUX_KCMP_H
static int
kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)
{
    return syscall(SYS_kcmp, pid1, pid2, type, idx1, idx2);
}

/* Note that this is called under cache_mutex, thus guaranteeing once-only init. */
static bool
is_kcmp_available(int fd)
{
    if (!kcmp_checked) {
        pid_t pid = getpid();

        kcmp_available = kcmp(pid, pid, KCMP_FILE, fd, fd) == 0;
        kcmp_checked = true;
    }

    return kcmp_available;
}
#else
#define is_kcmp_available(fd) (false)
#endif

static int
is_same_file(const struct fd_cache_entry *entry1,
             const struct fd_cache_entry *entry2)
{
#ifdef HAVE_LINUX_KCMP_H
    /*
     * We prefer using kcmp for detecting file descriptor duplicates.
     * Unfortunately, it's not available on all kernel versions/configurations,
     * and Docker's default seccomp policy blocks it. Thus we fall back to
     * comparing device and inode numbers as well as flags bits. Note that the
     * fallback isn't a perfect replacement, as it will consider file
     * descriptors identical even though they originate from separate open()
     * calls as long as their parameters match. That's OK though, as we really
     * only care about the targets. Specifically, the file positions aren't
     * of relevance due to using pread/pwrite with explicit offsets.
     */
    if (is_kcmp_available(entry1->fd)) {
        pid_t pid = getpid();
        return kcmp(pid, pid, KCMP_FILE, entry1->fd, entry2->fd);
    }
#endif

    return !(entry1->dev == entry2->dev && entry1->ino == entry2->ino &&
             entry1->flags == entry2->flags);
}

static int
fd_cache_entry_init(int fd, struct fd_cache_entry *entry, bool *accurate)
{
    struct stat st;
    int flags;

    if (fstat(fd, &st) != 0 || (flags = fcntl(fd, F_GETFL)) == -1) {
        return -1;
    }

    entry->fd = fd;
    entry->dev = st.st_dev;
    entry->ino = st.st_ino;
    entry->flags = flags;
    entry->refcount = 0;

    /*
     * Indicate whether fd equivalence testing will work accurately for the fd.
     * This is trivially true when kcmp is available. When operating in
     * fallback mode, declare that non-regular files can't be accurately
     * compared. This is to exclude most "exotic" file descriptors such as
     * eventfd, etc. The reason is that some of these don't have unique inode
     * numbers, which would cause false positives in (dev, inode)-based
     * duplicate detection.
     */
    *accurate = is_kcmp_available(fd) || S_ISREG(st.st_mode);

    return 0;
}

static uintptr_t
fd_cache_entry_compute_key(const struct fd_cache_entry *entry)
{
    /*
     * Compute a key from device and inode numbers. Note that the key value
     * isn't unique per file descriptor, but at best per file (assuming there
     * are no key collisions). That's OK given that the cache B-Tree can handle
     * multiple entries with the same key, at least as long as the number of
     * identical keys doesn't grow too large.
     */
    return entry->ino ^ (bswap_64(entry->dev) >>
                         ((sizeof(uint64_t) - sizeof(uintptr_t)) * CHAR_BIT));
}

static int
fd_cache_lookup(const struct fd_cache_entry *query, btree_iter_t *iter,
                struct fd_cache_entry **entry)
{
    uintptr_t query_key = fd_cache_entry_compute_key(query);
    uintptr_t key;
    int ret;

    /*
     * Note that the key is not guaranteed to be unique: Collisions can happen
     * if we have multiple independent file descriptors (not just duplicates)
     * for a given file, or when the cache keys are colliding accidentally (due
     * to unfortunate inode/device number values).
     *
     * Thus, we iterate over all entries matching the target key and rely on
     * `is_same_file` to identify actually matching entries.
     */
    for (btree_iter_init(&cache_tree, query_key, iter);
         (*entry = btree_iter_get(iter, &key)) != NULL && query_key == key;
         btree_iter_next(iter)) {
        ret = is_same_file(query, *entry);
        if (ret <= 0) {
            return ret;
        }
    }

    *entry = NULL;
    return 0;
}

static int
fd_cache_get_locked(int fd)
{
    struct fd_cache_entry *entry;
    struct fd_cache_entry query;
    btree_iter_t iter;
    uintptr_t key;
    bool accurate;

    if (fd_cache_entry_init(fd, &query, &accurate) != 0) {
        return -1;
    }

    /*
     * When we can't make accurate comparisons, bypass the cache and
     * pretend to the caller that everything is fine.
     */
    if (!accurate) {
        return fd;
    }

    if (fd_cache_lookup(&query, &iter, &entry) != 0) {
        return -1;
    }

    if (entry != NULL) {
        close_safely(&fd);
        ++entry->refcount;
        return entry->fd;
    }

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        errno = ENOMEM;
        return -1;
    }

    *entry = query;
    entry->refcount = 1;

    key = fd_cache_entry_compute_key(entry);
    if (btree_iter_insert(&iter, key, entry) != 0) {
        close_safely(&entry->fd);
        free(entry);
        return -1;
    }

    return entry->fd;
}

static int
fd_cache_put_locked(int fd)
{
    struct fd_cache_entry *entry;
    struct fd_cache_entry query;
    btree_iter_t iter;
    bool accurate;

    if (fd == -1) {
        return 0;
    }

    if (fd_cache_entry_init(fd, &query, &accurate) != 0) {
        return -1;
    }

    if (!accurate) {
        /*
         * This file descriptor isn't eligible for de-duplication and thus
         * fd_cache_get hasn't created a cache entry. Just close the
         * descriptor to provide consistent semantics to the caller.
         */
        close_safely(&fd);
        return 0;
    }

    if (fd_cache_lookup(&query, &iter, &entry) != 0) {
        return -1;
    }

    if (entry == NULL || entry->fd != fd) {
        errno = ENOENT;
        return -1;
    }

    assert(entry->refcount > 0);
    --entry->refcount;

    if (entry->refcount == 0) {
        btree_iter_remove(&iter);
        close_safely(&entry->fd);
        free(entry);
    }

    return 0;
}

int
fd_cache_get(int fd)
{
    int ret;

    pthread_mutex_lock(&cache_mutex);
    ret = fd_cache_get_locked(fd);
    pthread_mutex_unlock(&cache_mutex);

    return ret;
}

int
fd_cache_put(int fd)
{
    int ret;

    pthread_mutex_lock(&cache_mutex);
    ret = fd_cache_put_locked(fd);
    pthread_mutex_unlock(&cache_mutex);

    return ret;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
