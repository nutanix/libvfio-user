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
 * B-tree data structure.
 *
 * A straightforward B-tree implementation using page-sized nodes. Each entry
 * maps a numeric `uintptr_t` key to a void* value. The tree stores the
 * key-value pairs in ascending key order. Multiple copies of the same key are
 * allowed. Values are opaque to the tree, in particular, it is OK to store
 * NULL values.
 *
 * Tree elements are accessed via iterators represented by `btree_iter_t`.
 * Insertion and removal of elements are operations on the iterator to avoid
 * redundant lookup.
 */

#ifndef LIB_VFIO_USER_BTREE_H
#define LIB_VFIO_USER_BTREE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Represents a B-Tree. Contains tree-wide parameters and the root node
 * pointer. See also btree_init and btree_destroy.
 */
typedef struct {
    struct btree_node *root;
    /* Number of entries in the tree. */
    size_t size;
    /* Current tree height. */
    int height;
} btree_t;

/*
 * Maximum B-tree height. With a page-sized node holding 170 entries (on an
 * LP64 system), the fan-out is 171, so a 6-level tree will have (per formula
 * for truncated geometric series) `(1 - 171^(6 + 1)) / (1 - 171)` page-sized
 * nodes, which exceeds 2^52 (which corresponds to the maximum amount of
 * addressable memory in today's typical hardware).
 */
#define BTREE_MAX_HEIGHT 6

/*
 * A "cursor", encoding a btree node pointer and an index within the node. We
 * allocate nodes with a minimum alignment, so the lower pointer bits are
 * always zero and can hold the index.
 */
typedef uintptr_t btree_cursor_t;

/*
 * An iterator type representing a position within the sequence of elements
 * stored in the tree. Iterators are not only used for lookup, but also used to
 * specify the location where to insert or remove elements.
 */
typedef struct {
    /* Points back at the tree that we're iterating. */
    btree_t *tree;
    /*
     * Cursors indicating the node and index within the node for each level.
     * The intuition here is that the iterator position splits the tree into a
     * left and right half, and the split position is given by the node / split
     * index pair for each level.
     *
     * Note that the cursor stack uniquely defines the element before and after
     * the split position: Start looking on the leaf level. If there is a right
     * (or left) element at the cutting position, that's the element we're
     * looking for. If there is no element (because we're at the left or right
     * end of the node), then check the next higher level, recursively, until
     * we find an element. If we don't find a level that has a right (or left)
     * element, then we're at the right (or left) end of the tree.
     *
     * The leaf level is at index zero, index increasing towards the tree root
     * with the last valid entry at iter->tree->height - 1.
     */
    btree_cursor_t cursors[BTREE_MAX_HEIGHT];
} btree_iter_t;

/*
 * Initialize a B-tree instance.
 */
void btree_init(btree_t *tree);

/*
 * Destroy a B-tree and free all internal memory. Does not free the stored
 * values themselves.
 */
void btree_destroy(btree_t *tree);

/*
 * Returns the number of elements in the tree.
 */
size_t btree_size(btree_t *tree);

/*
 * Initializes an iterator to point at the first entry not less than `key`.
 * This means that passing `key = 0` will start the iterator at the first
 * entry.
 */
void btree_iterate(btree_t *tree, uintptr_t key, btree_iter_t *iter);

/*
 * Obtains the value the iterator points at currently, or NULL if the iterator
 * has reached the end of the tree. `key`, if non-NULL, will be updated to the
 * current entry's key.
 */
void *btree_iter_get(btree_iter_t *iter, uintptr_t *key);

/*
 * Advances the iterator. Returns true if successful and false when the
 * iterator has reached the end of the tree.
 */
bool btree_iter_next(btree_iter_t *iter);

/*
 * Insert a value into the tree at the position indicated by the iterator. The
 * inserted key must compare larger or equal than the previous element and less
 * than or equal to the key of the entry at the iterator position. Returns 0 on
 * success, or -1 with errno set. EINVAL indicates the provided key doesn't
 * respect ascending key order with respect to the iterator position. Insertion
 * may have to allocate tree nodes, allocation failures will cause errno to be
 * set to ENOMEM.
 */
int btree_iter_insert(btree_iter_t *iter, uintptr_t key, void *value);

/*
 * Delete the entry the iterator currently points at. The iterator will be
 * updated to point at the following entry (if any). Returns the value that was
 * stored, or NULL if there was no entry to remove.
 */
void *btree_iter_remove(btree_iter_t *iter);

#endif /* LIB_VFIO_USER_BTREE_H */

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
