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
 * A libfuzzer based test to exercise the B-Tree implementation. The idea is to
 * create a test tree and maintain an iterator on it as the code under test.
 * The test holds redundant bookkeeping data to track tree and iterator state.
 * Then, the fuzzer performs arbitrary operations on the tree, and we check
 * whether predicted behavior (based on the bookkeeping data) matches actual
 * behavior exhibited by the tree iterator.
 */

#undef NDEBUG /* so assert() works in release builds */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "btree.h"

enum fuzz_action {
    FUZZ_ACTION_SEEK,
    FUZZ_ACTION_NEXT,
    FUZZ_ACTION_GET,
    FUZZ_ACTION_INSERT,
    FUZZ_ACTION_REMOVE,
    FUZZ_ACTION_MULTIPLY,
};

/*
 * Instead of storing actual pointers in the tree, the test uses fake values
 * generated from the corresponding key by this macro.
 */
#define to_value(v) ((void *)(uintptr_t)((v) | 0x800))

/*
 * The test keeps track of what entries have been inserted into the tree, and
 * what the current iterator position is. In order to limit memory usage, the
 * key range is limited to 2^8 values, represented by an uint8_t. However, we
 * allow 2^16 copies of a single key to be inserted, to still allow the fuzzer
 * to create large trees.
 *
 * The current iterator position is encoded as `(key << 16) | index`, where
 * `index` indicates which copy of `key` we're at. The iterator can also point
 * beyond the last element, in which case `key == 256`.
 */
#define iter_pos(key, index) ((key) << 16 | (index) & 0xffff)
#define iter_pos_key(pos) ((pos) >> 16)
#define iter_pos_index(pos) ((pos) & 0xffff)

/*
 * Finds the next valid tree position, given the tree population state given in
 * `count`.
 */
static uint32_t next(uint16_t count[256], uint32_t pos)
{
    if (iter_pos_key(pos) >= 256) {
        return 256 << 16;
    }

    for (; iter_pos_key(pos) < 256;
         pos = iter_pos((iter_pos_key(pos) + 1), 0)) {
        if (iter_pos_index(pos) < count[iter_pos_key(pos)]) {
            return pos;
        }
    }

    return pos;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    btree_t tree;
    btree_init(&tree);

    btree_iter_t iter;
    btree_iterate(&tree, 0, &iter);

    /* Tracks how many copies of each uint8_t value are present. */
    uint16_t count[256] = { 0 };

    /* The iterator for the empty tree points beyond the last entry. */
    uint32_t pos = iter_pos(256, 0);

    for (; size >= 2; size -= 2) {
        enum fuzz_action action = (enum fuzz_action) * data++;
        uint8_t param = *data++;

        switch (action) {
        case FUZZ_ACTION_SEEK: {
            /* Reposition the iterator. */
            btree_iterate(&tree, param, &iter);
            pos = next(count, iter_pos(param, 0));
            break;
        }
        case FUZZ_ACTION_NEXT: {
            /* Advance the iterator. */
            bool has_next = btree_iter_next(&iter);
            assert(has_next == (iter_pos_key(pos) < 256));
            pos = next(count, pos + 1);
            break;
        }
        case FUZZ_ACTION_GET: {
            /* Get the current entry. */
            uintptr_t key = ~0;
            void *val = btree_iter_get(&iter, &key);
            if (iter_pos_key(pos) < 256) {
                assert(val == to_value(iter_pos_key(pos)));
                assert(key == (uintptr_t)iter_pos_key(pos));
            } else {
                assert(val == NULL);
                assert(key == (uintptr_t)~0);
            }
            break;
        }
        case FUZZ_ACTION_INSERT: {
            /* Insert an entry. */
            if (count[param] >= UINT16_MAX) {
                /* Ignore the action if it would overflow the counter. */
                break;
            }
            bool valid =
                param == iter_pos_key(pos) ||
                (param < iter_pos_key(pos) && iter_pos_index(pos) == 0);
            for (uint32_t i = param + 1; valid && i < iter_pos_key(pos); ++i) {
                valid &= count[i] == 0;
            }
            int ret = btree_iter_insert(&iter, param, to_value(param));
            assert((ret == 0) == valid);
            if (valid) {
                if (param < iter_pos_key(pos)) {
                    pos = iter_pos(param, count[param]);
                }
                ++count[param];
            }
            break;
        }
        case FUZZ_ACTION_REMOVE: {
            /* Remove the current entry. */
            void *value = btree_iter_remove(&iter);
            int key = iter_pos_key(pos);
            if (key < 256) {
                assert(value == to_value(key));
                assert(count[key] > 0);
                --count[key];
            } else {
                assert(value == NULL);
            }
            pos = next(count, pos);
            break;
        }
        case FUZZ_ACTION_MULTIPLY: {
            /* Insert copies of the current entry. */
            int key = iter_pos_key(pos);
            if (key >= 256) {
                /* Can't make copies if we're at the end. */
                break;
            }
            int copies = (1 << (param > 16 ? 16: param));
            if (count[key] + copies > UINT16_MAX) {
                /* Ignore the action if it would overflow the counter. */
                break;
            }
            while (copies-- > 0) {
                int ret = btree_iter_insert(&iter, key, to_value(key));
                assert(ret == 0);
                ++count[key];
            }
            break;
        }
        default:
            break;
        }
    }

    btree_destroy(&tree);

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
