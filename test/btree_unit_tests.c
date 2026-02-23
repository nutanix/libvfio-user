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
#include <stdlib.h>

#include "btree.h"
#include "common.h"

static void insert_value(btree_t *tree, uintptr_t value)
{
    btree_iter_t iter;
    btree_iterate(tree, value, &iter);
    assert(btree_iter_insert(&iter, value, (void *)(value + 1)) == 0);
}

static void test_empty()
{
    btree_t tree;
    btree_init(&tree);

    btree_iter_t iter;
    btree_iterate(&tree, 0, &iter);

    assert(btree_iter_get(&iter, NULL) == NULL);
    uintptr_t key;
    assert(btree_iter_get(&iter, &key) == NULL);

    assert(!btree_iter_next(&iter));

    btree_destroy(&tree);
}

static void test_insert_front()
{
    btree_t tree;
    btree_init(&tree);

    btree_iter_t iter;
    btree_iterate(&tree, 0, &iter);

    const uintptr_t N = 100000;
    for (uintptr_t i = N; i > 0; --i) {
        assert(btree_iter_insert(&iter, i, (void *)i) == 0);
    }

    uintptr_t expectation = 1;
    uintptr_t key = -1;
    void *value;
    for (btree_iterate(&tree, 0, &iter);
         (value = btree_iter_get(&iter, &key)) != NULL;
         btree_iter_next(&iter)) {
        assert(key == expectation);
        assert((uintptr_t)value == expectation);
        ++expectation;
    }
    assert(expectation == N + 1);

    assert(!btree_iter_next(&iter));

    btree_destroy(&tree);
}

static void test_insert_randomized()
{
    btree_t tree;
    btree_init(&tree);

    /* The size of the array should be prime so we hit all entries. */
    bool present[4019] = { false };
    const uintptr_t MOD = ARRAY_SIZE(present);
    const int STEP = 34567;
    uintptr_t n = 0;
    for (uintptr_t i = 0; i < MOD; ++i) {
        /* Insert an element. */
        insert_value(&tree, n);
        present[n] = true;
        n = (n + STEP) % MOD;

        /* Iterate the tree and verify the inserted elements are present. */
        int pos = 0;
        uintptr_t key = -1;
        void *value;
        btree_iter_t iter;
        for (btree_iterate(&tree, 0, &iter);
             (value = btree_iter_get(&iter, &key)) != NULL;
             btree_iter_next(&iter)) {
            for (uintptr_t p = pos; p < key; ++p) {
                assert(!present[p]);
            }
            assert(present[key]);
            pos = key + 1;
        }
        for (uintptr_t p = pos; p < MOD; ++p) {
            assert(!present[p]);
        }
    }

    btree_destroy(&tree);
}

static void test_remove_front()
{
    btree_t tree;
    btree_init(&tree);

    insert_value(&tree, 1);
    insert_value(&tree, 2);

    btree_iter_t iter;
    btree_iterate(&tree, 0, &iter);
    btree_iter_remove(&iter);

    btree_iterate(&tree, 0, &iter);
    assert(btree_iter_get(&iter, NULL) == (void *)3);

    btree_iter_remove(&iter);
    assert(btree_iter_get(&iter, NULL) == NULL);

    btree_iter_remove(&iter);
    assert(btree_iter_get(&iter, NULL) == NULL);

    btree_destroy(&tree);
}

static void test_remove_randomized()
{
    btree_t tree;
    btree_init(&tree);

    bool present[4019] = { false };
    const uintptr_t MOD = ARRAY_SIZE(present);
    for (uintptr_t i = 0; i < MOD; ++i) {
        insert_value(&tree, i);
        present[i] = true;
    }

    const int STEP = 34567;
    uintptr_t n = 0;
    for (uintptr_t i = 0; i < MOD; ++i) {
        /* Remove an element. */
        btree_iter_t iter;
        btree_iterate(&tree, n, &iter);
        btree_iter_remove(&iter);
        present[n] = false;

        uintptr_t next = 0;
        if (btree_iter_get(&iter, &next) != NULL) {
            assert(next > n);
            assert(present[next]);
        } else {
            next = MOD;
        }

        for (uintptr_t k = n + 1; k < next; ++k) {
            assert(!present[k]);
        }

        n = (n + STEP) % MOD;
    }

    btree_destroy(&tree);
}

int main(void)
{
    test_empty();
    test_insert_front();
    test_insert_randomized();
    test_remove_front();
    test_remove_randomized();

    return 0;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
