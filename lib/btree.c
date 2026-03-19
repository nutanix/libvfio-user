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
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "btree.h"
#include "common.h"

/*
 * The allocation size for nodes. This parameter determines fan-out and thus
 * balances cost of scanning a node vs. allocation overhead tree height.
 */
#define BTREE_NODE_SIZE 4096

/*
 * Number of entries within a node. This calculates the number of entries based
 * on allocation size and node contents, filling the space not occupied by
 * fixed-size items with array entries.
 */
#define BTREE_NODE_NUM_ENTRIES                                            \
    ((BTREE_NODE_SIZE - (sizeof(size_t) + sizeof(struct btree_node *))) / \
     (sizeof(uintptr_t) + sizeof(void *) + sizeof(struct btree_node *)))

/*
 * Node alignment. Chosen such that there are enough unused low-order bits to
 * hold the node index in a cursor.
 */
#define BTREE_NODE_ALIGNMENT NEXT_POWER_OF_2(BTREE_NODE_NUM_ENTRIES)

/*
 * Cursor mask, used for extracting the pointer and index fields from a cursor
 * value.
 */
#define BTREE_NODE_CURSOR_MASK (BTREE_NODE_ALIGNMENT - 1)

/*
 * Minimum occupancy count of a node. This is used for making rebalancing
 * decisions. Note that the root node is an exception and may hold any number
 * of entries.
 */
#define BTREE_MIN_DEGREE (BTREE_NODE_NUM_ENTRIES / 2)

/* Helpers for invoking memcpy/memmove on node entry arrays. */
#define btree_move_array_entries(array, from, to, count) \
    memmove(&(array)[(to)], &(array)[(from)], (count) * sizeof((array)[0]))
#define btree_copy_array_entries(from, to, count) \
    memcpy((to), (from), (count) * sizeof((from)[0]))

/* Represents a tree node. */
struct btree_node {
    /* Number of valid entries in the arrays below (children has count + 1). */
    size_t count;

    /*
     * Numeric entry keys used as ordering criterion. These are stored directly
     * in the node rather than obtained from the corresponding value to make
     * sure tree traversal only needs to access node memory.
     */
    uintptr_t keys[BTREE_NODE_NUM_ENTRIES];

    /*
     * Tree data payload, entirely opaque to the code here. It is OK to store
     * NULL pointers, although that might make it harder for the caller to
     * distinguish present-but-NULL from absent entries.
     */
    void *values[BTREE_NODE_NUM_ENTRIES];

    /*
     * Child node pointers. These are conceptually on each side of a node's
     * entry, hence we number of children of a node is one more than its
     * entries. The subtree at the child left to an entry contains keys that
     * are less than or equal to the entry, the right subtree contains larger
     * or equal entries.
     */
    struct btree_node *children[BTREE_NODE_NUM_ENTRIES + 1];
};

_Static_assert(sizeof(struct btree_node) <= BTREE_NODE_SIZE,
               "btree node size exceeds allocation size");
_Static_assert(BTREE_NODE_SIZE % BTREE_NODE_ALIGNMENT == 0,
               "allocation size must be a multiple of alignment");

/* Make a cursor from a node pointer and entry index. */
static inline btree_cursor_t btree_cursor(struct btree_node *node, size_t pos)
{
    uintptr_t ptr = (uintptr_t)node;

    assert((ptr & BTREE_NODE_CURSOR_MASK) == 0);
    assert((pos & ~BTREE_NODE_CURSOR_MASK) == 0);

    return ptr | pos;
}

/* Extract the node pointer from a cursor value. */
static inline struct btree_node *
btree_cursor_node(btree_iter_t *iter, int level)
{
    return (struct btree_node *)(iter->cursors[level] &
                                 ~BTREE_NODE_CURSOR_MASK);
}

/* Extract the entry index from a cursor value. */
static inline size_t btree_cursor_pos(btree_iter_t *iter, int level)
{
    return iter->cursors[level] & BTREE_NODE_CURSOR_MASK;
}

/*
 * Allocate a new node with the correct alignment so we have enough low-order
 * bits to use for index storage.
 */
static struct btree_node *node_alloc(void)
{
    void *node = NULL;
    if (posix_memalign(&node, BTREE_NODE_ALIGNMENT, BTREE_NODE_SIZE) != 0) {
        return NULL;
    }

    memset(node, 0, sizeof(struct btree_node));

    return node;
}

/*
 * Recursively free a node and all its descendants.
 */
static void node_destroy_recursive(struct btree_node *node, int height)
{
    if (height == 0) {
        return;
    }

    for (size_t i = 0; i <= node->count; ++i) {
        node_destroy_recursive(node->children[i], height - 1);
    }

    free(node);
}

void btree_init(btree_t *tree)
{
    assert(tree != NULL);

    tree->root = NULL;
    tree->size = 0;
    tree->height = 0;
}

void btree_destroy(btree_t *tree)
{
    assert(tree != NULL);

    node_destroy_recursive(tree->root, tree->height);
    btree_init(tree);
}

size_t btree_size(btree_t *tree)
{
    assert(tree != NULL);

    return tree->size;
}

void btree_iterate(btree_t *tree, uintptr_t key, btree_iter_t *iter)
{
    iter->tree = tree;

    /*
     * Build the cursor stack starting at the root, working towards the leaf
     * and filling in cursors for each level.
     */
    struct btree_node *node = tree->root;
    for (int level = iter->tree->height - 1; level >= 0; --level) {
        /* Find the position within the current node. */
        size_t pos;
        for (pos = 0; pos < node->count; pos++) {
            if (node->keys[pos] >= key) {
                break;
            }
        }

        assert(pos <= BTREE_NODE_NUM_ENTRIES);

        iter->cursors[level] = btree_cursor(node, pos);

        node = node->children[pos];
    }
}

/*
 * Helper function to find the level of the element that is on the right side
 * of the iterator cut. Returns the level, or the tree height if we're at the
 * right end of the tree and no right side element exists.
 */
static inline int btree_iter_right_side_level(btree_iter_t *iter)
{
    int level;

    for (level = 0; level < iter->tree->height; ++level) {
        struct btree_node *node = btree_cursor_node(iter, level);
        size_t pos = btree_cursor_pos(iter, level);
        if (pos < node->count) {
            break;
        }
    }

    return level;
}

void *btree_iter_get(btree_iter_t *iter, uintptr_t *key)
{
    int level = btree_iter_right_side_level(iter);
    if (level >= iter->tree->height) {
        return NULL;
    }

    struct btree_node *node = btree_cursor_node(iter, level);
    size_t pos = btree_cursor_pos(iter, level);

    if (key != NULL) {
        *key = node->keys[pos];
    }

    return node->values[pos];
}

void *btree_iter_next(btree_iter_t *iter)
{
    int level = btree_iter_right_side_level(iter);
    if (level >= iter->tree->height) {
        return NULL;
    }

    /*
     * Skip across the right element. We are sure it exists, otherwise we would
     * have bailed above.
     */
    ++iter->cursors[level];

    struct btree_node *node = btree_cursor_node(iter, level);
    size_t pos = btree_cursor_pos(iter, level);

    /*
     * Rebuild the cursor levels towards the leaf level: We're at the left edge
     * of the subtree between the entries in the level we advanced.
     */
    for (node = node->children[pos]; --level >= 0; node = node->children[0]) {
        iter->cursors[level] = btree_cursor(node, 0);
    }

    return btree_iter_get(iter, NULL);
}

/*
 * Insert a new entry into the given node. The caller must make sure there is
 * capacity, and that the insertion maintains proper key order.
 */
static void
btree_node_insert_entry(struct btree_node *node, size_t pos, uintptr_t key,
                        void *value, struct btree_node *left_child,
                        struct btree_node *right_child)
{
    assert(pos <= node->count);

    /* There must be available space in the given node. */
    assert(node->count < BTREE_NODE_NUM_ENTRIES);

    /* Callers must make sure to maintain key order. */
    assert(pos == node->count || node->keys[pos] >= key);
    assert(pos == 0 || node->keys[pos - 1] <= key);

    /* Shift existing entries right to make room for the new entry. */
    int count = node->count - pos;

    btree_move_array_entries(node->keys, pos, pos + 1, count);
    btree_move_array_entries(node->values, pos, pos + 1, count);
    btree_move_array_entries(node->children, pos + 1, pos + 2, count);

    /* Put the new entry in place. */
    node->keys[pos] = key;
    node->values[pos] = value;
    node->children[pos] = left_child;
    node->children[pos + 1] = right_child;

    ++node->count;
}

int btree_iter_insert(btree_iter_t *iter, uintptr_t key, void *value)
{
    /* Lazy initialization of empty tree. */
    if (iter->tree->height == 0) {
        struct btree_node *root = node_alloc();
        if (root == NULL) {
            errno = ENOMEM;
            return -1;
        }

        root->count = 1;
        root->keys[0] = key;
        root->values[0] = value;

        assert(iter->tree->root == NULL);
        iter->tree->root = root;
        iter->cursors[0] = btree_cursor(root, 0);
        iter->tree->size = 1;
        iter->tree->height = 1;

        return 0;
    }

    /*
     * We traverse the tree from the top along the path given by the iterator.
     * Along the way, we proactively split nodes that are at capacity. This
     * guarantees that we can insert another element if we need to push one up
     * from the next level we will visit.
     *
     * While proactive splitting might do more work than necessary, it
     * simplifies the implementation: Tree structure remains consistent at all
     * times, so we can just bail when hitting errors without having to repair
     * the tree in the error path.
     */
    for (int level = iter->tree->height - 1; level >= 0; --level) {
        struct btree_node *node = btree_cursor_node(iter, level);
        size_t pos = btree_cursor_pos(iter, level);

        /* Reject insertion attempts that violate key order. */
        if ((pos < node->count && key > node->keys[pos]) ||
            (pos > 0 && key < node->keys[pos - 1])) {
            errno = EINVAL;
            return -1;
        }

        /* Proactively split the node if it is full. */
        if (node->count == BTREE_NODE_NUM_ENTRIES) {
            /* Allocate a right sibling to insert */
            struct btree_node *right = node_alloc();
            if (right == NULL) {
                errno = ENOMEM;
                return -1;
            }

            /* If necessary, allocate a new root. */
            if (level == iter->tree->height - 1) {
                if (iter->tree->height >= BTREE_MAX_HEIGHT) {
                    free(right);
                    errno = EOVERFLOW;
                    return -1;
                }
                struct btree_node *root = node_alloc();
                if (root == NULL) {
                    free(right);
                    errno = ENOMEM;
                    return -1;
                }
                root->count = 0; /* insertion will bump it */
                root->children[0] = node;
                iter->cursors[level + 1] = btree_cursor(root, 0);
                iter->tree->root = root;
                ++iter->tree->height;
            }

            size_t split = BTREE_NODE_NUM_ENTRIES / 2;
            size_t count = BTREE_NODE_NUM_ENTRIES - split;
            btree_copy_array_entries(&node->keys[split + 1], &right->keys[0],
                                     count - 1);
            btree_copy_array_entries(&node->values[split + 1],
                                     &right->values[0], count - 1);
            btree_copy_array_entries(&node->children[split + 1],
                                     &right->children[0], count);
            right->count = count - 1;

            uintptr_t median_key = node->keys[split];
            void *median_value = node->values[split];

            node->count = split;

            /* Push the median element to the parent level. */
            btree_node_insert_entry(btree_cursor_node(iter, level + 1),
                                    btree_cursor_pos(iter, level + 1),
                                    median_key, median_value, node, right);

            /* Update the iterator cursor stack. */
            iter->cursors[level] = pos <= split ?
                                       btree_cursor(node, pos) :
                                       btree_cursor(right, pos - split - 1);
            iter->cursors[level + 1] += pos <= split ? 0 : 1;
        }
    }

    /* Insert the new element. */
    btree_node_insert_entry(btree_cursor_node(iter, 0),
                            btree_cursor_pos(iter, 0), key, value, NULL, NULL);
    ++iter->tree->size;

    return 0;
}

/*
 * Remove the entry at the given position in a node. Entries to the right will
 * be shifted one position to the left to close the gap.
 */
static void btree_node_remove_entry(struct btree_node *node, size_t pos)
{
    assert(pos < node->count);
    --node->count;

    size_t count = node->count - pos;
    btree_move_array_entries(node->keys, pos + 1, pos, count);
    btree_move_array_entries(node->values, pos + 1, pos, count);
    btree_move_array_entries(node->children, pos + 2, pos + 1, count);
}

void *btree_iter_remove(btree_iter_t *iter)
{
    bool advance_iter = false;

    int level = btree_iter_right_side_level(iter);
    if (level >= iter->tree->height) {
        /* The iterator has reached the end, there is nothing to remove. */
        return NULL;
    }

    struct btree_node *node = btree_cursor_node(iter, level);
    size_t pos = btree_cursor_pos(iter, level);
    void *value = node->values[pos];
    if (level > 0) {
        /*
         * Inner node: Grab the left subtree's largest entry to use as a new
         * separator.
         */
        struct btree_node *left_leaf_node = btree_cursor_node(iter, 0);

        assert(left_leaf_node->count > 0);
        --left_leaf_node->count;
        node->keys[pos] = left_leaf_node->keys[left_leaf_node->count];
        node->values[pos] = left_leaf_node->values[left_leaf_node->count];

        assert(btree_cursor_pos(iter, 0) > 0);
        --iter->cursors[0];

        /*
         * We have moved the new separator element to the other side of the
         * iterator position, so the iterator must be advanced to maintain its
         * position. We can't do that here though because the cursor stack is
         * still needed for rebalancing, so we take a note to advance the
         * iterator later.
         */
        advance_iter = true;
    } else {
        /* Leaf node: just remove the entry. */
        btree_node_remove_entry(node, pos);
    }
    --iter->tree->size;

    /* Fix deficient nodes, working from the leaf level towards the root. */
    for (level = 0; level < iter->tree->height - 1; ++level) {
        struct btree_node *parent = btree_cursor_node(iter, level + 1);
        pos = btree_cursor_pos(iter, level + 1);
        node = btree_cursor_node(iter, level);

        if (node->count >= BTREE_MIN_DEGREE) {
            /*
             * The node we're looking at has enough entries. This means we're
             * done, since nodes further towards the top haven't been changed.
             */
            break;
        }

        /* Try rotating in an element from the left sibling. */
        if (pos > 0) {
            struct btree_node *left_sibling = parent->children[pos - 1];
            size_t left_count = left_sibling->count;

            if (left_count > BTREE_MIN_DEGREE) {
                btree_node_insert_entry(
                    node, 0, parent->keys[pos - 1], parent->values[pos - 1],
                    left_sibling->children[left_count], node->children[0]);

                parent->keys[pos - 1] = left_sibling->keys[left_count - 1];
                parent->values[pos - 1] = left_sibling->values[left_count - 1];

                --left_sibling->count;

                /*
                 * We shifted the node's entries right by one, so adjust the
                 * iterator's cursors for the current level.
                 */
                ++iter->cursors[level];

                break;
            }
        }

        /* Try rotating in an element from the right sibling. */
        if (pos < parent->count) {
            struct btree_node *right_sibling = parent->children[pos + 1];

            if (right_sibling->count > BTREE_MIN_DEGREE) {
                node->keys[node->count] = parent->keys[pos];
                node->values[node->count] = parent->values[pos];
                node->children[node->count + 1] = right_sibling->children[0];
                ++node->count;

                parent->keys[pos] = right_sibling->keys[0];
                parent->values[pos] = right_sibling->values[0];

                right_sibling->children[0] = right_sibling->children[1];
                btree_node_remove_entry(right_sibling, 0);

                /*
                 * Iterator state is good as is since we changed tree structure
                 * only on the right of the iterator position.
                 */

                break;
            }
        }

        /* Rotation didn't work, merge nodes. */
        size_t merge_pos = pos > 0 ? pos - 1 : pos;
        struct btree_node *left = parent->children[merge_pos];
        struct btree_node *right = parent->children[merge_pos + 1];

        left->keys[left->count] = parent->keys[merge_pos];
        left->values[left->count] = parent->values[merge_pos];
        ++left->count;

        size_t right_pos_shift = left->count;

        size_t right_count = right->count;
        btree_copy_array_entries(&right->keys[0], &left->keys[left->count],
                                 right_count);
        btree_copy_array_entries(&right->values[0], &left->values[left->count],
                                 right_count);
        btree_copy_array_entries(&right->children[0],
                                 &left->children[left->count], right_count + 1);
        left->count += right_count;
        assert(left->count <= BTREE_NODE_NUM_ENTRIES);

        btree_node_remove_entry(parent, merge_pos);

        if (node == right) {
            /*
             * Update iterator state if changes happened left to its position:
             *  - The separator element between left and right in the parent
             *    node has been removed: parent cursor position needs to be
             *    decremented by one.
             *  - The elements in the right node have been moved to the left
             *    node: Update cursor with new node pointer and shifted index.
             */
            --iter->cursors[level + 1];
            iter->cursors[level] = btree_cursor(
                left, btree_cursor_pos(iter, level) + right_pos_shift);
        }

        free(right);
    }

    /* Remove the root node in case it has become empty. */
    if (iter->tree->root->count == 0) {
        int height = --iter->tree->height;
        free(iter->tree->root);
        iter->tree->root =
            height > 0 ? btree_cursor_node(iter, height - 1) : NULL;
    }

    if (advance_iter) {
        btree_iter_next(iter);
    }

    return value;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
