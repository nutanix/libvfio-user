#
# Copyright (c) 2023 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos@nutanix.com>
#          William Henderson <william.henderson@nutanix.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of Nutanix nor the names of its contributors may be
#        used to endorse or promote products derived from this software without
#        specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
#  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#

from libvfio_user import *
from collections import deque
import ctypes
import errno

ctx = None
sock = None

current_state = None  # the current migration state on the server
path = []  # the server transition path (each transition appends the new state)

read_data = None
write_data = None
callbacks_errno = 0


STATES = {
    VFIO_USER_DEVICE_STATE_STOP,
    VFIO_USER_DEVICE_STATE_RUNNING,
    VFIO_USER_DEVICE_STATE_STOP_COPY,
    VFIO_USER_DEVICE_STATE_RESUMING,
    VFIO_USER_DEVICE_STATE_PRE_COPY
}


UNREACHABLE_STATES = {
    VFIO_USER_DEVICE_STATE_ERROR,
    VFIO_USER_DEVICE_STATE_PRE_COPY_P2P,
    VFIO_USER_DEVICE_STATE_RUNNING_P2P
}


VFU_TO_VFIO_MIGR_STATE = {
    VFU_MIGR_STATE_STOP: VFIO_USER_DEVICE_STATE_STOP,
    VFU_MIGR_STATE_RUNNING: VFIO_USER_DEVICE_STATE_RUNNING,
    VFU_MIGR_STATE_STOP_AND_COPY: VFIO_USER_DEVICE_STATE_STOP_COPY,
    VFU_MIGR_STATE_RESUME: VFIO_USER_DEVICE_STATE_RESUMING,
    VFU_MIGR_STATE_PRE_COPY: VFIO_USER_DEVICE_STATE_PRE_COPY
}


# Set a very small maximum transfer size for later tests.
MAX_DATA_XFER_SIZE = 4


@transition_cb_t
def migr_trans_cb(_ctx, state):
    global current_state, path

    if callbacks_errno != 0:
        set_real_errno(callbacks_errno)
        return -1

    if state in VFU_TO_VFIO_MIGR_STATE:
        state = VFU_TO_VFIO_MIGR_STATE[state]
    else:
        assert False

    current_state = state

    path.append(state)

    return 0


@read_data_cb_t
def migr_read_data_cb(_ctx, buf, count):
    global read_data

    if callbacks_errno != 0:
        set_real_errno(callbacks_errno)
        return -1

    length = min(count, len(read_data))
    ctypes.memmove(buf, read_data, length)
    read_data = None

    return length


@write_data_cb_t
def migr_write_data_cb(_ctx, buf, count):
    global write_data

    if callbacks_errno != 0:
        set_real_errno(callbacks_errno)
        return -1

    write_data = bytes(count)
    ctypes.memmove(write_data, buf, count)

    return count


def setup_fail_callbacks(errno):
    global callbacks_errno
    callbacks_errno = errno


def teardown_fail_callbacks():
    global callbacks_errno
    callbacks_errno = 0
    c.set_errno(0)


def teardown_function(function):
    teardown_fail_callbacks()


def transition_to_migr_state(state, expect=0, rsp=True, busy=False):
    return transition_to_state(ctx, sock, state, expect, rsp, busy)


def mig_data_payload(data):
    argsz = len(vfio_user_mig_data()) + len(data)
    return vfio_user_mig_data(
        argsz=argsz,
        size=len(data)
    )


def test_migration_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    cbs = vfu_migration_callbacks_t()
    cbs.version = 1  # old callbacks version
    cbs.transition = migr_trans_cb
    cbs.read_data = migr_read_data_cb
    cbs.write_data = migr_write_data_cb

    ret = vfu_setup_device_migration_callbacks(ctx, cbs)
    assert ret < 0, "do not allow old callbacks version"

    cbs.version = VFU_MIGR_CALLBACKS_VERS  # new callbacks version
    ret = vfu_setup_device_migration_callbacks(ctx, cbs)
    assert ret == 0

    vfu_setup_device_quiesce_cb(ctx)

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx, MAX_DATA_XFER_SIZE)


def server_transition_track_path(a, b, expectA=0, expectB=0):
    """
    Carry out the state transition from a to b on the server, keeping track of
    and returning the transition path taken.
    """

    global path

    if current_state == VFIO_USER_DEVICE_STATE_STOP_COPY and \
            a == VFIO_USER_DEVICE_STATE_PRE_COPY:
        # The transition STOP_COPY -> PRE_COPY is explicitly blocked so we
        # advance one state to get around this in order to set up the test.
        transition_to_migr_state(VFIO_USER_DEVICE_STATE_STOP)

    transition_to_migr_state(a, expect=expectA)

    if expectA != 0:
        return None

    path = []

    transition_to_migr_state(b, expect=expectB)

    return path.copy()


def test_migration_shortest_state_transition_paths():
    """
    The spec dictates that complex state transitions are to be implemented as
    combinations of the defined direct transitions, with the path selected
    according to the following rules:

    - Select the shortest path.
    - The path cannot have saving group states as interior arcs, only start/end
      states.

    This test implements a breadth-first search to ensure that the paths taken
    by the implementation correctly follow these rules.
    """

    # allowed direct transitions (edges)
    E = {
        VFIO_USER_DEVICE_STATE_ERROR: set(),
        VFIO_USER_DEVICE_STATE_STOP: {
            VFIO_USER_DEVICE_STATE_RUNNING,
            VFIO_USER_DEVICE_STATE_STOP_COPY,
            VFIO_USER_DEVICE_STATE_RESUMING
        },
        VFIO_USER_DEVICE_STATE_RUNNING: {
            VFIO_USER_DEVICE_STATE_STOP,
            VFIO_USER_DEVICE_STATE_PRE_COPY
        },
        VFIO_USER_DEVICE_STATE_STOP_COPY: {VFIO_USER_DEVICE_STATE_STOP},
        VFIO_USER_DEVICE_STATE_RESUMING: {VFIO_USER_DEVICE_STATE_STOP},
        VFIO_USER_DEVICE_STATE_RUNNING_P2P: set(),
        VFIO_USER_DEVICE_STATE_PRE_COPY: {
            VFIO_USER_DEVICE_STATE_RUNNING,
            VFIO_USER_DEVICE_STATE_STOP_COPY
        },
        VFIO_USER_DEVICE_STATE_PRE_COPY_P2P: set()
    }

    # states (vertices)
    V = E.keys()

    # "saving states" which cannot be internal arcs
    saving_states = {VFIO_USER_DEVICE_STATE_PRE_COPY,
                     VFIO_USER_DEVICE_STATE_STOP_COPY}

    # Consider each vertex in turn to be the start state, that is, the state
    # we are transitioning from.
    for source in V:
        # The previous node in the shortest path for each node, e.g. for
        # shortest path `source -> node -> target`, `back[node] == source`.
        back = {v: None for v in V}
        queue = deque([(source, None)])

        # Use BFS to calculate the shortest path from the start state to every
        # other state, following the rule that no intermediate states can be
        # saving states.
        while len(queue) > 0:
            (curr, prev) = queue.popleft()
            back[curr] = prev
            for nxt in E[curr]:
                if back[nxt] is None \
                        and (curr == source or curr not in saving_states):
                    queue.append((nxt, curr))

        # Iterate over the states
        for target in V:
            if source == VFIO_USER_DEVICE_STATE_STOP_COPY \
                    and target == VFIO_USER_DEVICE_STATE_PRE_COPY:
                # test for this transition being blocked in a separate test
                continue

            # If BFS found a path to that state, follow the backpointers to
            # calculate the path, and check that it's equal to the path taken
            # by the server.
            if back[target] is not None:
                seq = deque([])
                curr = target
                while curr != source:
                    seq.appendleft(curr)
                    curr = back[curr]

                server_seq = server_transition_track_path(source, target)

                assert len(seq) == len(server_seq)
                assert all(seq[i] == server_seq[i] for i in range(len(seq)))

            # If BFS couldn't find a path to that state, check that the server
            # doesn't allow that transition either.
            else:
                # If the start state is an unreachable state, we won't be able
                # to transition into it in order to try and calculate a path on
                # the server, so we expect that transition to fail.
                expectA = errno.EINVAL if source in UNREACHABLE_STATES else 0

                # No matter what, we expect transitioning to the target state
                # to fail.
                server_transition_track_path(source, target, expectA=expectA,
                                             expectB=errno.EINVAL)


def test_migration_stop_copy_to_pre_copy_rejected():
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_STOP_COPY)
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_PRE_COPY,
                             expect=errno.EINVAL)


def test_migration_nonexistent_state():
    transition_to_migr_state(0xabcd, expect=errno.EINVAL)


def test_migration_failed_callback():
    setup_fail_callbacks(0xbeef)
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RUNNING, expect=0xbeef)
    assert c.get_errno() == 0xbeef
    teardown_fail_callbacks()


def test_migration_get_state():
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RUNNING)

    feature = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
            len(vfio_user_device_feature_mig_state()),
        flags=VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE
    )

    result = msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, feature)
    _, result = vfio_user_device_feature.pop_from_buffer(result)
    state, _ = vfio_user_device_feature_mig_state.pop_from_buffer(result)
    assert state.device_state == VFIO_USER_DEVICE_STATE_RUNNING


def test_handle_mig_data_read():
    global read_data

    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RUNNING)

    data = bytes([0, 1, 2, 3])
    payload = mig_data_payload(data)

    VALID_STATES = {VFIO_USER_DEVICE_STATE_PRE_COPY,
                    VFIO_USER_DEVICE_STATE_STOP_COPY}

    for state in STATES:
        transition_to_migr_state(state)
        read_data = data
        expect = 0 if state in VALID_STATES else errno.EINVAL
        result = msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload,
                     expect=expect)

        if state in VALID_STATES:
            assert len(result) == len(payload) + len(data)
            assert result[len(vfio_user_mig_data()):] == data


def test_handle_mig_data_read_too_long():
    """
    When we set up the tests at the top of this file we specify that the max
    data transfer size is 4 bytes. Here we test to check that a transfer of too
    many bytes fails.
    """

    global read_data

    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RUNNING)
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_PRE_COPY)

    # Create a payload reading with length 1 byte longer than the max.
    read_data = bytes([i for i in range(MAX_DATA_XFER_SIZE + 1)])
    payload = mig_data_payload(read_data)

    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload, expect=errno.EINVAL)


def test_handle_mig_data_read_failed_callback():
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_PRE_COPY)

    read_data = bytes([1, 2, 3, 4])
    payload = mig_data_payload(read_data)

    setup_fail_callbacks(0xbeef)

    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload, expect=0xbeef)
    assert c.get_errno() == 0xbeef


def test_handle_mig_data_read_short_write():
    data = bytes([1, 2, 3, 4])
    payload = bytes(mig_data_payload(data))

    # don't send the last byte
    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload[:-1],
        expect=errno.EINVAL)


def test_handle_mig_data_write():
    data = bytes([1, 2, 3, 4])
    payload = mig_data_payload(data)

    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RESUMING)
    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data)
    assert write_data == data


def test_handle_mig_data_write_invalid_state():
    data = bytes([1, 2, 3, 4])
    payload = mig_data_payload(data)

    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RUNNING)
    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data,
        expect=errno.EINVAL)


def test_handle_mig_data_write_too_long():
    """
    When we set up the tests at the top of this file we specify that the max
    data transfer size is 4 bytes. Here we test to check that a transfer of too
    many bytes fails.
    """

    # Create a payload writing with length 1 byte longer than the max.
    data = bytes([i for i in range(MAX_DATA_XFER_SIZE + 1)])
    payload = mig_data_payload(data)

    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RESUMING)
    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data,
        expect=errno.EINVAL)


def test_handle_mig_data_write_failed_callback():
    transition_to_migr_state(VFIO_USER_DEVICE_STATE_RESUMING)

    data = bytes([1, 2, 3, 4])
    payload = mig_data_payload(data)

    setup_fail_callbacks(0xbeef)

    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data,
        expect=0xbeef)
    assert c.get_errno() == 0xbeef


def test_handle_mig_data_write_short_write():
    data = bytes([1, 2, 3, 4])
    payload = mig_data_payload(data)

    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, payload, expect=errno.EINVAL)


def test_device_feature_migration_get():
    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
              len(vfio_user_device_feature_migration()),
        flags=VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION
    )

    result = msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload)
    _, result = vfio_user_device_feature.pop_from_buffer(result)
    flags, _ = vfio_user_device_feature_migration.pop_from_buffer(result)
    flags = flags.flags

    assert flags == VFIO_MIGRATION_STOP_COPY | VFIO_MIGRATION_PRE_COPY


def test_device_feature_short_write():
    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
              len(vfio_user_device_feature_migration()),
        flags=VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION
    )

    payload = bytes(payload)

    # don't send the last byte
    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload[:-1],
        expect=errno.EINVAL)


def test_device_feature_unsupported_operation():
    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
              len(vfio_user_device_feature_migration()),
        flags=VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_MIGRATION
    )

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=errno.EINVAL)


def test_device_feature_bad_argsz_probe():
    payload = vfio_user_device_feature(
        argsz=2,
        flags=VFIO_DEVICE_FEATURE_PROBE | VFIO_DEVICE_FEATURE_MIGRATION
    )

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=errno.EINVAL)


def test_device_feature_bad_argsz_get_migration():
    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()),
        flags=VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION
    )

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=errno.EINVAL)


def test_device_feature_bad_argsz_get_dma():
    argsz = len(vfio_user_device_feature()) + \
            len(vfio_user_device_feature_dma_logging_report()) + \
            get_bitmap_size(0x20 << PAGE_SHIFT, PAGE_SIZE)

    feature = vfio_user_device_feature(
        argsz=argsz - 1,  # not big enough
        flags=VFIO_DEVICE_FEATURE_DMA_LOGGING_REPORT | VFIO_DEVICE_FEATURE_GET
    )

    report = vfio_user_device_feature_dma_logging_report(
        iova=0x10 << PAGE_SHIFT,
        length=0x20 << PAGE_SHIFT,
        page_size=PAGE_SIZE
    )

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, bytes(feature) + bytes(report),
        expect=errno.EINVAL)


def test_device_feature_bad_argsz_set():
    feature = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()),  # no space for state data
        flags=VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE
    )
    payload = vfio_user_device_feature_mig_state(
        device_state=VFIO_USER_DEVICE_STATE_RUNNING
    )
    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, bytes(feature) + bytes(payload),
        expect=errno.EINVAL)


def test_device_feature_probe():
    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()),
        flags=VFIO_DEVICE_FEATURE_PROBE | VFIO_DEVICE_FEATURE_MIGRATION
    )

    result = msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload)
    assert bytes(payload) == result

    payload = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()),
        flags=VFIO_DEVICE_FEATURE_PROBE | VFIO_DEVICE_FEATURE_SET |
              VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION
    )

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=errno.EINVAL)


def test_migration_cleanup():
    disconnect_client(ctx, sock)
    vfu_destroy_ctx(ctx)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: #
