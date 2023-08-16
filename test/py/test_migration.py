#
# Copyright (c) 2023 Nutanix Inc. All rights reserved.
#
# Authors: William Henderson <william.henderson@nutanix.com>
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
current_state = None
path = []
read_data = None
write_data = None


UNREACHABLE_STATES = {
    VFIO_USER_DEVICE_STATE_ERROR,
    VFIO_USER_DEVICE_STATE_PRE_COPY_P2P,
    VFIO_USER_DEVICE_STATE_RUNNING_P2P
}


@transition_cb_t
def migr_trans_cb(_ctx, state):
    global current_state, path

    if state == VFU_MIGR_STATE_STOP:
        state = VFIO_USER_DEVICE_STATE_STOP
    elif state == VFU_MIGR_STATE_RUNNING:
        state = VFIO_USER_DEVICE_STATE_RUNNING
    elif state == VFU_MIGR_STATE_STOP_AND_COPY:
        state = VFIO_USER_DEVICE_STATE_STOP_COPY
    elif state == VFU_MIGR_STATE_RESUME:
        state = VFIO_USER_DEVICE_STATE_RESUMING
    elif state == VFU_MIGR_STATE_PRE_COPY:
        state = VFIO_USER_DEVICE_STATE_PRE_COPY
    else:
        assert False

    current_state = state

    path.append(state)

    return 0


@read_data_cb_t
def migr_read_data_cb(_ctx, buf, count):
    global read_data
    length = min(count, len(read_data))
    ctypes.memmove(buf, read_data, length)
    read_data = None
    return length


@write_data_cb_t
def migr_write_data_cb(_ctx, buf, count):
    global write_data
    write_data = bytes(count)
    ctypes.memmove(write_data, buf, count)
    return count


def transition_to_state(state, expect=0):
    feature = vfio_user_device_feature(
        argsz=len(vfio_user_device_feature()) +
            len(vfio_user_device_feature_mig_state()),
        flags=VFIO_DEVICE_FEATURE_SET | VFIO_DEVICE_FEATURE_MIG_DEVICE_STATE
    )
    payload = vfio_user_device_feature_mig_state(device_state=state)
    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, bytes(feature) + bytes(payload),
        expect=expect)


def test_migration_setup():
    global ctx, sock

    ctx = vfu_create_ctx(flags=LIBVFIO_USER_FLAG_ATTACH_NB)
    assert ctx is not None

    cbs = vfu_migration_callbacks_t()
    cbs.version = VFU_MIGR_CALLBACKS_VERS
    cbs.transition = migr_trans_cb
    cbs.read_data = migr_read_data_cb
    cbs.write_data = migr_write_data_cb

    ret = vfu_setup_device_migration_callbacks(ctx, cbs)
    assert ret == 0

    vfu_setup_device_quiesce_cb(ctx)

    ret = vfu_realize_ctx(ctx)
    assert ret == 0

    sock = connect_client(ctx, 4)


def get_server_shortest_path(a, b, expectA=0, expectB=0):
    global path

    if current_state == VFIO_USER_DEVICE_STATE_STOP_COPY and \
            a == VFIO_USER_DEVICE_STATE_PRE_COPY:
        # The transition STOP_COPY -> PRE_COPY is explicitly blocked so we
        # advance one state to get around this in order to set up the test.
        transition_to_state(VFIO_USER_DEVICE_STATE_STOP)

    transition_to_state(a, expect=expectA)

    if expectA != 0:
        return None

    path = []

    transition_to_state(b, expect=expectB)

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

    # states (vertices)
    V = {VFIO_USER_DEVICE_STATE_ERROR, VFIO_USER_DEVICE_STATE_STOP,
         VFIO_USER_DEVICE_STATE_RUNNING, VFIO_USER_DEVICE_STATE_STOP_COPY,
         VFIO_USER_DEVICE_STATE_RESUMING, VFIO_USER_DEVICE_STATE_RUNNING_P2P,
         VFIO_USER_DEVICE_STATE_PRE_COPY, VFIO_USER_DEVICE_STATE_PRE_COPY_P2P}

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

    # "saving states" which cannot be internal arcs
    S = {VFIO_USER_DEVICE_STATE_PRE_COPY, VFIO_USER_DEVICE_STATE_STOP_COPY}

    for source in V:
        back = {v: None for v in V}
        queue = deque([(source, None)])

        while len(queue) > 0:
            (curr, prev) = queue.popleft()
            back[curr] = prev
            for nxt in E[curr]:
                if back[nxt] is None and (curr == source or curr not in S):
                    queue.append((nxt, curr))

        for target in V:
            if source == VFIO_USER_DEVICE_STATE_STOP_COPY \
                    and target == VFIO_USER_DEVICE_STATE_PRE_COPY:
                # test for this transition being blocked in a separate test
                continue

            if back[target] is not None:
                seq = deque([])
                curr = target
                while curr != source:
                    seq.appendleft(curr)
                    curr = back[curr]

                server_seq = get_server_shortest_path(source, target)

                assert len(seq) == len(server_seq)
                assert all(seq[i] == server_seq[i] for i in range(len(seq)))
            else:
                expectA = 22 if source in UNREACHABLE_STATES else 0

                get_server_shortest_path(source, target, expectA=expectA,
                                         expectB=22)


def test_migration_stop_copy_to_pre_copy_blocked():
    transition_to_state(VFIO_USER_DEVICE_STATE_STOP_COPY)
    transition_to_state(VFIO_USER_DEVICE_STATE_PRE_COPY, expect=errno.EINVAL)


def test_migration_nonexistent_state():
    transition_to_state(0xabcd, expect=errno.EINVAL)


def test_handle_mig_data_read():
    global read_data

    transition_to_state(VFIO_USER_DEVICE_STATE_RUNNING)

    argsz = len(vfio_user_mig_data())

    payload = vfio_user_mig_data(
        argsz=argsz,
        size=4
    )

    data = bytes([0, 1, 2, 3])

    transition_to_state(VFIO_USER_DEVICE_STATE_PRE_COPY)
    read_data = data
    result = msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload)
    assert len(result) == argsz + 4
    assert result[argsz:argsz + 4] == data

    transition_to_state(VFIO_USER_DEVICE_STATE_STOP_COPY)
    read_data = data
    result = msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload)
    assert len(result) == argsz + 4
    assert result[argsz:argsz + 4] == data


def test_handle_mig_data_read_too_long():
    global read_data

    transition_to_state(VFIO_USER_DEVICE_STATE_RUNNING)

    payload = vfio_user_mig_data(
        argsz=len(vfio_user_mig_data()),
        size=8
    )

    # When we set up the tests at the top of this file we specify that the max
    # data transfer size is 4 bytes. Here we test to check that a transfer of 8
    # bytes fails.

    transition_to_state(VFIO_USER_DEVICE_STATE_PRE_COPY)
    read_data = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload, expect=errno.EINVAL)


def test_handle_mig_data_read_invalid_state():
    global read_data

    payload = vfio_user_mig_data(
        argsz=len(vfio_user_mig_data()),
        size=4
    )

    data = bytes([1, 2, 3, 4])

    transition_to_state(VFIO_USER_DEVICE_STATE_RUNNING)
    read_data = data
    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload, expect=errno.EINVAL)

    transition_to_state(VFIO_USER_DEVICE_STATE_STOP)
    read_data = data
    msg(ctx, sock, VFIO_USER_MIG_DATA_READ, payload, expect=errno.EINVAL)


def test_handle_mig_data_write():
    payload = vfio_user_mig_data(
        argsz=len(vfio_user_mig_data()) + 4,
        size=4
    )

    data = bytes([1, 2, 3, 4])

    transition_to_state(VFIO_USER_DEVICE_STATE_RESUMING)
    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data)
    assert write_data == data


def test_handle_mig_data_write_invalid_state():
    payload = vfio_user_mig_data(
        argsz=len(vfio_user_mig_data()) + 4,
        size=4
    )

    data = bytes([1, 2, 3, 4])

    transition_to_state(VFIO_USER_DEVICE_STATE_RUNNING)
    msg(ctx, sock, VFIO_USER_MIG_DATA_WRITE, bytes(payload) + data,
        expect=errno.EINVAL)


def test_device_feature_short_write():
    payload = struct.pack("I", 8)

    msg(ctx, sock, VFIO_USER_DEVICE_FEATURE, payload, expect=errno.EINVAL)


def test_migration_cleanup():
    disconnect_client(ctx, sock)
    vfu_destroy_ctx(ctx)

# ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab:
