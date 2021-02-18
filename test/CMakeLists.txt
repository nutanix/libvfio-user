#
# Copyright (c) 2020 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos@nutanix.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Nutanix nor the names of its contributors may be
#       used to endorse or promote products derived from this software without
#       specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

add_executable(unit-tests unit-tests.c mocks.c
		../lib/dma.c
		../lib/irq.c
		../lib/libvfio-user.c
		../lib/migration.c
		../lib/pci.c
		../lib/pci_caps.c
		../lib/tran_sock.c)

target_link_libraries(unit-tests PUBLIC cmocka json-c)

target_compile_definitions(unit-tests PUBLIC UNIT_TEST)

# No "target_link_options" in cmake2
target_link_libraries(unit-tests PUBLIC
                      "-Wl,--wrap=_dma_controller_do_remove_region")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=dma_controller_add_region")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=dma_map_region")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=device_is_stopped")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=get_next_command")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=exec_command")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=close")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=tran_sock_send_iovec")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=free")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=process_request")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=bind")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=listen")
target_link_libraries(unit-tests PUBLIC "-Wl,--wrap=handle_dirty_pages")

enable_testing()
add_test(NAME unit-tests COMMAND unit-tests)
add_test(NAME lspci COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test-lspci.sh)
add_test(NAME client-server COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test-client-server.sh)
