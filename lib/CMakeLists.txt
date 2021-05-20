#
# Copyright (c) 2019 Nutanix Inc. All rights reserved.
#
# Authors: Thanos Makatos <thanos@nutanix.com>
#          Swapnil Ingle <swapnil.ingle@nutanix.com>
#          Felipe Franciosi <felipe@nutanix.com>
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

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

#
# FIXME: we're not updating this yet, so it has no meaning.
#
set(LIBMAJOR 0)
set(LIBMINOR 0)
set(LIBPATCH 1)

set(LIBOBJS
    $<TARGET_OBJECTS:pci_caps>
    $<TARGET_OBJECTS:dma>
    $<TARGET_OBJECTS:irq>
    $<TARGET_OBJECTS:libvfio-user>
    $<TARGET_OBJECTS:migration>
    $<TARGET_OBJECTS:pci>
    $<TARGET_OBJECTS:tran_sock>)

add_library(pci_caps OBJECT pci_caps.c)
add_library(dma OBJECT dma.c)
add_library(irq OBJECT irq.c)
add_library(libvfio-user OBJECT libvfio-user.c)
add_library(migration OBJECT migration.c)
add_library(pci OBJECT pci.c)
add_library(tran_sock OBJECT tran_sock.c)

add_library(vfio-user-shared SHARED ${LIBOBJS})
target_link_libraries(vfio-user-shared json-c pthread)
set_target_properties(vfio-user-shared PROPERTIES
                      LINKER_LANGUAGE C)
set_target_properties(vfio-user-shared PROPERTIES
                      OUTPUT_NAME vfio-user
                      CLEAN_DIRECT_OUTPUT 1)
set_target_properties(vfio-user-shared PROPERTIES
                      SOVERSION ${LIBMAJOR}
                      VERSION ${LIBMAJOR}.${LIBMINOR}.${LIBPATCH})

add_library(vfio-user-static STATIC ${LIBOBJS})
target_link_libraries(vfio-user-static json-c pthread)
set_target_properties(vfio-user-static PROPERTIES
                      LINKER_LANGUAGE C)
set_target_properties(vfio-user-static PROPERTIES
                      OUTPUT_NAME vfio-user
                      CLEAN_DIRECT_OUTPUT 1)

install(TARGETS vfio-user-shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(TARGETS vfio-user-static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
