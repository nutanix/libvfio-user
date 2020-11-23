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

add_library(muser SHARED
    $<TARGET_OBJECTS:cap>
    $<TARGET_OBJECTS:dma>
    $<TARGET_OBJECTS:muser_ctx>
    $<TARGET_OBJECTS:muser_pci>
    $<TARGET_OBJECTS:tran_sock>
    $<TARGET_OBJECTS:migration>
    $<TARGET_OBJECTS:irq>
    common.h
    muser.h
    muser_priv.h
    tran_sock.h
    vfio_user.h
    irq.h)

set_target_properties(muser PROPERTIES LINKER_LANGUAGE C)
set_target_properties(muser PROPERTIES PUBLIC_HEADER "muser.h;pci.h;vfio_user.h")

set(UT_CFLAGS "-O0 -ggdb --coverage")
set(UT_LFLAGS "--coverage")

function(add_library_ut lib)
    add_library(${lib} OBJECT ${ARGN})
    set(lib_ut ${lib}_ut)
    add_library(${lib_ut} ${ARGN})
    set_target_properties(${lib_ut} PROPERTIES COMPILE_FLAGS ${UT_CFLAGS})
    set_target_properties(${lib_ut} PROPERTIES LINK_FLAGS    ${UT_LFLAGS})
endfunction(add_library_ut)

add_library_ut(cap cap.c cap.h)
add_library_ut(dma dma.c dma.h)
add_library_ut(muser_ctx muser_ctx.c muser.h)
add_library_ut(muser_pci muser_pci.c pci.h)
add_library_ut(tran_sock tran_sock.c tran_sock.h)
add_library_ut(migration migration.c migration.h)
add_library_ut(irq irq.c irq.h)

set(MUSER_HEADERS_DIR ${CMAKE_INSTALL_INCLUDEDIR}/muser)

install(TARGETS muser
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${MUSER_HEADERS_DIR})

install(DIRECTORY "caps"
        DESTINATION ${MUSER_HEADERS_DIR}
        FILES_MATCHING PATTERN "*.h")

if (DEFINED ENV{PYTHON_BINDINGS})
        add_custom_target(python_bindings_build ALL
                COMMAND python setup.py build -b ${CMAKE_BINARY_DIR}
                DEPENDS python_bindings.c setup.py
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/lib
                SOURCES python_bindings.c setup.py)
        # execute_process seems to only execute a single command, e.g. it can't
        # handle two commands joined by &&
        install(CODE "execute_process(COMMAND ${CMAKE_SOURCE_DIR}/lib/python_bindings_install.sh ${CMAKE_SOURCE_DIR})")

endif()
