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

# Copy sources to build directory (avoid polluting source directory).
# TODO can we copy all source files with a wildcard?
configure_file(muser.c ${CMAKE_CURRENT_BINARY_DIR}/muser.c COPYONLY)
configure_file(muser.h ${CMAKE_CURRENT_BINARY_DIR}/muser.h COPYONLY)
# FIXME need to pass "CFLAGS_muser.o := -DDEBUG" for debug builds
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Kbuild "obj-m := muser.o")

# Build module using kernel's Makefile.
set(KBUILD_CMD ${CMAKE_MAKE_PROGRAM} -C ${KDIR} M=${CMAKE_CURRENT_BINARY_DIR} modules)
ADD_CUSTOM_COMMAND(OUTPUT DRIVER_BIN_FILE
                   COMMAND ${KBUILD_CMD}
                   DEPENDS ${MODULE_SOURCE_FILES} VERBATIM
)
ADD_CUSTOM_TARGET(driver ALL DEPENDS DRIVER_BIN_FILE)
execute_process(COMMAND uname -r OUTPUT_VARIABLE kver OUTPUT_STRIP_TRAILING_WHITESPACE)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/muser.ko DESTINATION /lib/modules/${kver}/extra/)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/muser.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/linux)
