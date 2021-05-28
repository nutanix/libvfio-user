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

cmake_minimum_required (VERSION 2.6)
if (CMAKE_MAJOR_VERSION LESS 3)
    project(libvfio-user C)
else()
    project(libvfio-user LANGUAGES C)
endif()
include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSON REQUIRED json-c)

# for the benefit of the gcov rules
set(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${JSON_INCLUDE_DIRS})

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
#
# NB: this intentionally does not define NDEBUG: we want our assert()s even in a
# release build.
#
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -D_GNU_SOURCE -Wall -Werror -Wextra")
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wmissing-declarations")
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -fvisibility=hidden")

# public headers
add_subdirectory(include)

# shared libraries
add_subdirectory(lib)

# samples
add_subdirectory(samples)

# test
add_subdirectory(test)
