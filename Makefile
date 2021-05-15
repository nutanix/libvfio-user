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

BUILD_TYPE ?= dbg

ifeq ($(BUILD_TYPE), dbg)
	CMAKE_BUILD_TYPE = Debug
    CFLAGS += -DDEBUG
else
	CMAKE_BUILD_TYPE = Release
endif

ifdef WITH_ASAN
	CC = clang
	CFLAGS += -fsanitize=address
	LDFLAGS += -fsanitize=address
endif

ifeq ($(VERBOSE),)
    MAKEFLAGS += -s
endif

CMAKE = cmake

BUILD_DIR_BASE = $(CURDIR)/build
BUILD_DIR = $(BUILD_DIR_BASE)/$(BUILD_TYPE)

INSTALL_PREFIX ?= /usr/local

PHONY_TARGETS := all pytest pytest-valgrind test pre-push realclean buildclean force_cmake tags
.PHONY: $(PHONY_TARGETS)

all $(filter-out $(PHONY_TARGETS), $(MAKECMDGOALS)): $(BUILD_DIR)/Makefile
	+$(MAKE) -C $(BUILD_DIR) $@

#
# NB: add --capture=no to get a C-level assert failure output.
#
PYTESTCMD = \
	$(shell which -a pytest-3 /bin/true 2>/dev/null | head -1) \
	-rP \
	--quiet

PYTEST = \
    BUILD_TYPE=$(BUILD_TYPE) \
	$(PYTESTCMD)

#
# In our tests, we make sure to destroy the ctx at the end of each test; this is
# enough for these settings to detect (most?) library leaks as "definite",
# without all the noise from the rest of the Python runtime.
#
# As running under valgrind is very slow, we don't run this unless requested.
#
PYTESTVALGRIND = \
	BUILD_TYPE=$(BUILD_TYPE) \
	PYTHONMALLOC=malloc \
	valgrind \
	--suppressions=$(CURDIR)/test/py/valgrind.supp \
	--quiet \
	--track-origins=yes \
	--errors-for-leak-kinds=definite \
	--show-leak-kinds=definite \
	--leak-check=full \
	--error-exitcode=1 \
	$(PYTESTCMD)

ifdef WITH_ASAN

pytest pytest-valgrind:

else

pytest: all
	@echo "=== Running python tests ==="
	$(PYTEST)

pytest-valgrind: all
	@echo "=== Running python tests with valgrind ==="
	$(PYTESTVALGRIND)

endif

test: all pytest
	cd $(BUILD_DIR)/test; ctest --verbose

pre-push: realclean
	make test WITH_ASAN=1
	make realclean
	make test CC=clang BUILD_TYPE=rel
	make test CC=clang
	make realclean
	make test CC=gcc BUILD_TYPE=rel
	make test CC=gcc
	make pytest-valgrind

realclean:
	rm -rf $(BUILD_DIR_BASE)

buildclean:
	rm -rf $(BUILD_DIR)

force_cmake: $(BUILD_DIR)/Makefile

$(BUILD_DIR)/Makefile:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR); $(CMAKE) \
		-D "CMAKE_C_COMPILER:STRING=$(CC)" \
		-D "CMAKE_C_FLAGS:STRING=$(CFLAGS)" \
		-D "CMAKE_BUILD_TYPE:STRING=$(CMAKE_BUILD_TYPE)" \
		-D "CMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX)" \
		-D "WITH_ASAN=$(WITH_ASAN)" \
		$(CURDIR)

tags:
	ctags -R --exclude=$(BUILD_DIR)
