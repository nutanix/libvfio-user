#!/bin/sh

set -e
set -v

test -z "$BUILD" && BUILD=build

rm -rf $BUILD

# ASAN build with clang
CC=clang meson $BUILD/asan -Db_sanitize=address -Db_lundef=false
ninja -C $BUILD/asan -v
meson test -C $BUILD/asan --suite style --print-errorlogs
meson test -C $BUILD/asan --no-suite style --print-errorlogs

# debug build with clang
CC=clang meson build/clang-debug -Dtran-pipe=true
ninja -C $BUILD/clang-debug -v
meson test -C $BUILD/clang-debug --no-suite style --print-errorlogs

# plain build with clang
CC=clang meson build/clang-plain -Dtran-pipe=true -Dbuildtype=plain
ninja -C $BUILD/clang-plain -v
meson test -C $BUILD/clang-plain --no-suite style --print-errorlogs

# debug build with gcc
CC=gcc meson build/gcc-debug -Dtran-pipe=true
ninja -C $BUILD/gcc-debug -v
meson test -C $BUILD/gcc-debug --no-suite style --print-errorlogs

# plain build with gcc
CC=gcc meson build/gcc-plain -Dtran-pipe=true -Dbuildtype=plain
ninja -C $BUILD/gcc-plain -v
meson test -C $BUILD/gcc-plain --no-suite style --print-errorlogs

meson test -C $BUILD/gcc-plain --suite unit --setup valgrind --print-errorlogs
meson test -C $BUILD/gcc-plain --suite pyunit --setup pyvalgrind --print-errorlogs

DESTDIR=tmp.install meson install -C $BUILD/gcc-plain
