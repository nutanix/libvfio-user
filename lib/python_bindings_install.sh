#!/bin/bash

# 'python setup.py install' expects to find a directory named 'build' with
# subdirectories 'lib.linux-x86_64-2.7' and 'temp.linux-x86_64-2.7'. If not,
# then it tries to build, however there's no way to tell it where to put the
# binary files -- it puts them in the sources directory. These two directories
# are created during the build phase (by 'python setup.py build') and the
# binary files are explicitly stored under build/dbg.

# current directory is build/dbg/, move back to build/
cd ../

# now sylmink dbg to build (parent dir is also build)
ln -s dbg build

# now symlink'ed dir build contains lib.linux-x86_64-2.7 and
# temp.linux-x86_64-2.7

# --skip-build seems necessary otherwise 'python setup.py install' to tries to
# build because source files aren't found (we're under the build directory).
# We can't simply cd into the source directory and run the install command there
# because it expects to find the build/ directory there.
python ${1}/lib/setup.py install --skip-build
