Testing
=======

Running `make test` runs most of the integrated tests. You should have
`valgrind` installed.

Running `make pre-push` runs the above builds and tests in different configurations: GCC,
clang, and with ASAN enabled.

There are some [older unit tests](test/unit-tests.c) written in C, but most
tests are now done via Python, in the [test/py](test/py) sub-directory. You can
run just the Python tests via `make pytest` or `make pytest-valgrind`.

The master branch is run through [Coverity](scan.coverity.com) when a new PR
lands.

You can also run `make gcov` to get code coverage reports.

Debugging Test Errors
---------------------

Sometimes debugging Valgrind errors on Python unit tests can be tricky. To
run specific tests use the pytest `-k` option in `PYTESTCMD` in the Makefile.

AFL++
-----

You can run [American Fuzzy Lop](https://github.com/AFLplusplus/AFLplusplus)
against `libvfio-user`. It's easiest to use the Docker container:

```
cd /path/to/libvfio-user/src
docker pull aflplusplus/aflplusplus
docker run -ti -v $(pwd):/src aflplusplus/aflplusplus
```

Set up and build:

```
apt update
apt-get -y install libjson-c-dev libcmocka-dev clang valgrind \
                   python3-pytest debianutils flake8 cmake

cd /src
export AFL_LLVM_LAF_ALL=1
make CC=afl-clang-fast WITH_TRAN_PIPE=1

mkdir inputs
# don't yet have a better starting point
echo "1" >inputs/start
mkdir outputs
```

The `VFU_TRAN_PIPE` is a special `libvfio-user` transport that reads from
`stdin` instead of a socket, we'll use this with the sample server to do our
fuzzing:

```
afl-fuzz -i inputs/ -o outputs/ -- ./build/dbg/samples/server pipe
```
