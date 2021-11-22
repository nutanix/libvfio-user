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
