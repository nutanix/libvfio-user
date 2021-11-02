#!/bin/bash

set -e

#
# ASAN and valgrind, understandably, don't get along.
#
if [ "$WITH_ASAN" = 1 ]; then
    valgrind=""
else
    valgrind="valgrind --quiet --trace-children=yes --error-exitcode=1 --leak-check=full"
fi

sock="/tmp/vfio-user.sock"
rm -f ${sock}*
${valgrind} ../samples/server -v ${sock} &
while [ ! -S ${sock} ]; do
	sleep 0.1
done
${valgrind} ../samples/client ${sock} || {
    kill $(jobs -p)
    exit 1
}
wait
