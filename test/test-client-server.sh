#!/bin/bash

set -e

valgrind="valgrind --quiet --trace-children=yes --error-exitcode=1 --exit-on-first-error=yes --leak-check=full"

sock="/tmp/vfio-user.sock"
rm -f ${sock}*
${valgrind} ../samples/server ${sock} &
server_pid=$!
while [ ! -S ${sock} ]; do
	sleep 0.1
done
${valgrind} ../samples/client ${sock}
wait
