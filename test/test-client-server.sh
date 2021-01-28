#!/bin/bash

set -e

sock="/tmp/vfio-user.sock"
rm -f ${sock}*
../samples/server -v ${sock} &
server_pid=$!
while [ ! -S ${sock} ]; do
	sleep 0.1
done
../samples/client ${sock}
wait
