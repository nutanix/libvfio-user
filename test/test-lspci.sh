#!/bin/bash

../samples/lspci | lspci -vv -F /dev/stdin >lspci.out
exec diff lspci.out $(dirname $0)/lspci.expected.out
