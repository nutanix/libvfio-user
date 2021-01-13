#!/bin/bash

#
# There are two different potential outputs on the distributions we test for;
# accept either.
#

../samples/lspci | lspci -vv -F /dev/stdin >lspci.out
diff lspci.out $(dirname $0)/lspci.expected.out || {
	diff lspci.out $(dirname $0)/lspci.expected.out.2
}
exit $?
