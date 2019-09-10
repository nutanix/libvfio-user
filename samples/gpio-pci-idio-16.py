#!/usr/bin/python

def bar2(pvt, buf, count, offset, is_write):
        if not is_write and int(offset) == 0:
                return int(input("enter new GPIO value: "))

import muser
muser.run(vid=0x494F, did=0x0DC8, uuid="00000000-0000-0000-0000-000000000000", bar2=("rw", 0x100, bar2), intx=1)
