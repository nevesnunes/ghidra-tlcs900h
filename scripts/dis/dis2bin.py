#!/usr/bin/env python3

import collections
import re
import sys

disasms = []
ins_ret = b'\x0e'
p = r'^[ \t]*(([0-9a-f][0-9a-f][ \t])+)[ \t][ \t]+(\w+)(.*)$'
with open(sys.argv[1], 'r') as f, open(sys.argv[2], 'wb') as f_out:
    for i,line in enumerate(f.readlines()):
        m = re.match(p, line)
        if m:
            f_out.write(bytes.fromhex(m.group(1)))
        if i > 1000 and i % 10000 == 0:
            # Avoid reaching address space limits by spreading
            # return instructions, which should reduce address spaces
            # required for tracking register values.
            f_out.write(ins_ret)
