#!/usr/bin/env python3

import re
import sys

with open(sys.argv[1], 'r') as f_in, open(sys.argv[2], 'w') as f_out:
    p_num = r'0x[0-9a-f][0-9a-f]+'
    p_ins = r'^[ \t]*(([0-9a-f][0-9a-f][ \t])+)\|(.*)$'
    prev_candidate = None
    prev_i = 0
    for line in f_in.readlines():
        m_num = re.search(p_num, line)
        if not m_num:
            prev_i = 0
            prev_candidate = None
            f_out.write(line)
            continue
        else:
            m_ins = re.search(p_ins, line)
            if not m_ins:
                continue
            else:
                candidate = re.sub(p_num, '_', m_ins.group(3))
                if not prev_candidate or prev_candidate != candidate:
                    prev_i = 0
                    prev_candidate = candidate
                    f_out.write(line)
                    continue
                elif prev_i < 2 or prev_i == 0xff or prev_i % 0x7fff == 0:
                    f_out.write(line)
                prev_i += 1
