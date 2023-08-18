#!/usr/bin/env python3

import os
import re
import subprocess
import sys


def chunks(lst, n):
    """Expand successive n-sized chunks from lst."""
    return [lst[i - n : i] for i in range(n, len(lst) + n, n)]


filename = sys.argv[1]
n = int(sys.argv[2], 0)
tmp_name = f"/tmp/{n}"
with open(filename, "r") as f:
    p = r"^[ \t]*" + (r"([0-9a-f]{2} )" * n) + r" +.*$"
    p_db = r"^.*  db$"
    for chunk in chunks(f.readlines(), 5000):
        with open(tmp_name, "wb") as temp:
            for line in chunk:
                m = re.match(p, line)
                if m:
                    known_hex = ""
                    for i in range(1, n, 1):
                        known_hex += m.group(i)
                    known_bytes = bytes.fromhex(known_hex)
                    m_db = re.search(p_db, line)
                    i_range = (
                        range(0x100)
                        if m_db
                        else [
                            0x00, 0x01, 0x08, 0x0F,
                            0x7F, 0x80, 0xF0, 0xFF,
                        ]
                    )
                    for i in i_range:
                        b = bytes([i] + [0x00] * 8)
                        temp.write(known_bytes + b)

        cmd = [
            os.path.expanduser("~/opt/mame/unidasm"),
            tmp_name,
            "-arch",
            "tlcs900",
        ]
        subprocess.Popen(cmd).wait()
