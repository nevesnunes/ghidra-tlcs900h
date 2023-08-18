#!/usr/bin/env python3

import binascii
import os
import subprocess
import sys

for i3 in range(0x100):
    b3 = bytes([i3])
    with open('/tmp/3', 'wb') as f:
        for i2 in range(0x100):
            b2 = bytes([i2])
            for i in range(0x100):
                b = bytes([i])
                f.write(b3 + b2 + b + bytes([0x00]*8))

    cmd = [
        os.path.expanduser('~/opt/mame/unidasm'),
        '/tmp/3',
        '-arch',
        'tlcs900'
    ]
    subprocess.Popen(cmd).wait()

# ~/code/wip/tlcs900h/3all.py  667.86s user 221.84s system 95% cpu 15:32.15 total
# sed 's/   */  /g'  248.13s user 249.69s system 53% cpu 15:32.15 total
# cut -d':' -f2-  25.26s user 4.73s system 3% cpu 15:32.15 total
# grep -v '^ *.. .. ..  db'  18.02s user 3.60s system 2% cpu 15:32.15 total
# sort -u > 3allout  197.99s user 3.85s system 21% cpu 15:50.36 total
