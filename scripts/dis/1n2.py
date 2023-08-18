#!/usr/bin/env python3

import binascii
import os
import subprocess
import sys

with open('/tmp/2', 'wb') as f:
    for i2 in range(0x100):
        b2 = bytes([i2])
        f.write(b2 + bytes([0x00]*8))
        for i in range(0x100):
            b = bytes([i])
            f.write(b2 + b + bytes([0x00]*8))

cmd = [
    os.path.expanduser('~/opt/mame/unidasm'),
    '/tmp/2',
    '-arch',
    'tlcs900'
]
subprocess.Popen(cmd).wait()
