from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Listing
from ghidra.app.cmd.disassemble import DisassembleCommand

from collections import OrderedDict

def bytesToHex(byte):
    out = ''
    for b in byte:
        b = (bin(((1 << 8) - 1) & b)[2:]).zfill(8)
        h = hex(int(b, 2))[2:]
        if len(h) == 1:
            h = '0' + h
        out += h + ' '
    return out.strip()

def dis(cus, start):
    # Do not follow flow or auto-analyze to avoid null pointer exceptions.
    start_addr = toAddr(start)
    end_addr = toAddr(0xffffff)
    addresses = AddressSet(start_addr, end_addr)
    cmd = DisassembleCommand(start_addr, addresses, False)
    cmd.enableCodeAnalysis(False)
    cmd.applyTo(currentProgram, monitor)

    listing = currentProgram.getListing()
    cuIterator = Listing.getCodeUnits(listing, True)

    args = getScriptArgs()
    for cu in cuIterator:
        cu_addr = cu.getAddress()
        cu_bytes = bytesToHex(cu.getBytes())
        cu_line = "{}: {} {}".format(
            cu_addr,
            cu_bytes.ljust(18),
            cu,
        )
        print(cu_line)
        cus[cu_addr.getUnsignedOffset()] = cu
        if '??' in cu_line:
            break

# Start disassembling on next undefined address, otherwise
# auto-disassemble will just stop at a jump instruction, although more
# valid instructions may lie ahead.
cus = {}
last_start = 0
while True:
    dis(cus, last_start)
    cus_sorted = OrderedDict(sorted(cus.items()))
    k = next(reversed(list(cus_sorted)))
    new_start = k + len(cus[k].getBytes())
    if abs(last_start - new_start) > 1:
        print(hex(last_start), '->', hex(new_start))
        last_start = new_start - 1
    else:
        break

args = getScriptArgs()
cus_sorted = OrderedDict(sorted(cus.items()))
with open(args[0], "w") as f:
    for cu in cus_sorted.values():
        cu_bytes = bytesToHex(cu.getBytes())
        cu_addr = cu.getAddress()
        cu_line = "{}: {} {}\n".format(
            cu_addr,
            cu_bytes.ljust(18),
            cu,
        )
        f.write(cu_line)
