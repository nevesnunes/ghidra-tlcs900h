#!/usr/bin/env python3

import colorama
import re
import sys

colorama.init()


def hi_bold(text):
    return colorama.Style.BRIGHT + str(text) + colorama.Style.RESET_ALL


def hi_1(text):
    return (
        colorama.Fore.RED + colorama.Style.BRIGHT + str(text) + colorama.Style.RESET_ALL
    )


def hi_2(text):
    return (
        colorama.Fore.MAGENTA
        + colorama.Style.BRIGHT
        + str(text)
        + colorama.Style.RESET_ALL
    )


def hi_hex(text):
    text = str(text)
    o = ""
    i = 0
    while i < len(text):
        x = text[i : i + 2]
        if x == "00":
            # Grey
            o += "\x1b[38;5;8m" + x + colorama.Style.RESET_ALL
            i += 2
        elif x[0] in "0123456789abcdef":
            o += x
            i += 2
        else:
            o += x[0]
            i += 1
    return o


def parse(m):
    return {
        "PC": int(m.group(2), 16),
        "Ins": m.group(3).strip(),
        "Ops": m.group(4).strip(),
        "XWA": int(m.group(5), 16),
        "XBC": int(m.group(6), 16),
        "XDE": int(m.group(7), 16),
        "XHL": int(m.group(8), 16),
        "XIX": int(m.group(9), 16),
        "XIY": int(m.group(10), 16),
        "XIZ": int(m.group(11), 16),
        "XSP": int(m.group(12), 16),
        "IFF": m.group(13),
        "RFP": m.group(14),
        "Flags": m.group(15),
    }


def hi_diff_field(f_out, f_k, k):
    if f_k == k:
        return hi_1(f_out)

    return hi_hex(f_out)


def hi_diff(a, k):
    # Need to pad before applying colors, so that non-printable escape sequences
    # are not counted for padding...
    ins = f'{a["Ins"]} {a["Ops"]}'
    ins = f"{ins:<32}"
    ins = hi_diff_field(ins, "Ins", k)

    out = hi_diff_field(f'{a["PC"]:08x} ', "PC", k)
    out += ins
    for r in [ "XWA", "XBC", "XDE", "XHL", "XIX", "XIY", "XIZ", "XSP", ]:
        out += hi_diff_field(f"{r}:" f"{a[r]:08x} ", r, k)
    out += hi_diff_field(f'IFF:{a["IFF"]} ', "IFF", k)
    out += hi_diff_field(f'RFP:{a["RFP"]} ', "RFP", k)
    out += hi_diff_field(a["Flags"], "Flags", k)

    return out


seen_warn_fields = set()


def diff(i, ins_i, m1, m2):
    a = parse(m1)
    b = parse(m2)
    for k, av in sorted(a.items()):
        if k == "Ops":
            continue

        bv = b[k]
        if av != bv:
            if k == "Ins" and (
                (av.rstrip("w") == bv.rstrip("w"))
                or (av == "di" and bv == "ei")
                or (av == "ei" and bv == "di")
                or (av == "sbb" and bv == "sbc")
                or (av == "sbc" and bv == "sbb")
            ):
                if av not in seen_warn_fields and bv not in seen_warn_fields:
                    print(hi_2(f"WARN: possible mismatch @ line={i} field={k}:"))
                    print(f"\t{hi_diff(a, k)}\n\t{hi_diff(b, k)}")
                    seen_warn_fields.add(av)
                    seen_warn_fields.add(bv)

                continue

            raise RuntimeError(
                f"diff @ line={i} ins={ins_i} field={k}:{colorama.Style.RESET_ALL}\n\t{hi_diff(a, k)}\n\t{hi_diff(b, k)}"
            )


p = (
    r"^(CPU)?\s*([0-9a-f]+)\s+([0-9a-z]+)(.*?)"
    + r"XWA:([0-9a-f]+) "
    + r"XBC:([0-9a-f]+) "
    + r"XDE:([0-9a-f]+) "
    + r"XHL:([0-9a-f]+) "
    + r"XIX:([0-9a-f]+) "
    + r"XIY:([0-9a-f]+) "
    + r"XIZ:([0-9a-f]+) "
    + r"XSP:([0-9a-f]+) "
    + r"IFF:([0-9a-f]+) "
    + r"RFP:([0-9a-f]+) "
    + r"([sSzZhHvVnNcC]+)(.*)"
)
p_apu = r"^APU\s*.*"
p_cpu_event = r"^CPU\s*(Interrupt|I/O).*"


def match(line, line_i, file_i):
    if re.match(p_cpu_event, line) or re.match(p_apu, line):
        return None

    m = re.match(p, line)
    if not m:
        raise RuntimeError(f"unmatched file={file_i} line={line_i}: {line}")

    return m


with open(sys.argv[1], "r") as f1, open(sys.argv[2], "r") as f2:
    lines1 = f1.readlines()
    lines2 = f2.readlines()
    len_lines = min(len(lines1), len(lines2))
    ins_i = 0
    for i in range(len_lines):
        line1 = lines1[i]
        line2 = lines2[i]
        try:
            m1 = match(line1, i, 1)
            m2 = match(line2, i, 2)
            if not m1 or not m2:
                continue
            ins_i += 1
            diff(i, ins_i, m1, m2)
        except RuntimeError as e:
            print(hi_bold("Context:"))
            context_i = max(0, i - 5)
            while context_i < i:
                print(f"\t{hi_hex(lines1[context_i].rstrip())}", file=sys.stderr)
                context_i += 1
            print(hi_1(f"ERROR: {e}"), file=sys.stderr)
            exit(1)
    print(hi_bold(f"PASSED {ins_i} instructions / {len_lines} lines!"))
