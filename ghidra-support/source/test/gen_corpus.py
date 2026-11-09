#!/usr/bin/env python3
"""Decode corpora for the ARCompact module.

  gen_corpus.py <arc-tbl.h> <outdir>

Writes, for each byte order (le, be), raw files of fixed 10-byte slots; each slot starts with one
instruction (the odd slot size makes every other slot start at an address that is 2 mod 4, which
matters for PCL-relative operands):
  table_<e>.bin  every ARC600/ARC700 entry of binutils' opcodes/arc-tbl.h, 8 fillings of its free
                 bits each (one with all free bits clear, one with all set, six random)
  half_<e>.bin   every 16-bit first halfword (65,536), the rest random
  fuzz_<e>.bin   50,000 random slots
and table_entries.txt: "<slot-index> <name> <opcode> <mask>" for the table corpus.
32-bit instructions and long immediates are stored as two 16-bit halfwords, high halfword first,
each in the byte order of the target (ARCompact "middle-endian" layout for little-endian).
"""
import random
import re
import struct
import sys

SLOT = 10


def halves(v, e):
    hi, lo = (v >> 16) & 0xFFFF, v & 0xFFFF
    f = '<H' if e == 'le' else '>H'
    return struct.pack(f, hi) + struct.pack(f, lo)


def slot_bytes(insn, is32, tail, e):
    f = '<H' if e == 'le' else '>H'
    b = halves(insn, e) if is32 else struct.pack(f, insn)
    b += halves(tail, e) + halves(tail ^ 0x5A5AA5A5, e)
    return b[:SLOT]


def main():
    tbl, out = sys.argv[1], sys.argv[2]
    rnd = random.Random(20261025)
    ents = []
    for m in re.finditer(r'^\{ "([^"]+)", 0x([0-9A-Fa-f]+), 0x([0-9A-Fa-f]+), ([^,]+),', open(tbl).read(), re.M):
        name, op, mask, cpu = m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)
        if 'ARC600' in cpu or 'ARC700' in cpu:
            ents.append((name, op, mask, cpu))
    for e in ('le', 'be'):
        data = bytearray()
        lst = []
        for name, op, mask, cpu in ents:
            is32 = mask > 0xFFFF or op > 0xFFFF
            width = 0xFFFFFFFF if is32 else 0xFFFF
            free = width & ~mask
            for k in range(8):
                fill = 0 if k == 0 else free if k == 1 else rnd.getrandbits(32) & free
                lst.append((len(data) // SLOT, name, op, mask))
                data += slot_bytes(op | fill, is32, rnd.getrandbits(32), e)
        open(f'{out}/table_{e}.bin', 'wb').write(data)
        if e == 'le':
            with open(f'{out}/table_entries.txt', 'w') as f:
                for i, n, o, m in lst:
                    f.write(f'{i} {n} {o:08x} {m:08x}\n')
        data = bytearray()
        for h in range(65536):
            f = '<H' if e == 'le' else '>H'
            data += struct.pack(f, h) + bytes(rnd.getrandbits(8) for _ in range(SLOT - 2))
        open(f'{out}/half_{e}.bin', 'wb').write(data)
        data = bytes(rnd.getrandbits(8) for _ in range(SLOT * 50000))
        open(f'{out}/fuzz_{e}.bin', 'wb').write(data)
    print(f'{len(ents)} table entries')


main()
