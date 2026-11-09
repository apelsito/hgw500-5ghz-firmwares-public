#!/usr/bin/env python3
"""Compare Ghidra slot disassembly (DumpSlots.java) with GNU objdump slot disassembly (slotdis).

  compare.py <ghidra.txt> <objdump.txt>[,<objdump2.txt>...] [examples-per-class]
             [--corpus <raw.bin> <le|be> <slot> --nps <arc-nps400-tbl.h>] [--auxregs <arc-regs.h>]

All files have one line per slot: "<offset-hex> <length> <text>"; length 0 means rejected.
With several objdump files (e.g. -m ARC700 and -m ARC600 output), a slot agrees when Ghidra
matches any of them that decodes it; otherwise it is compared with the first that decodes it.
objdump's "Warning: disassembly may be wrong due to guessed opcode class choice" prefix (printed
for optional extension opcodes in major opcodes 6 and 7) is removed and the slot is bucketed
as "guessed".
With --corpus/--nps, slots whose 32-bit word matches an entry of binutils' NPS-400 table (EZchip
NPS-400 extensions, which objdump -m ARC700 always decodes; major opcodes 0x09-0x0b and some 0x05
forms) are bucketed as "nps400" and not scored when Ghidra rejects them or decodes them as
generic extension instructions.

  exact:    same length and same text after lower-casing, removing blanks in the operand list,
            writing every number as 32-bit hex and replacing objdump's "<offset> ;<target>"
            branch notation by the target
  semantic: additionally the spellings listed in SEM below
"""
import re
import sys
from collections import Counter, defaultdict

CONDS = "eq|ne|p|n|c|nc|v|nv|gt|ge|lt|le|hi|ls|pnz|nj|nm|nt"
BRANCH = re.compile(r"^((b|bl)\.?(%s)?(\.d)?|(breq|brne|brlt|brge|brlo|brhs|bbit0|bbit1)(\.d)?|lp(\.?(%s))?|"
                    r"b_s|beq_s|bne_s|bgt_s|bge_s|blt_s|ble_s|bhi_s|bhs_s|blo_s|bls_s|bl_s|breq_s|brne_s)\s"
                    % (CONDS, CONDS))
NUM = re.compile(r"(?<![\w.])(-?0x[0-9a-f]+|-?\d+)(?![\w])")


WARN = re.compile(r"^\s*Warning: disassembly may be wrong due to guessed opcode class choice\. "
                  r"Use -M<class\[,class\]> to select the correct opcode class\(es\)\.\s*")


def load(path):
    d = {}
    for line in open(path):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) < 2:
            continue
        t = p[2] if len(p) > 2 else ""
        t2 = WARN.sub("", t)
        d[int(p[0], 16)] = (int(p[1]), t2, t2 != t)
    return d


def bad(ol, ot):
    return ol == 0 or ot.startswith("(bad)") or ot.startswith(".word") or ot.startswith(".short") \
        or ot.startswith(".long") or "*unknown*" in ot


def canon_num(m):
    return hex(int(m.group(1), 0) & 0xFFFFFFFF)


def exact_norm(t):
    t = t.lower().replace("\t", " ").strip()
    # Ghidra marks instructions in a delay slot with a leading "_"
    if t.startswith("_"):
        t = t[1:]
    # objdump: "bl -4 ;0x1234" -> target only (relative branches and lp)
    m = re.match(r"^(.*?)(-?\d+|-?0x[0-9a-f]+)\s*;(0x[0-9a-f]+)\s*$", t)
    if m and BRANCH.match(t):
        t = m.group(1) + m.group(3)
    # objdump's address comment on pcl-relative operands ("ld_s r0,[pcl,8] ;0x1234")
    t = re.sub(r"\s*;0x[0-9a-f]+\s*$", "", t)
    m, _, ops = t.partition(" ")
    t = m + " " + ops.replace(" ", "")
    return NUM.sub(canon_num, t).strip()


SEM = [
    # objdump uses the ARCv2 register names; Ghidra the ARCompact ones
    (r"\bilink1\b", "ilink"), (r"\bilink2\b", "r30"), (r"\bmlo\b", "r57"),
    (r"\bmmid\b", "r58"), (r"\bmhi\b", "r59"), (r"\br61reserved\b", "reserved"),
    (r"\br61\b", "reserved"),
    # same encoding: swi on ARC600, trap0 on ARC700
    (r"^swi$", "trap0"),
    # objdump prints nothing for extension conditions without a name (16-20, 22, 25-31)
    (r"\.e0x1[0-9a-f](?=[. ]|$)", ""), (r"^(j\.f|j|jl|b|bl|lp)e0x1[0-9a-f](?=[. ]|$)", r"\1"),
    # objdump's prefetch entry "prefetch [b]" ignores the address-mode bits when the offset is 0
    (r"^prefetch((?:\.di)?)\.a[wbs]? \[([^,\]]+)(,0x0)?\]$", r"prefetch\1 [\2]"),
    # prefetch is a load to the null register; objdump prints either form
    (r"^prefetch(\S*) ", r"ld\1 0x0,"),
    # neg a,b = rsub a,b,0
    (r"^neg(\S*) ([^,]+),([^,]+)$", r"rsub\1 \2,\3,0x0"),
    # address-mode bits are reserved with a long-immediate base and no offset
    (r"^((?:ld|st)[bh]?(?:\.di)?)\.a[wbs]((?:\.x)? \S+,\[0x[0-9a-f]+\])$", r"\1\2"),
    # objdump prints a zero offset in a few store forms ("st limm,[b,0]")
    (r",0x0\]", "]"),
]
AUXREGS = {}


def load_auxregs(path):
    """objdump prints auxiliary register numbers as names (opcodes/arc-regs.h)."""
    for m in re.finditer(r"^DEF \((0x[0-9a-fA-F]+),\s*ARC_OPCODE_(\w+),\s*\w+,\s*(\w+)\)", open(path).read(), re.M):
        num, cpu, name = int(m.group(1), 16), m.group(2), m.group(3)
        if cpu in ("ARCV1", "ARCALL", "ARC600", "ARC700", "ARCFPX"):
            AUXREGS.setdefault(name.lower(), num)


MNEM = {"ldh": "ldw", "sth": "stw", "ldh_s": "ldw_s", "sth_s": "stw_s"}
SUFFIX = {"aw": "a"}


def sem_mnem(t):
    """objdump 2.45 prints the ARCv2 spellings (ldh, sth, .aw) and puts .di before the address
    mode; the ARCompact manual and Ghidra use ldw, stw, .a and <zz><.x><.aa><.di>."""
    m, sp, ops = t.partition(" ")
    parts = m.split(".")
    base = MNEM.get(parts[0], parts[0])
    if base.startswith(("ld", "st", "prefetch")):
        sfx = sorted(SUFFIX.get(x, x) for x in parts[1:])
        m = ".".join([base] + sfx)
    else:
        m = ".".join([base] + parts[1:])
    return m + sp + ops


def aux_name(m):
    n = m.group(1)
    return "[" + (hex(AUXREGS[n]) if n in AUXREGS else n) + "]"


def sem_norm(t):
    t = sem_mnem(exact_norm(t))
    if t.startswith(("lr ", "sr ")):
        t = re.sub(r"\[([a-z_][a-z0-9_]*)\]", aux_name, t)
    for a, b in SEM:
        t = re.sub(a, b, t)
    return t


SIMD = {"pkqb", "upkqb", "xpkqb", "avgqb", "addqbs", "mpyqb", "fxtr", "iaddr", "acm", "sfxtr", "clamp"}


def explain(gt, ot, gbad, obad, w):
    """Reason for a known, explained difference class, or None."""
    gm = mnem(gt).split(".")[0]
    om = mnem(ot).split(".")[0]
    if obad and not gbad and gm.startswith("ext0"):
        return "extension opcode space (majors 5-8), decoded generically by Ghidra"
    if obad and not gbad and gm in SIMD:
        return "ARC700 SIMD extension operand form missing from binutils' table"
    if obad and not gbad and gm in ("dmulpf", "dmacpf") and w is not None and \
            (((w >> 24) & 7, (w >> 12) & 7) == (6, 7) or (w & 0x3f == 62 and (w >> 6) & 0x3f == 62)):
        return "ARC600 dmulpf/dmacpf \"0,limm,c\"/\"0,b,limm\" forms missing from binutils' table"
    if obad and not gbad and gm in ("adcs", "sbcs") and w is not None and (w >> 22) & 3 == 0 \
            and ((w >> 24) & 7, (w >> 12) & 7) == (6, 7) and w & 0x3f == 62:
        return "binutils table bug: adcs/sbcs \"0,limm,c\" entries have format bits 01 (u6)"
    if not obad and not gbad and gm == "adcs" and om == "cmacrdw":
        return "adcs and cmacrdw share an encoding (different options); Ghidra decodes adcs"
    if not obad and not gbad and gm in ("adcs", "sbcs") and om in ("adcs", "sbcs", "cmacrdw") \
            and w is not None and (w >> 22) & 3 == 1 and ((w >> 24) & 7, (w >> 12) & 7) == (6, 7):
        return "binutils table bug: adcs/sbcs \"0,limm,c\" entries have format bits 01 (u6)"
    return None


def mnem(t):
    return t.split(" ")[0].lower() if t else "-"


def nps_table(path):
    """(opcode, mask) of every 32-bit entry of arc-nps400-tbl.h, macros expanded with cpp."""
    import subprocess
    txt = subprocess.run(["cpp", "-P", path], capture_output=True, text=True).stdout
    ents = []
    for m in re.finditer(r'\{\s*"([^"]+)",\s*(.+?),\s*(0x[0-9a-fA-F]+)(u?l*l*),\s*ARC_OPCODE', txt):
        op = eval(re.sub(r"(0x[0-9a-fA-F]+)u?l*l*", r"\1", m.group(2)))
        mask = int(m.group(3), 16)
        if mask <= 0xFFFFFFFF:
            ents.append((op, mask))
    return ents


def word32(data, off, e):
    import struct
    f = '<H' if e == 'le' else '>H'
    hi = struct.unpack_from(f, data, off)[0]
    lo = struct.unpack_from(f, data, off + 2)[0] if off + 4 <= len(data) else 0
    return (hi << 16) | lo


def main():
    args = sys.argv[1:]
    corpus = nps = None
    if "--corpus" in args:
        i = args.index("--corpus")
        corpus = (open(args[i + 1], "rb").read(), args[i + 2], int(args[i + 3]))
        del args[i:i + 4]
    if "--auxregs" in args:
        i = args.index("--auxregs")
        load_auxregs(args[i + 1])
        del args[i:i + 2]
    if "--nps" in args:
        i = args.index("--nps")
        nps = nps_table(args[i + 1])
        del args[i:i + 2]
    sys.argv[1:] = args
    g = load(sys.argv[1])
    os_ = [load(f) for f in sys.argv[2].split(",")]
    nex = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    cnt = Counter()
    classes = defaultdict(list)
    for off in sorted(os_[0]):
        gl, gt, _ = g.get(off, (0, "BAD", False))
        cands = [o[off] for o in os_ if off in o and not bad(o[off][0], o[off][1])]
        ol, ot, guessed = cands[0] if cands else os_[0][off]
        for c in cands:
            if c[0] == gl and sem_norm(c[1]) == sem_norm(gt):
                ol, ot, guessed = c
                break
        gbad = gl == 0
        obad = not cands
        cnt["total"] += 1
        if nps and corpus and not obad and (gbad or gt.lower().startswith("ext")):
            data, e, _ = corpus
            w = word32(data, off, e)
            if 0x09 <= (w >> 27) <= 0x0b or ((w >> 27) < 0x09 and any((w & m) == o for o, m in nps)):
                cnt["nps400"] += 1
                classes["nps400 (objdump ARC700 NPS-400 table) " + mnem(ot)].append((off, gt, ot, ol))
                continue
        if guessed and not gbad:
            cnt["guessed"] += 1
            if gl == ol and sem_norm(gt) == sem_norm(ot):
                cnt["guessed_agree"] += 1
            else:
                classes["guessed (objdump warns), differs: " + mnem(ot) + " / " + mnem(gt)].append((off, gt, ot, ol))
            continue
        if gbad and obad:
            cnt["both_reject"] += 1
            continue
        w = word32(corpus[0], off, corpus[1]) if corpus else None
        why = explain(gt, ot, gbad, obad, w) if (gbad or obad or sem_norm(gt) != sem_norm(ot)) else None
        if why:
            cnt["explained"] += 1
            classes["explained: " + why].append((off, gt, ot, ol))
            continue
        if gbad:
            cnt["ref_only"] += 1
            classes["ref only: " + mnem(ot)].append((off, gt, ot, ol))
            continue
        if obad:
            cnt["ghidra_only"] += 1
            classes["ghidra only: " + mnem(gt)].append((off, gt, ot, gl))
            continue
        cnt["both_decode"] += 1
        if gl == ol and exact_norm(gt) == exact_norm(ot):
            cnt["exact"] += 1
            cnt["semantic"] += 1
        elif gl == ol and sem_norm(gt) == sem_norm(ot):
            cnt["semantic"] += 1
            classes["~ " + mnem(ot)].append((off, gt, ot, gl))
        else:
            key = ("LEN " if gl != ol else "DIFF ") + mnem(ot) + " / " + mnem(gt)
            classes[key].append((off, gt, ot, "%d/%d" % (gl, ol)))
    bd = cnt["both_decode"] or 1
    unexplained = cnt["ghidra_only"] + cnt["ref_only"] + cnt["both_decode"] - cnt["semantic"] \
        + cnt["guessed"] - cnt["guessed_agree"]
    print("compared %d slots: both decode %d, exact %d (%.2f%%), semantic %d (%.2f%%), "
          "ghidra-only %d, ref-only %d, both reject %d, objdump guessed class %d (agree %d), nps400 %d, "
          "explained %d; unexplained differences %d"
          % (cnt["total"], cnt["both_decode"], cnt["exact"], 100.0 * cnt["exact"] / bd,
             cnt["semantic"], 100.0 * cnt["semantic"] / bd, cnt["ghidra_only"], cnt["ref_only"],
             cnt["both_reject"], cnt["guessed"], cnt["guessed_agree"], cnt["nps400"], cnt["explained"],
             unexplained))
    for k in sorted(classes, key=lambda k: (k.startswith("~"), -len(classes[k]))):
        v = classes[k]
        print("  [%d] %s" % (len(v), k))
        for off, gt, ot, ln in v[:nex]:
            print("      %08x len %s  ghidra: %-34s objdump: %s" % (off, ln, gt, ot))


if __name__ == "__main__":
    main()
