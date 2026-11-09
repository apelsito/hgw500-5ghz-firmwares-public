#!/usr/bin/env python3
"""Generate data/languages/ARCompact_ops.sinc: the ARCompact general operations (major opcodes
0x04-0x08: ALU, single-operand and zero-operand instructions) and the compare-and-branch
instructions (major 0x01, bit 16 set).

  tools/gen_arcompact.py [out.sinc]

Each operation is one table row. "res" is p-code computing local vr from the sources vb and vc
(and the flags); "flags" is p-code run only by the .f form, after vr is known. A row with
res=None becomes a named pcodeop taking the two sources (DSP, FPX and SIMD extension
instructions whose exact arithmetic is not modelled).

Operand formats of general operations (bits 23..22):
  0: a,b,c   1: a,b,u6   2: b,b,s12   3: <cc> b,b,c (M=0) / b,b,u6 (M=1)
Syntax follows GNU objdump 2.45 (".f" before the condition).
"""
import re
import sys

ZN = "Z = vr == 0;\n  N = vr s< 0;"

# add/sub style flags
ADD_F = "C = carry(vb, vt);\n  V = scarry(vb, vt);\n  " + ZN
SUB_F = "C = vb < vt;\n  V = sborrow(vb, vt);\n  " + ZN

# saturate a 64-bit signed value w into vr, setting local sat
SAT = """local sat:1 = (w s> 0x7fffffff) || (w s< -0x80000000);
  vr = w:4;
  if (w s<= 0x7fffffff) goto <nothigh>;
  vr = 0x7fffffff;
<nothigh>
  if (w s>= -0x80000000) goto <notlow>;
  vr = 0x80000000;
<notlow>"""

# Sticky saturation flag S (set by every saturating operation with .f; ARCompact PRM)
VS = "V = sat;\n  S = S || sat;\n  " + ZN

# shift with saturation (PRM ASLS/ASRS): the count is a signed 32-bit value, limited to +-31
def sat_shift(left, right):
    return ("local sh:4 = vc;\n  local w:8;\n"
            "  if (sh s> 31) goto <big>;\n  if (sh s< -31) goto <small>;\n  if (sh s< 0) goto <neg>;\n"
            f"  w = {left.format(n='sh')};\n  goto <done>;\n"
            f"<neg>\n  w = {right.format(n='(0 - sh)')};\n  goto <done>;\n"
            f"<big>\n  w = {left.format(n='31')};\n  goto <done>;\n"
            f"<small>\n  w = {right.format(n='31')};\n<done>\n  " + SAT)


SHL = "sext(vb) << {n}"
SHR = "sext(vb s>> {n})"

# dual 16-bit saturating add/subtract (PRM ADDSDW/SUBSDW)
def satdw(op):
    return (f"local bh:2 = vb(2);\n  local ch:2 = vc(2);\n  local wh:4 = sext(bh) {op} sext(ch);\n  local wl:4 = sext(vb:2) {op} sext(vc:2);\n"
            "  local sat:1 = 0;\n"
            "  if (wh s<= 0x7fff) goto <h1>;\n  wh = 0x7fff;\n  sat = 1;\n<h1>\n"
            "  if (wh s>= -0x8000) goto <h2>;\n  wh = -0x8000;\n  sat = 1;\n<h2>\n"
            "  if (wl s<= 0x7fff) goto <l1>;\n  wl = 0x7fff;\n  sat = 1;\n<l1>\n"
            "  if (wl s>= -0x8000) goto <l2>;\n  wl = -0x8000;\n  sat = 1;\n<l2>\n"
            "  vr = (wh << 16) | (wl & 0xffff);")


# ARC600/ARC700 XMAC 32x16 multiply(-accumulate) with the 64-bit accumulator r56:r57 (high:low),
# after the CGEN ARCompact description (foss-for-synopsys-dwc-arc-processors/cgen)
ACC = "local acc:8 = (zext(r56) << 32) | zext(mlo);"
SAT64 = """local sat:1 = (w s> 0x7fffffff) || (w s< -0x80000000);
  vr = w:4;
  if (w s<= 0x7fffffff) goto <nothigh>;
  vr = 0x7fffffff;
<nothigh>
  if (w s>= -0x80000000) goto <notlow>;
  vr = 0x80000000;
<notlow>"""
def xmac(mult, accumulate, unsigned, result_high):
    ext = "zext" if unsigned else "sext"
    code = f"local w:8 = {ext}(vb) * {ext}({mult});\n  "
    if accumulate:
        code += ACC + "\n  local sum:8 = acc + w;\n  local sat:1 = 0;\n"
        if unsigned:
            code += "  if (sum >= acc) goto <nosat>;\n  sum = -1;\n  sat = 1;\n<nosat>\n"
        else:
            code += ("  if (((acc ^ w) s< 0) || (((acc ^ sum) s>= 0))) goto <nosat>;\n"
                     "  sum = (acc s>> 63) ^ 0x7fffffffffffffff;\n  sat = 1;\n<nosat>\n")
        code += "  w = sum;\n"
    code += "  r56 = w(4);\n  mlo = w:4;\n  "
    if result_high:
        code += "vr = w(4);" + ("" if accumulate else "\n  local sat:1 = 0;")
    elif accumulate:
        code += "local w2:8 = w;\n  w = w2;\n  " + SAT64.replace("local sat:1 =", "sat = sat ||")
    else:
        code += SAT64
    return code


# (major, sub-opcode, name, cpus, res, flags)
#   cpus: "67" both, "6" ARC600 only, "7" ARC700 only (informational)
ALU3 = [
    (4, 0x00, "add", "67", "vr = vb + vc;", "local vt:4 = vc;\n  " + ADD_F),
    (4, 0x01, "adc", "67", "vr = vb + vc + zext(C);",
     "local w:8 = zext(vb) + zext(vc) + zext(C);\n  C = (w >> 32) != 0;\n  V = ((vb ^ vr) & (vc ^ vr)) s< 0;\n  " + ZN),
    (4, 0x02, "sub", "67", "vr = vb - vc;", "local vt:4 = vc;\n  " + SUB_F),
    (4, 0x03, "sbc", "67", "vr = vb - vc - zext(C);",
     "local w:8 = zext(vb) - zext(vc) - zext(C);\n  C = (w >> 32) != 0;\n  V = ((vb ^ vc) & (vb ^ vr)) s< 0;\n  " + ZN),
    (4, 0x04, "and", "67", "vr = vb & vc;", ZN),
    (4, 0x05, "or", "67", "vr = vb | vc;", ZN),
    (4, 0x06, "bic", "67", "vr = vb & ~vc;", ZN),
    (4, 0x07, "xor", "67", "vr = vb ^ vc;", ZN),
    (4, 0x08, "max", "67", "vr = vb;\n  if (vb s>= vc) goto <keep>;\n  vr = vc;\n<keep>",
     "local d:4 = vb - vc;\n  Z = vb == vc;\n  N = d s< 0;\n  C = vc s>= vb;\n  V = sborrow(vb, vc);"),
    (4, 0x09, "min", "67", "vr = vb;\n  if (vb s<= vc) goto <keep>;\n  vr = vc;\n<keep>",
     "local d:4 = vb - vc;\n  Z = vb == vc;\n  N = d s< 0;\n  C = vc s<= vb;\n  V = sborrow(vb, vc);"),
    (4, 0x0e, "rsub", "67", "vr = vc - vb;", "local vt:4 = vb;\n  vb = vc;\n  " + SUB_F),
    (4, 0x0f, "bset", "67", "vr = vb | (1:4 << (vc & 31));", ZN),
    (4, 0x10, "bclr", "67", "vr = vb & ~(1:4 << (vc & 31));", ZN),
    (4, 0x12, "bxor", "67", "vr = vb ^ (1:4 << (vc & 31));", ZN),
    (4, 0x13, "bmsk", "67", "vr = vb & ((1:4 << ((vc & 31) + 1)) - 1);", ZN),
    (4, 0x14, "add1", "67", "vr = vb + (vc << 1);", "local vt:4 = vc << 1;\n  " + ADD_F),
    (4, 0x15, "add2", "67", "vr = vb + (vc << 2);", "local vt:4 = vc << 2;\n  " + ADD_F),
    (4, 0x16, "add3", "67", "vr = vb + (vc << 3);", "local vt:4 = vc << 3;\n  " + ADD_F),
    (4, 0x17, "sub1", "67", "vr = vb - (vc << 1);", "local vt:4 = vc << 1;\n  " + SUB_F),
    (4, 0x18, "sub2", "67", "vr = vb - (vc << 2);", "local vt:4 = vc << 2;\n  " + SUB_F),
    (4, 0x19, "sub3", "67", "vr = vb - (vc << 3);", "local vt:4 = vc << 3;\n  " + SUB_F),
    (4, 0x1a, "mpy", "7", "local p:8 = sext(vb) * sext(vc);\n  vr = p:4;",
     ZN + "\n  V = sext(vr) != p;"),
    (4, 0x1b, "mpyh", "7", "local p:8 = sext(vb) * sext(vc);\n  vr = p(4);", ZN + "\n  V = 0;"),
    (4, 0x1c, "mpyhu", "7", "local p:8 = zext(vb) * zext(vc);\n  vr = p(4);", ZN + "\n  V = 0;"),
    (4, 0x1d, "mpyu", "7", "local p:8 = zext(vb) * zext(vc);\n  vr = p:4;", ZN + "\n  V = (p >> 32) != 0;"),
    (4, 0x3e, "mpyw", "6", "vr = sext(vb:2) * sext(vc:2);", ZN + "\n  V = 0;"),
    (4, 0x3f, "mpyuw", "6", "vr = zext(vb:2) * zext(vc:2);", ZN + "\n  V = 0;"),
    # major 5: extension ALU operations of ARC600/ARC700
    (5, 0x00, "asl", "67", "vr = vb << (vc & 31);",
     "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (32 - s)) & 1) != 0);\n  " + ZN),
    (5, 0x01, "lsr", "67", "vr = vb >> (vc & 31);",
     "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    (5, 0x02, "asr", "67", "vr = vb s>> (vc & 31);",
     "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    (5, 0x03, "ror", "67", "local s:4 = vc & 31;\n  vr = (vb >> s) | (vb << ((32 - s) & 31));",
     "C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    (5, 0x06, "adds", "67", "local w:8 = sext(vb) + sext(vc);\n  " + SAT, "C = 0;\n  " + VS),
    (5, 0x07, "subs", "67", "local w:8 = sext(vb) - sext(vc);\n  " + SAT, "C = 0;\n  " + VS),
    # DIVAW (PRM): one step of a 16-bit restoring division
    (5, 0x08, "divaw", "67", "vr = 0;\n  if (vb == 0) goto <z>;\n  local t:4 = vb << 1;\n  vr = t;\n"
     "  if ((t - vc) s< 0) goto <z>;\n  vr = (t - vc) | 1;\n<z>", ""),
    (5, 0x0a, "asls", "67", sat_shift(SHL, SHR), VS),
    (5, 0x0b, "asrs", "67", sat_shift(SHR, SHL), VS),
    (5, 0x26, "adcs", "67", "local w:8 = sext(vb) + sext(vc) + zext(C);\n  " + SAT, "C = 0;\n  " + VS),
    (5, 0x27, "sbcs", "67", "local w:8 = sext(vb) - sext(vc) - zext(C);\n  " + SAT, "C = 0;\n  " + VS),
    (5, 0x28, "addsdw", "67", satdw("+"), VS),
    (5, 0x29, "subsdw", "67", satdw("-"), VS),
    (5, 0x30, "mululw", "67", xmac("(vc & 0xffff)", False, True, False), VS),
    (5, 0x31, "mullw", "67", xmac("(vc & 0xffff)", False, False, False), VS),
    (5, 0x33, "maclw", "67", xmac("(vc & 0xffff)", True, False, False), VS),
    (5, 0x35, "machulw", "67", xmac("(vc & 0xffff0000)", True, True, True), VS),
    (5, 0x36, "machlw", "67", xmac("(vc & 0xffff0000)", True, False, True), VS),
    # FPX single precision (ARC700)
    (6, 0x00, "fmul", "7", "vr = vb f* vc;", ZN),
    (6, 0x01, "fadd", "7", "vr = vb f+ vc;", ZN),
    (6, 0x02, "fsub", "7", "vr = vb f- vc;", ZN),
]

# DSP / FPX / SIMD extension operations modelled as named pcodeops (a = op(b, c))
PCODEOPS3 = [
    (5, 0x09, "minidl", "6"), (5, 0x0c, "muldw", "67"),
    (5, 0x0d, "muludw", "67"), (5, 0x0e, "mulrdw", "67"), (5, 0x0f, "maxidl", "6"),
    (5, 0x10, "macdw", "67"), (5, 0x11, "macudw", "67"), (5, 0x12, "macrdw", "67"),
    (5, 0x14, "msubdw", "67"), (5, 0x18, "mult", "6"), (5, 0x19, "mulut", "6"),
    (5, 0x1a, "mulrt", "6"), (5, 0x1c, "mact", "6"), (5, 0x1e, "macrt", "6"),
    (5, 0x20, "msubt", "6"), (5, 0x21, "asldw", "6"), (5, 0x22, "asrdw", "6"),
    (5, 0x23, "lsrdw", "6"), (5, 0x24, "aslsdw", "6"), (5, 0x25, "asrsdw", "6"),
    (5, 0x2b, "maxabssdw", "6"),
    (5, 0x2c, "crc", "67"), 
    (5, 0x32, "mulflw", "67"), (5, 0x34, "macflw", "67"),
    (5, 0x37, "machflw", "67"),
    (5, 0x38, "mulhlw", "67"), (5, 0x39, "mulhflw", "67"), (5, 0x3a, "dmulpf", "6"),
    (5, 0x3b, "dmacpf", "6"),
    # major 6 (ARC700): FPX single/double precision assist and SIMD byte operations
    
    (6, 0x08, "dmulh11", "7"), (6, 0x09, "dmulh12", "7"), (6, 0x0a, "dmulh21", "7"),
    (6, 0x0b, "dmulh22", "7"), (6, 0x0c, "daddh11", "7"), (6, 0x0d, "daddh12", "7"),
    (6, 0x0e, "daddh21", "7"), (6, 0x0f, "daddh22", "7"), (6, 0x10, "dsubh11", "7"),
    (6, 0x11, "dsubh12", "7"), (6, 0x12, "dsubh21", "7"), (6, 0x13, "dsubh22", "7"),
    (6, 0x14, "drsubh11", "7"), (6, 0x15, "drsubh12", "7"), (6, 0x16, "drsubh21", "7"),
    (6, 0x17, "drsubh22", "7"), (6, 0x18, "dexcl1", "7"), (6, 0x19, "dexcl2", "7"),
    (6, 0x20, "pkqb", "7"), (6, 0x21, "upkqb", "7"), (6, 0x22, "xpkqb", "7"),
    (6, 0x23, "avgqb", "7"), (6, 0x24, "addqbs", "7"), (6, 0x25, "mpyqb", "7"),
    (6, 0x26, "fxtr", "7"), (6, 0x27, "iaddr", "7"), (6, 0x28, "acm", "7"),
    (6, 0x29, "sfxtr", "7"), (6, 0x2a, "clamp", "7"),
]

# two-operand flag-setting operations: name b,c (F must be 1)
FLAGONLY = [
    (0x0b, "tst", "local vr:4 = vb & vc;\n  " + ZN),
    (0x0c, "cmp", "local vr:4 = vb - vc;\n  Z = vb == vc;\n  N = vr s< 0;\n  C = vb < vc;\n  V = sborrow(vb, vc);"),
    (0x0d, "rcmp", "local vr:4 = vc - vb;\n  Z = vb == vc;\n  N = vr s< 0;\n  C = vc < vb;\n  V = sborrow(vc, vb);"),
    (0x11, "btst", "local vr:4 = vb & (1:4 << (vc & 31));\n  " + ZN),
]

# single-operand operations (sub-opcode 0x2f, sub-sub-opcode in the a field): name b,c
SINGLE = [
    (4, 0x00, "asl", "vr = vc << 1;", "C = vc s< 0;\n  V = (vc ^ vr) s< 0;\n  " + ZN),
    (4, 0x01, "asr", "vr = vc s>> 1;", "C = (vc & 1) != 0;\n  " + ZN),
    (4, 0x02, "lsr", "vr = vc >> 1;", "C = (vc & 1) != 0;\n  " + ZN),
    (4, 0x03, "ror", "vr = (vc >> 1) | (vc << 31);", "C = (vc & 1) != 0;\n  " + ZN),
    (4, 0x04, "rrc", "vr = (vc >> 1) | (zext(C) << 31);", "C = (vc & 1) != 0;\n  " + ZN),
    (4, 0x05, "sexb", "vr = sext(vc:1);", ZN),
    (4, 0x06, "sexw", "vr = sext(vc:2);", ZN),
    (4, 0x07, "extb", "vr = zext(vc:1);", ZN),
    (4, 0x08, "extw", "vr = zext(vc:2);", ZN),
    (4, 0x09, "abs", "vr = vc;\n  if (vc s>= 0) goto <pos>;\n  vr = -vc;\n<pos>",
     "Z = vc == 0;\n  N = vc == 0x80000000;\n  C = vc s< 0;\n  V = vc == 0x80000000;"),
    (4, 0x0a, "not", "vr = ~vc;", ZN),
    (4, 0x0b, "rlc", "vr = (vc << 1) | zext(C);", "C = vc s< 0;\n  " + ZN),
    # major 5
    (5, 0x00, "swap", "vr = (vc << 16) | (vc >> 16);", ZN),
    (5, 0x01, "norm", "local t:4 = vc;\n  if (vc s>= 0) goto <pos>;\n  t = ~vc;\n<pos>\n  vr = lzcount(t) - 1;",
     "Z = vc == 0;\n  N = vc s< 0;"),
    (5, 0x02, "sat16", "vr = vc;\n  if (vc s<= 0x7fff) goto <nothigh>;\n  vr = 0x7fff;\n<nothigh>\n"
     "  if (vc s>= -0x8000) goto <notlow>;\n  vr = 0xffff8000;\n<notlow>\n  local sat:1 = vr != vc;",
     VS),
    (5, 0x03, "rnd16", "local sat:1 = (vc s>= 0x7fff8000);\n  vr = (vc + 0x8000) s>> 16;\n"
     "  if (!sat) goto <ok>;\n  vr = 0x7fff;\n<ok>", VS),
    (5, 0x04, "abssw", "local h:2 = vc:2;\n  local sat:1 = h == 0x8000;\n  if (h s>= 0) goto <pos>;\n  h = -h;\n<pos>\n"
     "  vr = zext(h);\n  if (!sat) goto <ok>;\n  vr = 0x7fff;\n<ok>",
     "Z = vc == 0;\n  N = vc s< 0;\n  V = sat;\n  S = S || sat;"),
    (5, 0x05, "abss", "vr = vc;\n  local sat:1 = vc == 0x80000000;\n  if (vc s>= 0) goto <pos>;\n  vr = -vc;\n"
     "  if (!sat) goto <pos>;\n  vr = 0x7fffffff;\n<pos>",
     "Z = vc == 0;\n  N = vc s< 0;\n  V = sat;\n  S = S || sat;"),
    (5, 0x06, "negsw", "local h:4 = sext(vc:2);\n  local sat:1 = h == -0x8000;\n  vr = -h;\n"
     "  if (!sat) goto <ok>;\n  vr = 0x7fff;\n<ok>", VS),
    (5, 0x07, "negs", "vr = -vc;\n  local sat:1 = vc == 0x80000000;\n  if (!sat) goto <ok>;\n  vr = 0x7fffffff;\n<ok>",
     VS),
    (5, 0x08, "normw", "local h:2 = vc:2;\n  if (h s>= 0) goto <pos>;\n  h = ~h;\n<pos>\n  local lz:4 = lzcount(h);\n  vr = lz - 1;",
     "Z = vc:2 == 0;\n  N = vc:2 s< 0;"),
    (5, 0x09, "swape", "vr = (vc << 24) | ((vc & 0xff00) << 8) | ((vc >> 8) & 0xff00) | (vc >> 24);", ZN),
    (5, 0x0a, "vbfdw", None, None),
    (5, 0x0b, "fbfdw", None, None),
    (6, 0x1a, "rtsc", None, None),
]


def b_dst_src():
    return "l_b_dst"


def gen():
    out = []
    w = out.append
    w("# Generated by tools/gen_arcompact.py; do not edit.\n")
    pcodeops = sorted({n for _, _, n, _ in PCODEOPS3} | {n for _, _, n, r, _ in SINGLE if r is None})
    for n in pcodeops:
        w(f"define pcodeop {n};")
    w("")
    # ---- three-operand ALU
    w("# Three-operand general operations: <op>[.f][.cc] a,b,c")
    for maj, sub, name, cpus, res, flags in ALU3:
        if res is None:
            continue
        pat = f"l_major=0x{maj:02x} & l_sub6=0x{sub:02x}"
        for f in (0, 1):
            mn = name + (".f" if f else "")
            w(f":{mn}^ccu op4_a, op4_b_src, op4_c_src is (({pat} & l_F={f} & ccu & op4_a) ... & op4_b_src & op4_c_src) {{")
            w("  if (!ccu) goto <skip>;")
            w("  local vb:4 = op4_b_src;\n  local vc:4 = op4_c_src;\n  local vr:4;")
            w("  " + res)
            if f:
                w("  " + flags)
            w("  op4_a = vr;")
            w("<skip>\n}")
    for maj, sub, name, cpus in PCODEOPS3:
        pat = f"l_major=0x{maj:02x} & l_sub6=0x{sub:02x}"
        if name in ("dmulpf", "dmacpf"):
            pat += " & (l_fmt=0 | (l_fmt=3 & l_M=0))"
        for f in (0, 1):
            mn = name + (".f" if f else "")
            w(f":{mn}^ccu op4_a, op4_b_src, op4_c_src is (({pat} & l_F={f} & ccu & op4_a) ... & op4_b_src & op4_c_src) {{")
            w("  if (!ccu) goto <skip>;")
            w(f"  local vr:4 = {name}(op4_b_src, op4_c_src);")
            if f:
                w("  " + ZN)
            w("  op4_a = vr;")
            w("<skip>\n}")
    # neg = rsub a,b,0 (format 1 or format 3 with u6, c = 0)
    w("# neg a,b = rsub a,b,0")
    for f in (0, 1):
        mn = "neg" + (".f" if f else "")
        w(f":{mn}^ccu op4_a, op4_b_src is ((l_major=0x04 & l_sub6=0x0e & l_F={f} & ((l_fmt=1) | (l_fmt=3 & l_M=1)) & l_u6=0 & ccu & op4_a) ... & op4_b_src) {{")
        w("  if (!ccu) goto <skip>;\n  local vb:4 = op4_b_src;\n  local vr:4 = -vb;")
        if f:
            w("  local vt:4 = vb;\n  vb = 0;\n  " + SUB_F)
        w("  op4_a = vr;\n<skip>\n}")
    # mul64/mulu64 (ARC600): result in mlo/mmid/mhi, a must be 62 in formats 0 and 1
    w("# mul64/mulu64 0,b,c (ARC600): 64-bit product in mlo (low), mhi (high), mmid (middle)")
    for sub, name, ext in ((0x04, "mul64", "sext"), (0x05, "mulu64", "zext")):
        w(f":{name}^ccu \"0\", op4_b_src, op4_c_src is ((l_major=0x05 & l_sub6=0x{sub:02x} & l_F=0 & ccu & ((l_fmt=0 & l_a=62) | (l_fmt=1 & l_a=62) | l_fmt=2 | l_fmt=3)) ... & op4_b_src & op4_c_src) {{")
        w(f"  if (!ccu) goto <skip>;\n  local p:8 = {ext}(op4_b_src) * {ext}(op4_c_src);")
        w("  mlo = p:4;\n  mmid = p(2);\n  mhi = p(4);\n<skip>\n}")
    # mov b,c (all formats write b)
    w("# mov b,c; nop = mov 0,0 (format 1)")
    for f in (0, 1):
        mn = "mov" + (".f" if f else "")
        w(f":{mn}^ccu l_b_dst, op4_c_src is ((l_major=0x04 & l_sub6=0x0a & l_F={f} & ccu & l_b_dst) ... & op4_c_src) {{")
        w("  if (!ccu) goto <skip>;\n  local vr:4 = op4_c_src;")
        if f:
            w("  " + ZN)
        w("  l_b_dst = vr;\n<skip>\n}")
    w(":nop is l_major=0x04 & l_sub6=0x0a & l_F=0 & l_fmt=1 & l_b_hi=7 & l_b_lo_7=6 & l_u6=0 & l_a=0 { }")
    # flag-only
    w("# tst/cmp/rcmp/btst b,c (F is always 1)")
    for sub, name, body in FLAGONLY:
        w(f":{name}^ccu op4_b_src, op4_c_src is ((l_major=0x04 & l_sub6=0x{sub:02x} & l_F=1 & ccu & ((l_fmt=0 & l_a=0) | (l_fmt=1 & l_a=0) | l_fmt=2 | l_fmt=3)) ... & op4_b_src & op4_c_src) {{")
        w("  if (!ccu) goto <skip>;\n  local vb:4 = op4_b_src;\n  local vc:4 = op4_c_src;")
        w("  " + body + "\n<skip>\n}")
    # single operand
    w("# Single-operand operations (sub-opcode 0x2f, formats 0 and 1): <op>[.f] b,c")
    for maj, sub, name, res, flags in SINGLE:
        pat = f"l_major=0x{maj:02x} & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x{sub:02x}"
        fs = (0, 1) if name != "rtsc" else (0,)
        for f in fs:
            mn = name + (".f" if f else "")
            fpat = f" & l_F={f}" if name != "rtsc" else ""
            w(f":{mn} l_b_dst, op4_c_src is (({pat}{fpat} & l_b_dst) ... & op4_c_src) {{")
            if res is None:
                w(f"  local vr:4 = {name}(op4_c_src);")
                if f:
                    w("  " + ZN)
            else:
                w("  local vc:4 = op4_c_src;\n  local vr:4;\n  " + res)
                if f:
                    w("  " + flags)
            w("  l_b_dst = vr;\n}")
    # ex / llock / scond (ARC700; bit 15 is .di)
    w("# ex/llock/scond b,[c] (ARC700; bit 15 is .di)")
    w(":ex^F_di l_b_dst, \"[\"^op4_c_src^\"]\" is ((l_major=0x04 & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x0c & F_di & l_b_dst) ... & op4_c_src) {")
    w("  local addr:4 = op4_c_src;\n  local old:4 = l_b_dst;\n  l_b_dst = *[ram]:4 addr;\n  *[ram]:4 addr = old;\n}")
    w(":ex^F_di l_b_src, \"[\"^op4_c_src^\"]\" is ((l_major=0x04 & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x0c & F_di & l_b_hi=7 & l_b_lo_7=6) ... & l_b_src & op4_c_src) {")
    w("  local addr:4 = op4_c_src;\n  *[ram]:4 addr = l_b_src;\n}")
    w(":llock^F_di l_b_dst, \"[\"^op4_c_src^\"]\" is ((l_major=0x04 & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x10 & F_di & l_b_dst) ... & op4_c_src) {")
    w("  local addr:4 = op4_c_src;\n  l_b_dst = *[ram]:4 addr;\n  LF = 1;\n}")
    w("# scond stores only while the lock flag set by llock is still set (cleared by an intervening")
    w("# store to the address or an interrupt, which a single-threaded p-code model never sees)")
    w(":scond^F_di l_b_src, \"[\"^op4_c_src^\"]\" is ((l_major=0x04 & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x11 & F_di) ... & l_b_src & op4_c_src) {")
    w("  local addr:4 = op4_c_src;\n  local v:4 = l_b_src;\n  Z = LF;\n  if (!LF) goto <fail>;\n  *[ram]:4 addr = v;\n<fail>\n  LF = 0;\n}")
    # zero-operand (a = 0x3f)
    w("# Zero-operand operations (sub-opcode 0x2f, a = 0x3f, operation in b)")
    w(":sleep op4_c_src is ((l_major=0x04 & l_sub6=0x2f & (l_fmt=0 | l_fmt=1) & l_a=0x3f & l_F=0 & l_b_hi=0 & l_b_lo_0=1) ... & op4_c_src) {\n  sleep(op4_c_src);\n}")
    w("# trap0 (ARC700; swi on ARC600): software interrupt, returns to the next instruction")
    w(":trap0 is l_major=0x04 & l_sub6=0x2f & l_fmt=1 & l_a=0x3f & l_F=0 & l_b_hi=0 & l_b_lo_0=2 & l_u6=0 {\n  swi();\n}")
    w(":sync is l_major=0x04 & l_sub6=0x2f & l_fmt=1 & l_a=0x3f & l_F=0 & l_b_hi=0 & l_b_lo_0=3 & l_u6=0 {\n  sync();\n}")
    w("# rtie (ARC700, PRM): return from exception (STATUS32.AE, bit 5) or level 2/1 interrupt (A2/A1)")
    w(":rtie is l_major=0x04 & l_sub6=0x2f & l_fmt=1 & l_a=0x3f & l_F=0 & l_b_hi=0 & l_b_lo_0=4 & l_u6=0 {")
    w("""  local st:4 = *[auxregs]:4 (0x0a:2);
  local npc:4 = *[auxregs]:4 (0x400:2);
  local nst:4 = *[auxregs]:4 (0x402:2);
  local nbta:4 = *[auxregs]:4 (0x401:2);
  if ((st & 0x20) != 0) goto <done>;
  if ((st & 0x4) == 0) goto <l1>;
  npc = ilink2;
  nst = *[auxregs]:4 (0x0c:2);
  nbta = *[auxregs]:4 (0x414:2);
  goto <done>;
<l1>
  if ((st & 0x2) == 0) goto <done>;
  npc = ilink1;
  nst = *[auxregs]:4 (0x0b:2);
  nbta = *[auxregs]:4 (0x413:2);
<done>
  *[auxregs]:4 (0x0a:2) = nst;
  *[auxregs]:4 (0x412:2) = nbta;
  restore_flags(nst);
  pcl = npc;
  return [pcl];
}""")
    w(":brk is l_major=0x04 & l_sub6=0x2f & l_fmt=1 & l_a=0x3f & l_F=0 & l_b_hi=0 & l_b_lo_0=5 & l_u6=0 {\n  brk();\n}")
    # generic extension instructions
    w("# Other operations of the extension majors 0x05-0x08: generic extension instruction")
    for maj in (5, 6, 7, 8):
        w(f"define pcodeop ext{maj:02x};")
        for f in (0, 1):
            mn = f"EXT{maj:02X}" + (".f" if f else "")
            w(f":{mn}^ccu l_sub6, op4_a, op4_b_src, op4_c_src is ((l_major=0x{maj:02x} & l_F={f} & l_sub6 & ccu & op4_a) ... & op4_b_src & op4_c_src) {{")
            w(f"  if (!ccu) goto <skip>;\n  local op:1 = l_sub6;\n  local vr:4 = ext{maj:02x}(op, op4_b_src, op4_c_src);")
            if f:
                w("  " + ZN)
            w("  op4_a = vr;\n<skip>\n}")
    # compare and branch
    w("# Branch on compare / bit test, 0x01 bit 16 = 1: <op>[.d] b,c,s9 (c with bit 4 = 0, u6 with bit 4 = 1)")
    w("br_c: l_c_src is l_R4=0 ... & l_c_src { export l_c_src; }")
    w("br_c: l_u6 is l_R4=1 & l_u6 { export *[const]:4 l_u6; }")
    w("# valid operand combinations: no long immediate with a delay slot, not both operands limm")
    for cond in ("l_b_hi!=7 & l_R4=1", "l_b_hi!=7 & l_R4=0 & l_u6!=62",
                 "l_b_hi=7 & l_b_lo_7!=6 & l_R4=1", "l_b_hi=7 & l_b_lo_7!=6 & l_R4=0 & l_u6!=62",
                 "l_N=0 & l_b_hi=7 & l_b_lo_7=6 & l_R4=1", "l_N=0 & l_b_hi=7 & l_b_lo_7=6 & l_R4=0 & l_u6!=62",
                 "l_N=0 & l_b_hi!=7 & l_R4=0 & l_c=62", "l_N=0 & l_b_hi=7 & l_b_lo_7!=6 & l_R4=0 & l_c=62",
                 # bbit0/bbit1 limm,limm (accepted by objdump, unlike brcc limm,limm)
                 "l_N=0 & l_brop=14 & l_b_hi=7 & l_b_lo_7=6 & l_R4=0 & l_c=62",
                 "l_N=0 & l_brop=15 & l_b_hi=7 & l_b_lo_7=6 & l_R4=0 & l_c=62"):
        w(f"br_ok: is {cond} {{ }}")
    for op, name, cond in ((0, "breq", "vb == vc"), (1, "brne", "vb != vc"), (2, "brlt", "vb s< vc"),
                           (3, "brge", "vb s>= vc"), (4, "brlo", "vb < vc"), (5, "brhs", "vb >= vc"),
                           (14, "bbit0", "(vb & (1:4 << (vc & 31))) == 0"),
                           (15, "bbit1", "(vb & (1:4 << (vc & 31))) != 0")):
        for d in (0, 1):
            mn = name + (".d" if d else "")
            w(f":{mn} l_b_src, br_c, l_target_s9 is ((l_major=0x01 & l_bit16=1 & l_brop={op} & l_N={d} & br_ok & l_target_s9) ... & l_b_src & br_c) {{")
            w("  local vb:4 = l_b_src;\n  local vc:4 = br_c;")
            if d:
                w(f"  local t:1 = {cond};\n  delayslot(1);\n  if (t) goto l_target_s9;\n}}")
            else:
                w(f"  if ({cond}) goto l_target_s9;\n}}")
    return split_cc("\n".join(out) + "\n")


def split_cc(text):
    """Each constructor written with the ccu subtable becomes two: an unconditional one for
    formats 0-2 (no condition test in its p-code) and a conditional one for format 3."""
    res = []
    for block in re.split(r"(?m)^(?=:)", text):
        if "^ccu" not in block:
            res.append(block)
            continue
        head, rest = block.split("{", 1)
        body, tail = rest.split("\n}\n", 1)
        body += "\n"
        tail = "\n" + tail
        uh = head.replace("^ccu", "").replace("& ccu", "& l_fmt!=3")
        ub = body.replace("  if (!ccu) goto <skip>;\n", "").replace("<skip>\n", "")
        ch = head.replace("^ccu", "^ccd").replace("& ccu", "& l_fmt=3 & ccd")
        cb = body.replace("!ccu", "!ccd")
        res.append(uh + "{" + ub + "}\n")
        res.append(ch + "{" + cb + "}" + tail)
    return "".join(res)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/languages/ARCompact_ops.sinc"
    open(path, "w").write(gen())
