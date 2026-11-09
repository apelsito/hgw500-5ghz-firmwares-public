#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), assembled with GNU as.

  emu_tests.py <outdir> <bin-prefix> [--break N]
      <bin-prefix>: GNU toolchain prefix, e.g. .../bin/arc-linux- (needs as, ld, objcopy)
  -> emu_<cpu>_<e>.bin and emu_<cpu>_<e>.txt for cpu in arc700, arc600 and e in le, be

Each test is a short sequence at its own 0x100-aligned address followed by a "stop" label.
The .txt files have one line per test:
  <name> <start-hex> <stop-hex> <init: reg=val,...|-> <expect: reg=val,...>
Values are hex. A data area at 0x8000 (initially "D0" below) is part of the image.
--break N makes the expectation of test N wrong (to show that the check can fail).
"""
import os
import re
import subprocess
import sys

out, pre = sys.argv[1], sys.argv[2]
brk = int(sys.argv[sys.argv.index("--break") + 1]) if "--break" in sys.argv else -1
M = 0xffffffff

# data area at 0x8000: 16 bytes 00 01 02 ... 0f, then 0x80 0xff 0x7f 0x00, then zeros
D0 = bytes(range(16)) + bytes([0x80, 0xff, 0x7f, 0x00]) + bytes(44)


def word(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 4]
    return int.from_bytes(b, "little" if e == "le" else "big")


# (name, cpu, asm, init, expect); expect may be a function of the byte order
T = [
    ("add", "arc700", "add r0,r1,r2", {"r1": 5, "r2": 7}, {"r0": 12}),
    ("add.f_carry", "arc700", "add.f r0,r1,r2", {"r1": M, "r2": 1},
     {"r0": 0, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("add.f_overflow", "arc700", "add.f r0,r1,r2", {"r1": 0x7fffffff, "r2": 1},
     {"r0": 0x80000000, "Z": 0, "N": 1, "C": 0, "V": 1}),
    ("sub.f_borrow", "arc700", "sub.f r0,r1,r2", {"r1": 1, "r2": 2},
     {"r0": M, "Z": 0, "N": 1, "C": 1, "V": 0}),
    ("sub.f_overflow", "arc700", "sub.f r0,r1,r2", {"r1": 0x80000000, "r2": 1},
     {"r0": 0x7fffffff, "N": 0, "C": 0, "V": 1}),
    ("adc", "arc700", "add.f r0,r1,r2\n adc r3,r4,r5\n adc.f r6,r4,r5", {"r1": M, "r2": 1, "r4": 0x10, "r5": 0x20},
     {"r0": 0, "r3": 0x31, "r6": 0x31, "C": 0}),
    ("sbc", "arc700", "sub.f r0,r1,r2\n sbc.f r3,r4,r4", {"r1": 1, "r2": 2, "r4": 5},
     {"r3": M, "C": 1, "N": 1, "Z": 0}),
    ("logic", "arc700", "and r3,r1,r2\n or r4,r1,r2\n xor r5,r1,r2\n bic r6,r1,r2\n not r7,r1",
     {"r1": 0xf0f0, "r2": 0xff00}, {"r3": 0xf000, "r4": 0xfff0, "r5": 0x0ff0, "r6": 0x00f0, "r7": 0xffff0f0f}),
    ("max_min", "arc700", "max r3,r1,r2\n min r4,r1,r2\n max.f r5,r2,r1", {"r1": 0xfffffffb, "r2": 3},
     {"r3": 3, "r4": 0xfffffffb, "r5": 3, "Z": 0, "N": 0, "C": 0}),
    ("bitops", "arc700", "bset r2,r1,8\n bclr r3,r1,0\n bxor r4,r1,1\n bmsk r5,r1,1\n btst r1,4\n bmsk r6,r1,31",
     {"r1": 0x0f}, {"r2": 0x10f, "r3": 0xe, "r4": 0xd, "r5": 3, "Z": 1, "r6": 0x0f}),
    ("addn_subn", "arc700", "add1 r3,r1,r2\n add2 r4,r1,r2\n add3 r5,r1,r2\n sub3 r6,r1,r2", {"r1": 1, "r2": 2},
     {"r3": 5, "r4": 9, "r5": 17, "r6": 0xfffffff1}),
    ("rsub_neg", "arc700", "rsub r3,r1,r2\n neg r4,r1", {"r1": 3, "r2": 10}, {"r3": 7, "r4": 0xfffffffd}),
    ("cmp_cond_mov", "arc700", "cmp r1,r2\n mov.eq r3,1\n mov.ne r4,1\n mov.f.ge r5,r2", {"r1": 5, "r2": 5},
     {"r3": 1, "r4": 0, "r5": 5, "Z": 0, "N": 0}),
    ("rcmp_cond_add", "arc700", "rcmp r1,r2\n add.lt r3,r3,1\n add.gt r4,r4,1", {"r1": 7, "r2": 5},
     {"r3": 1, "r4": 0, "C": 1}),
    ("limm", "arc700", "mov r0,0x12345678\n add r1,r0,0x11111111\n add r2,0x10,r0", {},
     {"r0": 0x12345678, "r1": 0x23456789, "r2": 0x12345688}),
    ("mpy", "arc700", "mpyu r3,r1,r2\n mpyhu r4,r1,r2\n mpy r5,r6,r7\n mpyh r8,r6,r7",
     {"r1": 0x10000, "r2": 0x30000, "r6": 0xfffffffe, "r7": 3}, {"r3": 0, "r4": 3, "r5": 0xfffffffa, "r8": M}),
    ("shift_multi", "arc700", "asl r3,r1,4\n lsr r4,r1,4\n asr r5,r1,4\n ror r6,r1,4\n asr.f r7,r1,1",
     {"r1": 0x80000001}, {"r3": 0x10, "r4": 0x08000000, "r5": 0xf8000000, "r6": 0x18000000,
                          "r7": 0xc0000000, "C": 1, "N": 1}),
    ("shift_single", "arc700", "asl.f r3,r1\n lsr r4,r1\n ror r5,r1", {"r1": 0x80000001},
     {"r3": 2, "C": 1, "V": 1, "r4": 0x40000000, "r5": 0xc0000000}),
    ("rotate_carry", "arc700", "add.f 0,r1,r1\n rrc r3,r2\n rlc.f r4,r2", {"r1": 0x80000000, "r2": 2},
     {"r3": 0x80000001, "r4": 5, "C": 0}),
    ("extend_abs", "arc700", "sexb r2,r1\n sexw r3,r1\n extb r4,r1\n extw r5,r1\n abs r6,r7",
     {"r1": 0x80ff, "r7": 0xfffffff9}, {"r2": M, "r3": 0xffff80ff, "r4": 0xff, "r5": 0x80ff, "r6": 7}),
    ("norm", "arc700", "norm r3,r1\n norm r4,r2\n norm r5,r6\n normw r7,r1", {"r1": 1, "r2": 0, "r6": M},
     {"r3": 30, "r4": 31, "r5": 31, "r7": 14}),
    ("swap", "arc700", "swap r2,r1\n swape r3,r1", {"r1": 0x12345678}, {"r2": 0x56781234, "r3": 0x78563412}),
    ("saturate", "arc700", "adds.f r3,r1,r2\n subs r4,r5,r2\n negs r6,r5\n abss r7,r5\n sat16 r8,r9",
     {"r1": 0x7fffffff, "r2": 1, "r5": 0x80000000, "r9": 0x12345},
     {"r3": 0x7fffffff, "V": 1, "r4": 0x80000000, "r6": 0x7fffffff, "r7": 0x7fffffff, "r8": 0x7fff}),
    ("asls_asrs", "arc700", "asls r3,r1,4\n asls r4,r2,4\n asrs r5,r2,1", {"r1": 0x10000000, "r2": 0x10},
     {"r3": 0x7fffffff, "r4": 0x100, "r5": 8}),
    ("ld_st", "arc700", "mov r1,0x8000\n ld r3,[r1,4]\n ldb r4,[r1,5]\n ldh r5,[r1,6]\n st r1,[r1,32]\n ld r6,[r1,32]",
     {}, lambda e: {"r3": word(0x8004, e), "r4": 5, "r5": 0x0706 if e == "le" else 0x0607, "r6": 0x8000}),
    ("ld_sign", "arc700", "mov r1,0x8010\n ldb.x r3,[r1]\n ldb.x r4,[r1,2]\n ldh.x r5,[r1]",
     {}, lambda e: {"r3": 0xffffff80, "r4": 0x7f, "r5": 0xffffff80 if e == "le" else 0xffff80ff}),
    ("ld_writeback", "arc700", "mov r1,0x8000\n ld.aw r3,[r1,4]\n ld.ab r4,[r1,4]\n mov r2,0x8000\n ldh.as r5,[r2,2]",
     {}, lambda e: {"r1": 0x8008, "r3": word(0x8004, e), "r4": word(0x8004, e),
                    "r5": 0x0504 if e == "le" else 0x0405}),
    ("st_writeback", "arc700", "mov r1,0x8020\n mov r2,0x55\n st.aw r2,[r1,4]\n stb.ab r2,[r1,4]\n ld r3,[r1,-4]\n ldb r4,[r1,-4]",
     {}, lambda e: {"r1": 0x8028, "r3": 0x55 if e == "le" else 0x55000055, "r4": 0x55}),
    ("ld_regreg", "arc700", "mov r1,0x8000\n mov r2,2\n ld r3,[r1,r2]\n ld.as r4,[r1,r2]\n ldb r5,[r1,r2]",
     {}, lambda e: {"r3": word(0x8002, e), "r4": word(0x8008, e), "r5": 2}),
    ("short_ldst", "arc700", "mov_s r0,0x80\n asl_s r0,r0,8\n ld_s r1,[r0,4]\n ldb_s r2,[r0,3]\n ldw_s r3,[r0,2]\n st_s r1,[r0,40]\n ld r12,[r0,40]",
     {}, lambda e: {"r0": 0x8000, "r1": word(0x8004, e), "r2": 3, "r3": 0x0302 if e == "le" else 0x0203,
                    "r12": word(0x8004, e)}),
    ("push_pop", "arc700", "mov sp,0x8040\n push_s r1\n push_s blink\n pop_s r2\n pop_s r3",
     {"r1": 0x11, "blink": 0x22}, {"sp": 0x8040, "r2": 0x22, "r3": 0x11}),
    ("sp_rel", "arc700", "mov sp,0x8040\n sub_s sp,sp,8\n st_s r1,[sp,4]\n ld_s r2,[sp,4]\n add_s sp,sp,8",
     {"r1": 0x1234}, {"sp": 0x8040, "r2": 0x1234}),
    ("ex", "arc700", "mov r1,0x8020\n mov r3,0x99\n st r3,[r1]\n mov r2,0x42\n ex r2,[r1]\n ld r4,[r1]",
     {}, {"r2": 0x99, "r4": 0x42}),
    ("short_alu", "arc700", "mov_s r0,10\n add_s r1,r0,3\n mov_s r2,r0\n sub_s r2,r2,r1\n add_s r0,r0,0x20\n bset_s r1,r1,4\n mov_s r3,r0\n bmsk_s r3,r3,3\n neg_s r12,r1",
     {}, {"r0": 0x2a, "r1": 0x1d, "r2": M - 2, "r3": 0xa, "r12": 0xffffffe3}),
    ("sub_s.ne", "arc700", "cmp r1,0\n sub_s.ne r1,r1,r1\n cmp r2,1\n sub_s.ne r2,r2,r2", {"r1": 7, "r2": 1},
     {"r1": 0, "r2": 1}),
    ("branch", "arc700", "cmp r1,5\n beq 1f\n mov r2,1\n1: bne 2f\n mov r3,1\n2: b_s 3f\n mov r4,1\n3:",
     {"r1": 5}, {"r2": 0, "r3": 1, "r4": 0}),
    ("brcc", "arc700", "brne r1,5,1f\n mov r2,1\n1: breq r1,r3,2f\n mov r4,1\n2: brlt r1,10,3f\n mov r5,1\n3: brhs r1,r6,4f\n mov r7,1\n4:",
     {"r1": 5, "r3": 6, "r6": 0x10}, {"r2": 1, "r4": 1, "r5": 0, "r7": 1}),
    ("bbit", "arc700", "bbit0 r1,3,1f\n mov r2,1\n1: bbit1 r1,0,2f\n mov r3,1\n2: breq_s r12,0,3f\n mov r4,1\n3:",
     {"r1": 1, "r12": 0}, {"r2": 0, "r3": 0, "r4": 0}),
    ("delay_slot", "arc700", "mov r0,0\n b.d 1f\n add r0,r0,1\n add r0,r0,2\n1: beq.d 2f\n add r0,r0,4\n add r0,r0,8\n2:",
     {"Z": 0}, {"r0": 0xd}),
    ("call_return", "arc700", "bl 1f\n mov r3,r0\n b 2f\n1: mov r0,5\n j_s [blink]\n2:",
     {}, {"r0": 5, "r3": 5}),
    ("call_delay", "arc700", "bl.d 1f\n mov r2,7\n mov r3,r0\n b 2f\n1: mov r0,r2\n j_s.d [blink]\n add r0,r0,1\n2:",
     {}, {"r0": 8, "r2": 7, "r3": 8}),
    ("jl_indirect", "arc700", "mov r1,1f\n jl [r1]\n mov r3,r0\n b 2f\n1: mov r0,9\n j [blink]\n2:",
     {}, {"r3": 9}),
    ("loop", "arc700", "mov lp_count,5\n mov r0,0\n lp 1f\n add r0,r0,3\n add r1,r1,1\n1: mov r2,r0",
     {}, {"r0": 15, "r1": 5, "r2": 15}),
    ("aux_flag", "arc700", "sr r1,[0x30]\n lr r2,[0x30]\n flag 0xa00", {"r1": 0x1234},
     {"r2": 0x1234, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("divaw", "arc700", "divaw r3,r1,r2\n divaw r4,r5,r2\n divaw r6,r0,r2", {"r1": 2, "r2": 3, "r5": 1},
     {"r3": 1, "r4": 2, "r6": 0}),
    ("rnd16", "arc700", "rnd16 r3,r1\n rnd16.f r4,r2", {"r1": 0x18000, "r2": 0x7fffffff},
     {"r3": 2, "r4": 0x7fff, "V": 1, "S": 1}),
    ("abssw_negsw", "arc700", "abssw r3,r1\n abssw r4,r2\n negsw r5,r6\n negsw r7,r8",
     {"r1": 0xffff8000, "r2": 0xfffe, "r6": 5, "r8": 0x8000},
     {"r3": 0x7fff, "r4": 2, "r5": 0xfffffffb, "r7": 0x7fff}),
    ("dual_sat", "arc700", "addsdw.f r3,r1,r2\n subsdw r4,r5,r2", {"r1": 0x7fff0001, "r2": 0x00010002, "r5": 0x80000005},
     {"r3": 0x7fff0003, "V": 1, "S": 1, "r4": 0x80000003}),
    ("sat_shift", "arc700", "asls r3,r1,r2\n asls r4,r5,40\n asrs r6,r7,33\n asrs r8,r1,-2",
     {"r1": 0x100, "r2": 0xfffffffc, "r5": 1, "r7": 0x80000000}, {"r3": 0x10, "r4": 0x7fffffff, "r6": M, "r8": 0x400}),
    ("xmac", "arc700", "mullw r3,r1,r2\n maclw r4,r1,r5\n machlw r6,r7,r8\n mov r9,mlo",
     {"r1": 0x10000, "r2": 0x00030002, "r5": 2, "r7": 1, "r8": 0x30000},
     {"r3": 0x20000, "r4": 0x40000, "r6": 0, "r9": 0x70000, "r56": 0}),
    ("fpx", "arc700", "fmul r3,r1,r2\n fadd r4,r1,r2\n fsub r5,r1,r2", {"r1": 0x40000000, "r2": 0x3fc00000},
     {"r3": 0x40400000, "r4": 0x40600000, "r5": 0x3f000000}),
    ("llock_scond", "arc700", "mov r1,0x8020\n mov r2,0x77\n llock r3,[r1]\n scond r2,[r1]\n mov.eq r7,1\n ld r4,[r1]\n"
     " mov r5,0x99\n scond r5,[r1]\n ld r6,[r1]", {}, {"r4": 0x77, "r7": 1, "r6": 0x77, "Z": 0}),
    ("rtie", "arc700", "mov r1,1f\n sr r1,[0x400]\n mov r2,0x800\n sr r2,[0x402]\n mov r4,0x20\n sr r4,[0xa]\n"
     " rtie\n mov r5,1\n1: lr r6,[0xa]", {}, {"r5": 0, "r6": 0x800, "Z": 1}),
    ("normw_zero", "arc700", "normw r3,r1\n normw r4,r2", {"r1": 0, "r2": 0xffff}, {"r3": 15, "r4": 15}),
    ("mul64", "arc600", "mul64 r1,r2\n mulu64 r3,r2\n mov r4,mlo\n mul64_s r1,r1\n mov r5,mhi",
     {"r1": 0xfffffffe, "r2": 3, "r3": 0x80000000}, {"r4": 0x80000000, "mhi": 0, "mlo": 4, "r5": 0}),
    ("mpyw", "arc600", "mpyw r3,r1,r2\n mpyuw r4,r1,r2", {"r1": 0x1ffff, "r2": 3}, {"r3": 0xfffffffd, "r4": 0x2fffd}),
]


def build(cpu, e):
    tests = [t for t in T if t[1] == cpu]
    src = [" .text"]
    for i, (name, _, asm, _, _) in enumerate(tests):
        src.append(f" .org {i * 0x100:#x}\nT{i}: {asm}\nS{i}: nop\n")
    src.append(" .org 0x8000\n .byte " + ",".join(str(b) for b in D0))
    base = f"{out}/emu_{cpu}_{e}"
    open(base + ".s", "w").write("\n".join(src) + "\n")
    eb = ["-EB"] if e == "be" else []
    subprocess.run([pre + "as", "-mcpu=" + cpu] + (["-mspfp"] if cpu == "arc700" else []) + eb + [base + ".s", "-o", base + ".o"], check=True)
    subprocess.run([pre + "ld"] + eb + ["-Ttext=0", "-e", "0", base + ".o", "-o", base + ".elf"], check=True)
    subprocess.run([pre + "objcopy", "-O", "binary", base + ".elf", base + ".bin"], check=True)
    syms = {}
    for line in subprocess.run([pre + "nm", base + ".elf"], capture_output=True, text=True).stdout.split("\n"):
        m = re.match(r"([0-9a-f]+) \w (\w+)$", line)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    with open(base + ".txt", "w") as f:
        for i, (name, _, _, init, exp) in enumerate(tests):
            exp = exp(e) if callable(exp) else dict(exp)
            k = T.index(tests[i])
            if k == brk:
                r = next(iter(exp))
                exp[r] ^= 1
            ini = ",".join(f"{r}={v & M:x}" for r, v in init.items()) or "-"
            f.write(f"{name} {syms['T%d' % i]:x} {syms['S%d' % i]:x} {ini} "
                    + ",".join(f"{r}={v & M:x}" for r, v in exp.items()) + "\n")
    for x in (".o", ".elf"):
        os.remove(base + x)


for cpu in ("arc700", "arc600"):
    for e in ("le", "be"):
        build(cpu, e)
print(f"{len(T)} tests")
