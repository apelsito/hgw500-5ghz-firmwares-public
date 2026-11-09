# Ghidra-Rare notes: ARCompact (ARC600/ARC700)

This is the Ghidra-Rare fork of Ghidra pull request
[#3006](https://github.com/NationalSecurityAgency/ghidra/pull/3006) (ARCompact support by
Nicolas Iooss). Ghidra-Rare tested it against GNU binutils, the ARCompact Programmer's
Reference and real ARC700 Linux binaries, and fixed what the tests found. Authors, upstream
commit and the list of changes are in [CREDITS.md](CREDITS.md); the upstream limitations and
their status are in [README.md](README.md). It targets Ghidra 12.1.4 and also builds on 12.1.3
and 12.2.

## What it covers

| Language ID | Description |
|---|---|
| `ARCompact:LE:32:default` | ARC600/ARC700, little-endian (32-bit instructions and long immediates stored as two halfwords, high halfword first) |
| `ARCompact:BE:32:default` | ARC600/ARC700, big-endian |

- Every ARC600 and ARC700 instruction in binutils 2.45's `opcodes/arc-tbl.h`: the base
  instruction set, the extended arithmetic library, the ARC600 `mul64`/`mpyw` and XMAC/DSP
  options, the ARC700 `mpy*`, `ex`, `llock`/`scond`, `rtie`, `trap0`/`trap_s`, FPX and SIMD
  extensions. Unknown sub-opcodes of the extension majors 5-8 decode as generic `EXTnn`
  instructions (these are user-defined extension instructions on ARC cores).
- Syntax: GNU objdump's (`ldh`/`sth`, `.aw`, `add.f.eq`, `j [blink]`, aux register names for
  `lr`/`sr` u6).
- Semantics: real p-code for the base instruction set (flags, carries, saturating arithmetic,
  loads and stores in every address mode, delay slots, zero-overhead `lp` loops, `j.f`/`rtie`
  returns), extended arithmetic, the XMAC 32x16 multiply-accumulate instructions and FPX single
  precision. Instructions with no architectural register effect (`sync`, `sleep`, `brk`,
  `trap0`, `trap_s`, `unimp_s`) and the extension instructions whose operation is not publicly
  documented (below) are named pcodeops; all fall through.
- Spec files: GCC calling convention (cspec per byte order), DWARF register map, ELF opinion
  (e_machine 93), pspec with the auxiliary register names, a relocation handler and PLT markup.

## Testing

Requirements: Ghidra (`GHIDRA_INSTALL_DIR`, with this directory as
`Ghidra/Processors/ARCompact`), GNU binutils 2.45 source and an `--enable-targets=all` build
(for `test/slotdis.c`, a small libopcodes driver), and an ARC GNU toolchain for the emulator
tests (`test/fetch-real-samples.sh <dir> --keep-toolchain` provides Bootlin's).

```
test/run-tests.sh [workdir]            # decode diff, every-entry test, emulator tests
test/fetch-real-samples.sh samples     # real binaries (pinned URLs and SHA-256)
REAL_SAMPLES=samples test/run-tests.sh # ... plus the real-binary analysis
test/reloc-check.sh <ld> <objdump> <workdir> test/elf/relocs_le.o
```

`test/env.sh` points Ghidra at a private settings directory, because the headless script runner
takes a user-wide lock that serialises parallel runs.

## Results

### Decoding vs GNU objdump 2.45

`test/gen_corpus.py` writes three corpora per byte order, in 10-byte slots (so every other slot
starts at an address that is 2 mod 4, which matters for PCL-relative operands); Ghidra
(`DumpSlots.java`) and libopcodes (`slotdis`, ARC700 and ARC600 decoders) decode the first
instruction of each slot, and `test/compare.py` scores them:

- `table`: every ARC600/ARC700 entry of `arc-tbl.h` with its free bits clear, set and six
  random fillings (20,224 slots);
- `half`: every 16-bit first halfword (65,536);
- `fuzz`: 50,000 random slots.

| Corpus | Both decode | Exact | Semantic | Unexplained differences |
|---|---|---|---|---|
| table LE | 16,065 | 82.98% | 100% | 0 |
| half LE | 49,217 | 95.76% | 100% | 0 |
| fuzz LE | 37,446 | 95.81% | 100% | 0 |
| table BE | 16,065 | 82.53% | 100% | 0 |
| half BE | 49,177 | 95.66% | 100% | 0 |
| fuzz BE | 37,426 | 95.71% | 100% | 0 |

"Semantic" allows these spellings: register names (objdump prints the ARCv2 names `ilink`,
`r30`, `r57`-`r59`, `reserved`; Ghidra the ARCompact names `ilink1`, `ilink2`, `mlo`, `mmid`,
`mhi`, `r61`), aux register names vs numbers, `swi` vs `trap0` (the same encoding),
`neg a,b` vs `rsub a,b,0`, `prefetch` vs `ld 0,[...]`, and extension condition codes, which
objdump drops from the text when they have no name (Ghidra prints `.e0x10` etc.). Not scored
(both are counted and listed by `compare.py`):

- words that objdump decodes only with its "disassembly may be wrong due to guessed opcode
  class choice" warning (optional major-6/7 extension classes): Ghidra agrees on all of them;
- EZchip NPS-400 instructions, which `objdump -m ARC700` always decodes (major opcodes
  0x09-0x0b and some major-5 forms): not ARC700 instructions.

Explained difference classes (68 slots in the LE table corpus, 4,000-5,500 in the others):

| Class | Why |
|---|---|
| Extension opcode space (majors 5-8): Ghidra decodes `EXTnn`, objdump rejects | user-defined extension instructions; decoded so their operands and destination are visible |
| `adcs`/`sbcs` `0,limm,c`: different operands | binutils table bug, see below |
| `cmacrdw` vs `adcs` | the same encoding in two options; Ghidra decodes `adcs` (extended arithmetic) |
| ARC700 SIMD and ARC600 `dmulpf`/`dmacpf`: Ghidra decodes, objdump rejects | operand forms missing from binutils' table (e.g. `mpyqb a,b,c`) |

The pull request agreed with objdump on 26.8% of the table corpus and about 70% of random
words before these changes.

**Every-entry test** (`CoverageCheck.java`): every constructor of both languages (884) is
reached by the decoder in at least one of four seeded runs; none is shadowed.

### Emulator

`test/emu_tests.py` assembles 56 short sequences with GNU as (54 ARC700, 2 ARC600) and
`EmuCheck.java` runs them in Ghidra's emulator with hand-computed expectations, in both byte
orders: add/sub with carry and overflow, `adc`/`sbc`, logic, `max`/`min`, bit operations,
`add1-3`/`sub1-3`, `rsub`/`neg`, conditional execution, long immediates, `mpy*`, multi-bit
and single-bit shifts and rotates through carry, extensions, `abs`, `norm`/`normw`, `swap`/
`swape`, saturating arithmetic and the `S` flag, `divaw`, `rnd16`, `abssw`/`negsw`,
`addsdw`/`subsdw`, `asls`/`asrs` with negative and large counts, XMAC multiply-accumulate,
FPX, loads/stores with every address mode and write-back, sign extension, register-register
loads, 16-bit loads/stores, `push_s`/`pop_s`, `ex`, `llock`/`scond`, branches, compare-and-
branch, `bbit0/1`, delay slots, `bl`/`bl.d`/`jl` calls and returns, `lp` loops, `lr`/`sr`/
`flag`, `rtie`, and ARC600 `mul64`/`mulu64`/`mul64_s`/`mpyw`/`mpyuw`. Result: 56/56 per byte
order. A deliberately wrong expectation (`--break`) is reported as a failure.

### Relocations

`test/elf/relocs.s` (code and data relocations against local and undefined symbols:
`S25W_PCREL`, `S25H_PCREL`, `S21H_PCREL`, `S21W_PCREL`, `S13_PCREL`, `32_ME`, `PC32`, `32`) is
assembled for both byte orders; `test/reloc-check.sh` imports each object (Ghidra applies the
relocations at addresses it chooses), links it with GNU ld at those addresses and compares the
bytes: 11/11 relocations applied, 68/68 bytes identical, LE and BE.

### Real binaries

`test/fetch-real-samples.sh` downloads three public ARC700 Linux toolchains (pinned URL and
SHA-256) and extracts their target libraries and programs; nothing is committed. All are built
from LGPL/GPL sources (uClibc-ng, libgcc/libstdc++/libatomic with the GCC runtime exception):

- Synopsys ARC GNU toolchain arc-2024.12, uClibc ARC700, little- and big-endian:
  `libuClibc-1.0.49.so`, `ld-uClibc`, `libgcc_s`, `libatomic`, `libstdc++` (19 MB, DWARF),
  `getconf`, `iconv`, `locale`, `ldconfig`;
- Bootlin `arcle-750d--uclibc--stable-2025.08-1`: `libuClibc-1.0.54.so`, `ld-uClibc`,
  `libgcc_s`, `libatomic`.

`test/real-binaries.sh` imports each one headless without `-processor` (the opinion picks the
language from e_machine 93 and the ELF byte order; shared objects are imported at their link
address so addresses match objdump), analyses it, decompiles every function and compares
every instruction Ghidra found with libopcodes at the same address (`test/realcmp.py`).

| Sample | Language | Functions | Instructions | Bad instr. | Error bookmarks | Decompiled | Disassembly vs objdump |
|---|---|---|---|---|---|---|---|
| `bl-le-ld-uClibc-1.0.54.so` | LE | 56 | 4,398 | 0 | 0 | 56 / 56 | 4,398 / 4,398 |
| `bl-le-libatomic.so.1.2.0` | LE | 119 | 1,821 | 0 | 0 | 99 / 99 | 1,821 / 1,821 |
| `bl-le-libgcc_s.so.1` | LE | 327 | 14,560 | 0 | 0 | 290 / 290 | 14,560 / 14,560 |
| `bl-le-libuClibc-1.0.54.so` | LE | 2,227 | 100,902 | 0 | 2 | 2,192 / 2,192 | 100,902 / 100,902 |
| `syn-be-getconf` | BE | 68 | 442 | 0 | 0 | 30 / 30 | 442 / 442 |
| `syn-be-iconv` | BE | 58 | 380 | 0 | 0 | 26 / 26 | 380 / 380 |
| `syn-be-ld-uClibc-1.0.49.so` | BE | 56 | 4,422 | 0 | 0 | 56 / 56 | 4,422 / 4,422 |
| `syn-be-ldconfig` | BE | 147 | 1,537 | 0 | 0 | 61 / 61 | 1,537 / 1,537 |
| `syn-be-libatomic.so.1.2.0` | BE | 116 | 2,710 | 0 | 0 | 98 / 98 | 2,710 / 2,710 |
| `syn-be-libgcc_s.so.1` | BE | 346 | 15,719 | 0 | 0 | 303 / 303 | 15,719 / 15,719 |
| `syn-be-libuClibc-1.0.49.so` | BE | 2,132 | 97,428 | 0 | 2 | 2,097 / 2,097 | 97,428 / 97,428 |
| `syn-be-locale` | BE | 63 | 636 | 0 | 0 | 29 / 29 | 636 / 636 |
| `syn-le-getconf` | LE | 68 | 442 | 0 | 0 | 30 / 30 | 442 / 442 |
| `syn-le-iconv` | LE | 58 | 380 | 0 | 0 | 26 / 26 | 380 / 380 |
| `syn-le-ld-uClibc-1.0.49.so` | LE | 56 | 4,423 | 0 | 0 | 56 / 56 | 4,423 / 4,423 |
| `syn-le-ldconfig` | LE | 147 | 1,537 | 0 | 0 | 61 / 61 | 1,537 / 1,537 |
| `syn-le-libatomic.so.1.2.0` | LE | 116 | 2,616 | 0 | 0 | 98 / 98 | 2,616 / 2,616 |
| `syn-le-libgcc_s.so.1` | LE | 346 | 15,728 | 0 | 0 | 303 / 303 | 15,728 / 15,728 |
| `syn-le-libuClibc-1.0.49.so` | LE | 2,132 | 97,549 | 0 | 2 | 2,097 / 2,097 | 97,549 / 97,549 |
| `syn-le-locale` | LE | 63 | 636 | 0 | 0 | 29 / 29 | 636 / 636 |
| **total** | | 8,701 | 368,266 | 0 | 6 | 8,037 / 8,037 | 100% |

The Synopsys toolchains also ship `libstdc++.so.6.0.33` (19 MB with DWARF), analysed on its own
because it takes about an hour: 6,091 functions, 302,490 instructions, all identical to objdump
(100% semantic, 0 unexplained), 0 bad instructions, 5,712 of 5,724 functions decompiled. The 12
failures are "Overlapping input varnodes" in libstdc++'s `__collate_*`/`__messages_close`
helpers: their first parameter is the empty C++ tag struct `current_abi`, and GCC's DWARF places
it in `r0` (`DW_OP_reg0`) while the next parameter's location list also starts in `r0`; Ghidra's
DWARF importer applies both storages. 99 error bookmarks: 97 are Ghidra's DWARF line-table
reader (`DWARFLineProgramExecutor`, not part of the module) producing negative line numbers, off
by a multiple of 256 (readelf decodes line 76 where Ghidra has -180), which its source-map
importer then rejects; 2 are
`R_ARC_TLS_DTPMOD`/`R_ARC_TLS_DTPOFF` (see Known gaps).

The 6 error bookmarks in the table are `R_ARC_TLS_TPOFF` relocations in uClibc (see Known gaps).

## Known gaps

- **Extension instructions without a public specification** are named pcodeops that read
  their sources and write their destination: the ARC600 XMAC dual-16-bit and fractional forms
  (`muldw`, `macdw`, `mulrdw`, `msubdw`, `mulflw`, `macflw`, `machflw`, `mulhlw`, `mulhflw`,
  `cmacrdw`, `mult`/`mac*t`/`msubt`, `asldw`/`asrdw`/`lsrdw`/`aslsdw`/`asrsdw`, `minidl`/
  `maxidl`, `maxabssdw`, `dmulpf`/`dmacpf`), `crc`, the Viterbi `vbfdw`/`fbfdw`, the ARC700
  FPX double-precision assist (`dmulh*`, `daddh*`, `dsubh*`, `drsubh*`, `dexcl*`) and the SIMD
  byte operations (`pkqb` ... `clamp`). Neither the ARCompact Programmer's Reference nor binutils
  describes what they compute (binutils only encodes them; the CGEN description covers only the
  32x16 XMAC forms, which are implemented). `rtsc` reads a hardware time-stamp counter.
- **Extension condition codes 16-31** and the generic `EXTnn` instructions call
  `ext_condition`/`extNN` pcodeops: they are defined by the customer's extension hardware.
- **TLS relocations** (`R_ARC_TLS_*`) are reported, not applied: Ghidra has no thread-local
  storage model. `R_ARC_COPY` is reported as for every Ghidra processor.
- **Indirect tail calls** (`j [r0]` through a function pointer) and hand-written assembly that
  returns through a copy of `blink` (`mov r7,blink; ... j.d [r7]` in libgcc's division
  routines) are shown by the decompiler as "treating indirect jump as call"; the decompiled C
  is correct. A jump table and an indirect tail call use the same instruction.
- **lp loops** need the loop-end context set by the `lp` instruction (`globalset`); Ghidra's
  `EmulatorHelper` handles it, the newer `PcodeEmulator` does not (Ghidra issue #9337).
- **DWARF input outside the module's control**: 12 libstdc++ functions whose GCC debug info
  puts two parameters in `r0` fail to decompile ("Overlapping input varnodes"), and Ghidra's
  DWARF line-table reader mis-computes some line numbers (error bookmarks); see Real binaries.
- `swi` (ARC600) and `trap0` (ARC700) share an encoding; it prints as `trap0`.
- The auxiliary register names of the pspec are ARC700's; a register number given as a long
  immediate or s12 prints as a number.

## Confirmed reference-tool bugs (binutils 2.45)

- `opcodes/arc-tbl.h`: the `adcs<.f> 0,limm,c` and `sbcs<.f> 0,limm,c` entries have operand
  format bits `01` (u6) instead of `00`, so objdump prints `adcs 0,limm,0x3` for
  `adcs 0,limm,r3` and rejects the real format-0 encoding.
- `opcodes/arc-tbl.h` lacks some operand forms of the ARC700 SIMD instructions (e.g.
  `mpyqb a,b,c`) and of ARC600 `dmulpf`/`dmacpf`; objdump prints them as `.word`.
- `objdump -m ARC700` always decodes the EZchip NPS-400 instructions (its ARC700 instruction
  length rule even makes majors 0x0a/0x0b 6 or 8 bytes long).
- objdump's `prefetch [b]` entry ignores the address-mode bits when the offset is 0; for
  `st limm,[b,s9]` with s9 = 0 it prints `[b,0]`.
