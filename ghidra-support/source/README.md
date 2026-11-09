# ARCompact (ARC600/ARC700) processor module for Ghidra

> Public source snapshot. [Scope, provenance and verification](docs/PUBLIC_SNAPSHOT.md).

Ghidra support for the Synopsys (formerly ARC International) ARCompact instruction set used by
the ARC600 and ARC700 cores: some versions of Intel's Management Engine, Lenovo ThinkPad
embedded controllers, Intel Wireless-AC chips, many network and storage SoCs and ARC700 Linux
systems.

It was written by Nicolas Iooss as Ghidra pull request
[#3006](https://github.com/NationalSecurityAgency/ghidra/pull/3006). This copy is the
Ghidra-Rare fork, which tested it against GNU binutils, the ARCompact Programmer's Reference and
real ARC700 Linux binaries and fixed what the tests found; see [GHIDRA-RARE.md](GHIDRA-RARE.md)
for the results and [CREDITS.md](CREDITS.md) for the authors and the list of changes. ARCv2
(ARC EM/HS) and the legacy 32-bit ARCtangent-A4 instruction sets are different ISAs and are not
covered here.

## Install

Download the zip for your Ghidra version from this repository's Releases page (built for
Ghidra 12.1.3, 12.1.4 and 12.2) and install it with *File > Install Extensions*. To build it
yourself: `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension`.

## Languages

| Language ID | Description | ELF auto-select |
|---|---|---|
| `ARCompact:LE:32:default` | ARC600/ARC700, little-endian | e_machine 93 (EM_ARC_COMPACT), ELF32 LSB |
| `ARCompact:BE:32:default` | ARC600/ARC700, big-endian | e_machine 93, ELF32 MSB |

Both cores share one language: their instruction sets differ only in optional instructions that
do not overlap (ARC600 `mul64`/`mulu64`/`mpyw`, ARC700 `mpy*`, `llock`/`scond`, `ex`, `rtie`,
`trap_s`). The one encoding with two names prints as `trap0` (ARC700; `swi` on ARC600).

## Known limitations

These were collected from the pull request description, its review and discussion, the Ghidra
issues that refer to it, and Ghidra-Rare's own testing.

| Limitation | Status |
|---|---|
| No ELF relocation handler: every shared object reported unhandled `R_ARC_JMP_SLOT` relocations (pull request discussion, 2021-11) | **Fixed**: `R_ARC_*` relocation handler; TLS relocations are reported, not applied (Ghidra has no thread-local storage model) |
| Auxiliary registers shown as plain numbers in `lr`/`sr` (review) | **Fixed** for the u6 form, which prints the register name as objdump does (`lr r0,[status32]`), and in the decompiler, which shows the named aux registers of the pspec. Numbers given as a long immediate or s12 still print as numbers: SLEIGH can only attach names to small instruction fields |
| Instruction suffixes and condition names differ from objdump (`.a` vs `.aw`, `.cc` before `.f`) (discussion) | **Fixed**: the syntax is GNU binutils 2.45's |
| Load/store instructions unrolled for every suffix combination (discussion) | **Fixed**: address-mode and size subtables |
| "Junk" instructions shown around `lp` loops (discussion) | **Fixed/not reproduced**: in the real libraries every instruction Ghidra found, including all `lp` loops (`memcmp`, `memcpy`, `memset`), is identical to objdump's at the same address |
| 64-bit integer arguments assumed on the stack (discussion) | **Fixed**: they take the next two registers (no even alignment), as GCC passes them |
| `!=` constraints in patterns and two branches per conditional instruction (review) | **Fixed**: one unconditional and one conditional constructor per operation, generated; `!=` only on fields of at most 6 bits |
| `norm` needed a Java user-op library for emulation | **Fixed**: `norm`/`normw` are p-code (`lzcount`); no Java user-op library |
| Emulating `lp` loops with the new `PcodeEmulator` loses the loop-end context (Ghidra issue #9337) | **Remaining (Ghidra bug)**: the loop mechanism uses `globalset`, which `EmulatorHelper` handles (tested) and `PcodeEmulator` does not; the fix belongs in Ghidra |
| The pull request's `ARC700_O0/O3_EmulatorTest` need the Ghidra source tree's pcodetest binaries | **Replaced**: Ghidra-Rare's emulator tests (`test/emu_tests.py`, 56 sequences, both byte orders) run against an installed Ghidra |
| Gradle 8 build failure (`compile` dependency) (review) | **Fixed**: stand-alone extension `build.gradle` |
| ROR carry, ADD1 flags, BMSK mask, BBIT bit index, `ex.di` (fixed in the pull request's last commit) | **Fixed** upstream; re-checked by the emulator and decode tests |
| ARCv2 (ARC EM/HS) not supported (discussion) | **Out of scope**: a different instruction set (see pull request #6344) |
| Big-endian ARCompact not supported | **Fixed**: `ARCompact:BE:32:default` |

Remaining gaps found by testing are listed in [GHIDRA-RARE.md](GHIDRA-RARE.md).
