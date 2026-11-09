# Credits: ARCompact (ARC600/ARC700) module

This module is a community SLEIGH module that Ghidra-Rare imported, tested and fixed. The
original processor specification was written by Nicolas Iooss as a Ghidra pull request; the
big-endian language follows Jackson Donaldson's big-endian port. Ghidra-Rare's changes are
listed below.

## Upstream

| | |
|---|---|
| Source | Ghidra pull request [#3006](https://github.com/NationalSecurityAgency/ghidra/pull/3006) "Add support for ARCompact instruction set", head commit `d3fbf109ada6d051750e973779170c1758622530` (2026-07-01) |
| License | Apache License 2.0 (Ghidra contribution terms; `LICENSE` is Ghidra's Apache-2.0 text) |
| Original author | Nicolas Iooss ([@niooss-ledger](https://github.com/niooss-ledger), commits as "Nicolas Iooss"): the ARCompact SLEIGH specification, cspec, pspec, DWARF map, opinion, `norm` emulation, pcodetest definitions (2021-2026) |
| Big-endian layout | Jackson Donaldson ([@JacksonDonaldson](https://github.com/JacksonDonaldson)), [arcompact_be_ghidra](https://github.com/JacksonDonaldson/arcompact_be_ghidra) commit `2b742434` "Add big-endian ARC mode" (Apache-2.0): the big-endian 32-bit instruction token, reused for `ARCompact:BE:32:default` |
| Compared, not used | [BonusPlay/ghidra-arcompact](https://github.com/BonusPlay/ghidra-arcompact) (identical copy of the pull request packaged as an extension, GPL-3.0 `LICENSE` file); [niooss-ledger/ghidra-arcompact-test](https://github.com/niooss-ledger/ghidra-arcompact-test) (the author's pcodetest harness, no license) |
| Reference material | ARCompact ISA Programmer's Reference (Synopsys, as linked from the pull request) for instruction semantics; GNU binutils 2.45 `opcodes/arc-*` (GPL-3.0; used as the test oracle and for encodings, not copied); the CGEN ARCompact description (foss-for-synopsys-dwc-arc-processors/cgen `cpu/ARCompact.cpu`) for the XMAC multiply-accumulate semantics the reference does not describe; GCC 14 `config/arc` for the calling convention and DWARF numbering |

The pull request's files are the first commit of the Ghidra-Rare fork, unchanged at their
original paths (`Ghidra/Processors/ARC/...`, plus its change to
`Ghidra/Extensions/SleighDevTools/pcodetest/pcode_defs.py`); every Ghidra-Rare change is a
separate commit on top.

## Ghidra-Rare changes

1. **Instruction decoding reworked after differential testing against GNU objdump 2.45**
   (ARC600 and ARC700 decoders). The pull request agreed with objdump on 26.8% of the binutils
   opcode-table corpus and about 70% of random words; it is now 100% semantic with 0
   unexplained differences on both corpora, in both byte orders. Problems found:
   - every operand display (`pcl=0x...`, `r62limm`, missing `[...]` on jumps and `ex`, missing
     repeated operand of `add_s b,b,u7`, shifts by one printing `,1`, `mul64` without its `0`
     destination, `rtie 0x0`, `sync 0x0`), condition names and suffix order (`add.al`,
     `.cc` before `.f`), and the load/store spellings now follow objdump;
   - major-4 sub-opcodes that do not exist decoded as `EXT04`; DSP, FPX and SIMD extension
     instructions decoded as `EXT05`/`EXT06`; `prefetch`, `llock`, `scond`, `swape`, `rtsc`,
     `unimp_s`, `nop`, `neg`, `mpyw`/`mpyuw` and the XMAC instructions were missing;
   - reserved bits that objdump ignores were required to be 0 (`b`/`bl` far forms, `st`), and
     forms objdump rejects were accepted (long immediate with a delay slot, `cmp`/`tst` with a
     non-zero `a` field, `st [limm,s9]`);
   - `ldb.x.ab`/`ldw.x.ab` zero-extended, and `.x` loads with write-back used the wrong
     extension.
   The general operations are now generated from a table (`tools/gen_arcompact.py`), with one
   unconditional and one conditional constructor per operation (as the review asked) and no
   `!=` constraints on wide fields; loads and stores use address-mode subtables.
2. **Big-endian language** `ARCompact:BE:32:default` (`ARCompact_be.slaspec`, `ARCompact_be.cspec`),
   sharing `ARCompact.sinc` with the little-endian language; token layout after
   arcompact_be_ghidra.
3. **Semantics.** Checked in Ghidra's emulator (56 sequences per byte order). Fixed or added:
   `bl.d`/`jl.d` link address, `adc`/`sbc` carry and overflow, `max`/`min`/`abs` flags, shift
   flags, `norm`/`normw` in p-code (`lzcount`; the Java user-op library is no longer needed),
   `divaw`, `asls`/`asrs` count limits, `adds`/`subs`/`adcs`/`sbcs`/`addsdw`/`subsdw`/`abss`/
   `abssw`/`negs`/`negsw`/`sat16`/`rnd16` with the sticky `S` flag, the XMAC 32x16
   multiply(-accumulate) instructions with the r56:r57 accumulator, FPX `fmul`/`fadd`/`fsub`,
   `llock`/`scond` with a lock flag, `rtie` (exception and interrupt return through
   ERET/ERSTATUS or ILINK/STATUS32_Ln), `j.f` restoring STATUS32, `trap0`/`trap_s`/`brk`/`sleep`
   falling through, zero-overhead `lp` loops as a direct branch back to the loop start (context
   set by `lp`, so analysis and the decompiler see an ordinary loop), branch-free `sub_s.ne` (the
   decompiler rejected the conditional branch inside it). Auxiliary registers are addressed by register number (word-addressed
   `auxregs` space).
4. **cspec** rewritten from GCC: r24 was missing from the callee-saved registers, 64-bit
   arguments use consecutive registers with no even alignment (join rule) instead of the stack,
   killed-by-call registers, return address, 4-byte alignment of 64-bit types. Separate cspec for
   big-endian (register-pair word order).
5. **DWARF register map**: r30 is ilink2 and r31 blink (they were swapped).
6. **ELF support** (Java, `src/main/java`): a relocation handler for `R_ARC_*` (the pull
   request had none: every shared object reported unhandled `R_ARC_JMP_SLOT`, as noted in the
   pull request discussion), and an ELF extension that marks up the PLT (Ghidra's default PLT
   markup assumed a 16-byte header and disassembled the header's data words).
7. **Removed** the pull request's `src/test.processors` emulator-test classes, which need the
   Ghidra source tree's pcodetest binaries, and the Java `norm` user-op library.

Ghidra-Rare-only files: `GHIDRA-RARE.md`, `CREDITS.md`, `LICENSE`, `build.gradle` (stand-alone
extension build, replacing the in-tree one), `extension.properties`, `.gitignore`, `test/`,
`tools/`.
