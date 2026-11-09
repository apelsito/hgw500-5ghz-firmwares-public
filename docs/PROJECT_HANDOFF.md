# HGW500 Quantenna coprocessor firmware analysis handoff

## Purpose and evidence boundary

This repository organizes the generic MuC, AuC and DSP carriers and their independent component analysis repositories. Each child preserves the original ELF, byte-checked segment exports, a reopenable Ghidra project and inferred C/assembly output.

Continue function discovery, LP-loop semantics and alias/overlay interpretation. MuC symbol recovery has a later separate checkpoint; do not replace the original GZF. AuC command completion does not prove DSP/DMA retirement or make unloading safe.

## Source and evidence entry points

- `analysis-manifest.json`
- `ghidra-manifest.json`
- `byte-verification.json`
- `muc/README.md`
- `auc/README.md`
- `dsp/README.md`
- `docs/loader-notes.md`
- `ghidra-support/README.md`
- `reference-loader/qdrv_fw.c`

These paths are relative to this checkout. Some are preserved local additions
ahead of a remote branch; use the source/preservation manifests and the notes
below to establish which files a given clone actually contains. Do not guess
missing private inputs or replace an original with a similar-looking download.

## Continue from another machine

1. Clone the correct repository and branch from the [repository map](REPOSITORY_MAP.md).
   Initialize submodules only where the component actually declares them.
2. Read `docs/PUBLIC_SNAPSHOT.md`, the preservation/source manifest and the detailed
   [reference notes](REFERENCE_NOTES.md). Resolve baseline and target kernel first.
3. Verify the input hashes, analysis subject and compiler/processor definition.
   Keep preserved exports separate from any new analysis project.
4. Run the README's offline integrity checks. Missing context, original inputs
   or submodules are unmet dependencies, not permission to fabricate a passing result.
5. Put new build/analysis outputs in a fresh ignored `out/` or an external build
   directory. Record source hash, tool version, target ABI and the exact checks run.
6. Report source recovery, native compilation, byte comparison and any physical
   result separately. Installation/reboot/traffic tests need their own authority
   and exact-image recovery plan in the integration project.

## Handoff deliverables

- The selected source and immutable input hashes, with licences/provenance.
- A reproducible command or an explicit list of unresolved external inputs.
- New output locations and result receipts, leaving older evidence unchanged.
- A short explanation of what changed, which checks passed and what remains untested.
- A reviewed export containing no workstation paths, credentials, identity,
  client MACs, calibration or personalized image bodies.

The [firmware map](FIRMWARE_MAP.md) separates the OEM recovery, Core Boot R1 and
newer API v2 R3 integration. A historical acceptance does not transfer between them.
