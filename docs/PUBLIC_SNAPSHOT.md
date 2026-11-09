# Public source snapshot

This repository is a clean public export, not a visibility change or rewrite of
the original private repository. It includes the selected source, readable
reverse-engineering exports, generic firmware inputs, licences and documentation.

## Provenance and privacy

Personal workstation prefixes in source-side scripts, paths and reports have
been normalized to `/workspace/...`. These are portable placeholders, not a
claim that the scripts will run without configuring their declared toolchains
and inputs. Native Ghidra databases, private authoring instructions and selected
compressed duplicate analysis corpora remain in the private preservation clone.
Readable C, assembly and the selected original generic carriers are retained.
Nothing here exports per-unit provisioning, credentials or calibration.

`PUBLICATION.json` records the original source commit, excluded members, changed
file hashes and the exact public file inventory. Original manifests and result
receipts remain historical provenance: normalization can change their metadata
hashes. They must not be presented as new successful checks of this export.

## Verify this public copy

```sh
python tools/verify_public_export.py
```

The check compares every published payload file with its SHA-256. It does not
build, flash, boot, load a driver or qualify a radio. Firmware-family, source
availability and physical acceptance boundaries in the README still apply.

## Component links and dependencies

Links to the related project repositories use their public exports. Submodule
links to these exports are explicitly repinned to the public snapshots for
anonymous access; original release/build pins remain in the historical source
manifests. This is a navigable source collection, not a newly qualified firmware
release. External upstream GPL/kernel dependencies keep their own provenance.

GitHub Actions are disabled for this publication; no new build/test result is
claimed from exporting the sources. The private histories remain unchanged.
