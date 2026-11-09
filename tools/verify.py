"""Verify pinned carriers, ELF segment extraction and every assembly byte row."""

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from analyze import INPUTS, parse_elf, sha256


def verify_folder(root, role, filename, expected):
    folder = root / role
    raw = (folder / filename).read_bytes()
    if sha256(raw) != expected:
        raise ValueError("Input hash mismatch")
    layout = parse_elf(raw)
    saved = json.loads((folder / "analysis" / "elf-layout.json").read_text())
    if saved != layout:
        raise ValueError("ELF layout differs from independent reread")
    checks = []
    for segment in layout["segments"]:
        if not segment["file_bytes"]:
            continue
        path = folder / "segments" / ("segment-" + str(segment["index"]).zfill(2) + ".bin")
        data = path.read_bytes()
        offset = segment["file_offset"]
        if data != raw[offset:offset + segment["file_bytes"]]:
            raise ValueError("Segment bytes differ")
        hex_rows = path.with_suffix(".hex.tsv").read_text().splitlines()[1:]
        restored = bytearray()
        base = int(segment["virtual_address"], 16)
        for hex_row in hex_rows:
            file_text, address_text, hex_text, readable = hex_row.split("\t")
            if int(file_text, 16) != offset + len(restored) or int(address_text, 16) != base + len(restored):
                raise ValueError("Hex dump address differs")
            restored.extend(bytes.fromhex(hex_text))
        if bytes(restored) != data:
            raise ValueError("Hex dump bytes differ")
        check = {"index": segment["index"], "file_bytes": len(data), "sha256": sha256(data)}
        if segment["flags"] & 1:
            assembly = path.with_suffix(".asm").read_text()
            base = int(segment["virtual_address"], 16)
            seen = set()
            rows = 0
            unknown_rows = 0
            for line in assembly.splitlines():
                match = re.match(r"^\s*([0-9a-f]+):\s*\t([0-9a-f ]+)\t(.*)", line)
                if not match:
                    continue
                address = int(match.group(1), 16)
                tokens = match.group(2).split()
                decoded_bytes = b"".join(struct.pack("<H", int(token, 16))
                                         if len(token) == 4 else bytes.fromhex(token)
                                         for token in tokens)
                local = address - base
                if local < 0 or data[local:local + len(decoded_bytes)] != decoded_bytes:
                    raise ValueError("Assembly bytes differ at " + hex(address))
                positions = set(range(local, local + len(decoded_bytes)))
                if positions & seen:
                    raise ValueError("Overlapping byte rows")
                seen.update(positions)
                rows += 1
                unknown_rows += match.group(3).lstrip().startswith((".word", ".long", ".short", ".byte"))
            missing = sorted(set(range(len(data))) - seen)
            check.update({"byte_rows": rows, "bytes_verified": len(seen),
                          "all_assembly_rows_verified": True,
                          "all_segment_bytes_preserved_in_hex": True,
                          "bytes_without_assembly_row": len(missing),
                          "first_missing_segment_offsets": missing[:20],
                          "unknown_or_data_directive_rows": unknown_rows})
        checks.append(check)
    return {"role": role, "sha256": expected, "input_bytes": len(raw),
            "segments": checks, "all_checks_passed": True,
            "validation_scope": "Byte identity and linear ARC700 decoding export, without function/semantic validation."}


def run_json_verifier(script, arguments):
    """Run an offline verifier using this Python interpreter; never launch Ghidra."""
    result = subprocess.run([sys.executable, "-E", str(script), *map(str, arguments)],
                            capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise ValueError("Verifier failed: " + script.name + "\n" + result.stderr + result.stdout)
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise ValueError("Expected verifier JSON object: " + script.name)
    return report


def verify_artifact_manifest(root, role=None):
    """Verify size/SHA of every row and coverage of the whole published tree."""
    root = root.resolve()
    manifest_path = root / "artifact-manifest.json"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    schema = ("openmitrastar.quantenna-carrier-files/v1" if role else
              "openmitrastar.quantenna-analysis-files/v1")
    if manifest.get("schema") != schema or (role and manifest.get("role") != role):
        raise ValueError("Artifact manifest schema/role mismatch")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Artifact manifest must contain file rows")
    ignored = {".git", "out", "__pycache__"}
    seen, total = set(), 0
    for row in rows:
        relative = row.get("path")
        if not isinstance(relative, str) or not relative:
            raise ValueError("Invalid artifact path")
        parts = relative.split("/")
        if ("\\" in relative or ":" in relative or
                any(part in {"", ".", ".."} for part in parts) or
                ignored.intersection(parts) or relative == "artifact-manifest.json"):
            raise ValueError("Unsafe/excluded artifact path: " + relative)
        if relative in seen:
            raise ValueError("Duplicate artifact row: " + relative)
        path = root.joinpath(*parts).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Missing/escaping artifact: " + relative)
        data = path.read_bytes()
        if len(data) != row.get("bytes") or sha256(data) != row.get("sha256"):
            raise ValueError("Artifact size/SHA mismatch: " + relative)
        seen.add(relative)
        total += len(data)
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*")
              if path.is_file() and not ignored.intersection(path.relative_to(root).parts)
              and path != manifest_path}
    if seen != actual:
        raise ValueError("Artifact inventory mismatch: unlisted=" + repr(sorted(actual-seen)[:20]) +
                         "; absent=" + repr(sorted(seen-actual)[:20]))
    if manifest.get("total_files") != len(seen) or manifest.get("total_bytes") != total:
        raise ValueError("Artifact manifest totals mismatch")
    return {"schema": schema, "files_verified": len(seen), "bytes_verified": total,
            "sha256": sha256(raw), "complete_inventory_verified": True, "all_checks_passed": True}


def write_new_report(path, report):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, help="Create a new report; never replace an existing output")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError("Output already exists: " + str(args.output))
    root = args.root.resolve()
    results = []
    for role, (filename, expected) in INPUTS.items():
        child_root = root / role
        child = run_json_verifier(child_root / "tools/verify.py", ["--root", child_root])
        if (child.get("all_checks_passed") is not True or child.get("role") != role or
                child.get("sha256") != expected or
                child.get("native_ghidra", {}).get("all_checks_passed") is not True or
                child.get("artifact_manifest", {}).get("all_checks_passed") is not True):
            raise ValueError("Child verification failed: " + role)
        results.append(child)
    support = run_json_verifier(root / "ghidra-support/verify_support.py", [])
    if support.get("status") != "PASS":
        raise ValueError("Preserved extension verification failed")
    if any(child["native_ghidra"]["extension"]["source_commit"] != support.get("source_commit")
           for child in results):
        raise ValueError("Parent/child processor extension source pin mismatch")
    exports = [child["native_ghidra"]["export"] for child in results]
    native_summary = {"all_checks_passed": True, "carriers_verified": len(results),
                      "roundtrip_matches": True, "snapshot_facets_verified_each": 13,
                      "functions": sum(item["functions"] for item in exports),
                      "instructions": sum(item["instructions"] for item in exports),
                      "c_reconstructions": sum(item["c_reconstructions"] for item in exports),
                      "file_mapped_instructions_verified": sum(
                          item["file_mapped_instructions_verified"] for item in exports),
                      "unique_input_bytes_mapped": sum(item["unique_input_bytes_mapped"] for item in exports),
                      "target_executed": False, "hardware_accessed": False,
                      "validation_scope": "Byte identity, native export inventories and 13-facet GZF "
                                          "roundtrip preservation; reconstructed C and function "
                                          "boundaries remain static analysis observations."}
    report = {"schema": "openmitrastar.quantenna-carrier-byte-verification/v1",
              "all_checks_passed": True, "files": results, "native_ghidra": native_summary,
              "extension_support": support, "artifact_manifest": verify_artifact_manifest(root)}
    if args.output:
        write_new_report(args.output, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
