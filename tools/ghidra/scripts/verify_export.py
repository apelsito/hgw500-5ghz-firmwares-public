"""Verify native Ghidra exports against one pinned OEM Quantenna carrier."""

import argparse
import csv
import hashlib
import json
from pathlib import Path


INPUTS = {
    "muc": ("qtn_driver.qtn_ruby.0.bin", "71dcd32849f122c09397490914227af6f77e51c34d15615028faa3d0fabb0fe4"),
    "auc": ("auc_driver.nomu.0.bin", "c10018f4fe384d753a800bbbcd5ef3c85c568d0852c221009063282d30fd85f6"),
    "dsp": ("rdsp_driver.0.bin", "87c882910d87cd29ba2004c4154e9240291aaad6aedb0ff4d90c7a5570be79fd"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rows(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=INPUTS, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    filename, expected = INPUTS[args.role]
    raw = args.original.read_bytes()
    if digest(raw) != expected:
        raise ValueError("Original carrier hash differs")
    original_files = []
    for item in rows(args.export / "original-file-bytes.tsv"):
        exported = (args.export / item["file"]).read_bytes()
        if exported != raw or int(item["file_offset"]) != 0 or digest(exported) != item["sha256"]:
            raise ValueError("Ghidra original FileBytes differ from the carrier")
        original_files.append(item["file"])
    if not original_files:
        raise ValueError("Project did not preserve the full original input")
    blocks = {item["block"]: item for item in rows(args.export / "memory-blocks.tsv")}
    block_data = {}
    for name, item in blocks.items():
        if item["initialized"] != "true":
            continue
        data = (args.export / "memory-blocks" / item["file"]).read_bytes()
        if len(data) != int(item["length"]) or digest(data) != item["sha256"]:
            raise ValueError("Memory block digest differs")
        block_data[name] = data
    file_positions = set()
    ranges_verified = 0
    for item in rows(args.export / "memory-source-ranges.tsv"):
        offset = int(item["file_offset"])
        if offset < 0:
            continue
        block = blocks[item["block"]]
        local = int(item["start"], 16) - int(block["start"], 16)
        count = int(item["length"])
        if local < 0 or offset + count > len(raw):
            raise ValueError("Source mapping is out of range")
        data = block_data[item["block"]][local:local + count]
        if data != raw[offset:offset + count]:
            raise ValueError("Memory source range differs from input bytes")
        file_positions.update(range(offset, offset + count))
        ranges_verified += 1
    observed = set()
    instruction_positions = set()
    mapped_instructions = 0
    instructions = rows(args.export / "ghidra-instructions.tsv")
    for item in instructions:
        offset = int(item["file_offset"])
        if offset < 0:
            continue
        data = bytes.fromhex(item["bytes"])
        address = int(item["address"], 16)
        if raw[offset:offset + len(data)] != data or item["file_bytes_match"] != "true":
            raise ValueError("Instruction byte mapping differs")
        addresses = {(item["space"], address + index) for index in range(len(data))}
        if addresses & observed:
            raise ValueError("Ghidra instruction definitions overlap within an address space")
        observed.update(addresses)
        instruction_positions.update(range(offset, offset + len(data)))
        mapped_instructions += 1
    functions = rows(args.export / "ghidra-functions.tsv")
    c_count = 0
    for item in functions:
        assembly = args.export / "functions" / item["asm_file"]
        if not assembly.is_file():
            raise ValueError("Function assembly export is missing")
        if item["decompiled"] == "true":
            source = args.export / "functions" / item["c_file"]
            if not source.is_file() or not source.read_text().strip():
                raise ValueError("Declared function reconstruction is missing")
            c_count += 1
    summary = json.loads((args.export / "ghidra-export.json").read_text())
    if summary["decompiled_functions"] != c_count or summary["functions"] != len(functions):
        raise ValueError("Function export inventory differs")
    if summary["instruction_byte_mismatches"] or summary["file_mapped_instructions"] != mapped_instructions:
        raise ValueError("Instruction verification summary differs")
    snapshot = args.export / summary["snapshot"]
    if digest(snapshot.read_bytes()) != summary["snapshot_sha256"]:
        raise ValueError("Portable Ghidra snapshot digest differs")
    report = {
        "schema": "openmitrastar.ghidra-quantenna-export-verification/v1",
        "role": args.role, "original_filename": filename, "original_bytes": len(raw),
        "original_sha256": expected, "original_filebytes_verified": original_files,
        "original_entire_file_preserved": True, "source_ranges_verified": ranges_verified,
        "unique_input_bytes_mapped": len(file_positions),
        "instructions": len(instructions), "file_mapped_instructions_verified": mapped_instructions,
        "unique_input_instruction_bytes": len(instruction_positions),
        "functions": len(functions), "c_reconstructions": c_count,
        "snapshot_sha256": summary["snapshot_sha256"], "all_checks_passed": True,
        "limits": ["Input byte identity, source mappings and inventories are verified.",
                   "Function extent and reconstructed C remain Ghidra's static analysis observations.",
                   "ARC ISA extensions, ABI and execution equivalence require separate validation.",
                   "GZF must be reopened with the same processor extension to verify portability."],
    }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
