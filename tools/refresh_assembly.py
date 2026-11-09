"""Regenerate linear ARC700 assembly with explicit little-endian decoding."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from analyze import INPUTS, parse_elf, sha256, write_json, write_segment_hex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--objdump", type=Path, required=True)
    args = parser.parse_args()
    if sha256(args.objdump.read_bytes()) != "96784aca5469a645953814ad4f1672a2063154427c2c51e4a9fcbbf13dcb6f3a":
        raise ValueError("ARC objdump hash differs")
    for role, (filename, expected) in INPUTS.items():
        folder = args.root / role
        raw = (folder / filename).read_bytes()
        if sha256(raw) != expected:
            raise ValueError("Input hash differs")
        records = []
        for segment in parse_elf(raw)["segments"]:
            if not segment["file_bytes"]:
                continue
            path = folder / "segments" / ("segment-" + str(segment["index"]).zfill(2) + ".bin")
            write_segment_hex(path.with_suffix(".hex.tsv"), path.read_bytes(), segment["file_offset"],
                              int(segment["virtual_address"], 16))
            if not segment["flags"] & 1:
                continue
            command = [str(args.objdump), "-D", "-z", "-b", "binary", "-m", "arc:ARC700", "-EL",
                       "--adjust-vma=" + segment["virtual_address"], str(path)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError(result.stderr)
            path.with_suffix(".asm").write_text(result.stdout)
            path.with_suffix(".stderr").write_text(result.stderr)
            records.append({"segment_index": segment["index"], "command": command,
                            "returncode": result.returncode,
                            "linear_decode_rows": len(re.findall(r"^\s*[0-9a-f]+:\s+[0-9a-f]", result.stdout, re.M)),
                            "assembly": path.with_suffix(".asm").name,
                            "file_bytes": segment["file_bytes"]})
        verification_path = folder / "analysis" / "verification.json"
        verification = json.loads(verification_path.read_text())
        verification["linear_assembly_exports"] = records
        verification["disassembler_architecture"] = "arc:ARC700"
        verification["disassembler_byte_order"] = "little (-EL)"
        write_json(verification_path, verification)
        print(role, "assembly exports", len(records), flush=True)


if __name__ == "__main__":
    main()
