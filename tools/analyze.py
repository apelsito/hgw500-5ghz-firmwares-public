"""Inspect the three pinned Quantenna carriers without executing target code."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


INPUTS = {
    "muc": ("qtn_driver.qtn_ruby.0.bin", "71dcd32849f122c09397490914227af6f77e51c34d15615028faa3d0fabb0fe4"),
    "auc": ("auc_driver.nomu.0.bin", "c10018f4fe384d753a800bbbcd5ef3c85c568d0852c221009063282d30fd85f6"),
    "dsp": ("rdsp_driver.0.bin", "87c882910d87cd29ba2004c4154e9240291aaad6aedb0ff4d90c7a5570be79fd"),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def run_record(output, name, command, timeout=180, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, env=env)
        code = result.returncode
        stdout, stderr = result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = 124
        stdout = (error.stdout or b"").decode(errors="replace")
        stderr = (error.stderr or b"").decode(errors="replace") + "\nTimeout expired.\n"
    (output / (name + ".stdout")).write_text(stdout)
    (output / (name + ".stderr")).write_text(stderr)
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        parsed = None
    record = {"command": command, "returncode": code, "result": parsed,
              "stdout_file": name + ".stdout", "stderr_file": name + ".stderr"}
    write_json(output / (name + ".json"), record)
    print(output.parent.name, name, "returncode", code, flush=True)
    return record


def parse_elf(raw):
    if raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected ELF32 little-endian input")
    fields = struct.unpack_from("<16sHHIIIIIHHHHHH", raw)
    (_, elf_type, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = fields
    if machine != 93 or phentsize != 32 or phoff + phnum * phentsize > len(raw):
        raise ValueError("Unsupported carrier header")
    segments = []
    for index in range(phnum):
        kind, offset, vaddr, paddr, filesz, memsz, permissions, align = struct.unpack_from(
            "<IIIIIIII", raw, phoff + index * phentsize)
        if offset + filesz > len(raw) or filesz > memsz:
            raise ValueError("Invalid program header bounds")
        segments.append({"index": index, "type": kind, "file_offset": offset,
                         "virtual_address": hex(vaddr), "physical_address": hex(paddr),
                         "file_bytes": filesz, "memory_bytes": memsz,
                         "flags": permissions, "alignment": align,
                         "sha256": sha256(raw[offset:offset + filesz])})
    return {"class": "ELF32", "byte_order": "little", "e_machine": machine,
            "machine_declared": "ARCompact", "entry": hex(entry),
            "program_header_count": phnum, "section_header_count": shnum,
            "elf_flags": hex(flags), "segments": segments}


def extract_strings(raw):
    rows = ["file_offset\ttext"]
    for match in re.finditer(rb"[\x20-\x7e]{5,}", raw):
        rows.append(hex(match.start()) + "\t" + match.group().decode("ascii"))
    return "\n".join(rows) + "\n"


def write_segment_hex(path, data, file_offset, address):
    rows = ["file_offset\tvirtual_address\thex_bytes\tascii"]
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        readable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in block)
        rows.append("\t".join([hex(file_offset + offset), hex(address + offset),
                              block.hex(" "), readable]))
    path.write_text("\n".join(rows) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="New output directory. Existing output is refused.")
    parser.add_argument("--objdump", type=Path, required=True,
                        help="Absolute path to the pinned ARC objdump executable")
    parser.add_argument("--rea", default="/usr/local/bin/rea")
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("Use an absent output directory")
    if sha256(args.objdump.read_bytes()) != "96784aca5469a645953814ad4f1672a2063154427c2c51e4a9fcbbf13dcb6f3a":
        raise ValueError("ARC objdump hash differs from the verified toolchain")
    args.output.mkdir(parents=True)
    env = dict(os.environ, REA_OBJDUMP_COMMAND=str(args.objdump))
    run_record(args.output, "rea-version", [args.rea, "--version"])
    run_record(args.output, "arc-objdump-version", [str(args.objdump), "--version"])
    records = []
    for role, (filename, expected) in INPUTS.items():
        source = args.source_dir / filename
        if not source.is_file():
            source = args.source_dir / role / filename
        raw = source.read_bytes()
        if sha256(raw) != expected:
            raise ValueError("Input hash mismatch for " + filename)
        folder = args.output / role
        analysis = folder / "analysis"
        segments_dir = folder / "segments"
        analysis.mkdir(parents=True)
        segments_dir.mkdir()
        target = folder / filename
        target.write_bytes(raw)
        layout = parse_elf(raw)
        write_json(analysis / "elf-layout.json", layout)
        (analysis / "strings.tsv").write_text(extract_strings(raw))
        run_record(analysis, "rea-artifact", [args.rea, "inspect-artifact", str(target), "--format", "json"])
        run_record(analysis, "rea-entropy", [args.rea, "inspect-byte-entropy", str(target), "--format", "json"])
        run_record(analysis, "rea-regions", [args.rea, "inspect-firmware-regions", str(target), "--format", "json"], timeout=180)
        run_record(analysis, "rea-layout", [args.rea, "inspect-binary-layout", str(target), "--format", "json"])
        run_record(analysis, "rea-arc-headers", [args.rea, "inspect-with-objdump", str(target), "file_headers", "--format", "json"], env=env)
        run_record(analysis, "rea-ghidra-analysis", [args.rea, "analyze", str(target), "--provider", "ghidra", "--format", "json"], timeout=180)
        run_record(analysis, "rea-decompile-all", [args.rea, "decompile-all", str(target), "--provider", "ghidra", "--output", str(folder / "decompiled"), "--format", "json"], timeout=180)
        run_record(analysis, "readelf", ["readelf", "-h", "-l", str(target)])
        decoded = []
        for segment in layout["segments"]:
            if not segment["file_bytes"]:
                continue
            index = segment["index"]
            name = "segment-" + str(index).zfill(2)
            offset = segment["file_offset"]
            data = raw[offset:offset + segment["file_bytes"]]
            binary = segments_dir / (name + ".bin")
            binary.write_bytes(data)
            write_segment_hex(segments_dir / (name + ".hex.tsv"), data, offset,
                              int(segment["virtual_address"], 16))
            if segment["flags"] & 1:
                command = [str(args.objdump), "-D", "-z", "-b", "binary", "-m", "arc:ARC700", "-EL",
                           "--adjust-vma=" + segment["virtual_address"], str(binary)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                assembly = segments_dir / (name + ".asm")
                assembly.write_text(result.stdout)
                (segments_dir / (name + ".stderr")).write_text(result.stderr)
                rows = len(re.findall(r"^\s*[0-9a-f]+:\s+[0-9a-f]", result.stdout, re.M))
                decoded.append({"segment_index": index, "returncode": result.returncode,
                                "linear_decode_rows": rows, "assembly": assembly.name,
                                "file_bytes": len(data)})
        verification = {"input_bytes": len(raw), "sha256": expected,
                        "input_unchanged": source.read_bytes() == raw,
                        "segment_count": len(layout["segments"]),
                        "all_segment_hashes_verified": True,
                        "linear_assembly_exports": decoded,
                        "decompiled_c_recovered": False,
                        "hardware_accessed": False,
                        "limits": ["Carrier ELF e_machine is ARCompact. Processor extensions and actual execution mode need independent validation.",
                                   "GNU objdump uses explicit ARC700 little-endian mode and performs linear decoding of every executable-marked file-backed segment. Data embedded in such segments can decode as instructions.",
                                   "Duplicated virtual-address segments remain separate. Loader order and physical-address overrides are preserved in elf-layout.json.",
                                   "No section table, symbols or debug information are present. Function boundaries are not recovered.",
                                   "Ghidra 12.1.3 stock has no ARC language. REA failure records are retained.",
                                   "No functionally equivalent C reconstruction or firmware behavior is claimed."]}
        write_json(analysis / "verification.json", verification)
        records.append({"role": role, "file": role + "/" + filename,
                        "bytes": len(raw), "sha256": expected,
                        "entry": layout["entry"], "segments": len(layout["segments"]),
                        "linear_assembly_files": len(decoded)})
    write_json(args.output / "analysis-manifest.json", {"schema": "openmitrastar.quantenna-carrier-analysis/v1",
                                                       "rea_version": "6.8.0", "files": records,
                                                       "hardware_accessed": False})


if __name__ == "__main__":
    main()
