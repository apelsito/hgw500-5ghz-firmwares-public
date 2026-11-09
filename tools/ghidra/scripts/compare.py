#!/usr/bin/env python3
"""Verify canonical Ghidra snapshot facets and compare two preserved programs."""
import argparse
import hashlib
import json
from pathlib import Path


def verify(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "openmitrastar.ghidra-program-snapshot/v1":
        raise ValueError("unknown snapshot schema")
    facets = path.parent / (path.stem + ".facets")
    for name, expected in value["artifacts"].items():
        if Path(name).name != name or not name.endswith(".tsv"):
            raise ValueError("unsafe facet path")
        data = (facets / name).read_bytes()
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("facet digest differs: " + name)
        if len(data.decode("utf-8").splitlines()) - 1 != expected["rows"]:
            raise ValueError("facet row count differs: " + name)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("restored", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    original = verify(args.original)
    restored = verify(args.restored)
    keys = sorted(set(original) | set(restored))
    differences = [key for key in keys if original.get(key) != restored.get(key)]
    facets = sorted(set(original["artifacts"]) | set(restored["artifacts"]))
    changed_facets = [name for name in facets if original["artifacts"].get(name) != restored["artifacts"].get(name)]
    result = {"schema": "openmitrastar.ghidra-snapshot-comparison/v1", "equal": not differences, "different_fields": differences, "different_facets": changed_facets, "facets_verified_each": len(facets), "original_json_sha256": hashlib.sha256(args.original.read_bytes()).hexdigest(), "restored_json_sha256": hashlib.sha256(args.restored.read_bytes()).hexdigest()}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    print(text, end="")
    raise SystemExit(0 if result["equal"] else 1)


if __name__ == "__main__":
    main()
