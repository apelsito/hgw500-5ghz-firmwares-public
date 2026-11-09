"""Verify the preserved ARCompact source and extension package."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-directory", type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
    for row in manifest["files"]:
        path = (ROOT / row["path"]).resolve()
        assert path.is_relative_to(ROOT), row["path"]
        data = path.read_bytes()
        assert len(data) == row["bytes"], row["path"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"], row["path"]
        if "git_object" in row:
            blob = b"blob " + str(len(data)).encode() + b"\x00" + data
            assert hashlib.sha1(blob).hexdigest() == row["git_object"], row["path"]
    license_text = (ROOT / "source/LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text and "Version 2.0" in license_text
    package = ROOT / manifest["extension_package"]["path"]
    installed_files = 0
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None
        package_files = [entry for entry in archive.infolist() if not entry.is_dir()]
        names = {entry.filename for entry in package_files}
        assert any(name.endswith("data/languages/ARCompact.sla") for name in names)
        assert any(name.endswith("data/languages/ARCompact_be.sla") for name in names)
        assert any(name.endswith("LICENSE") for name in names)
        if args.installed_directory:
            installed_root = args.installed_directory.resolve()
            for entry in package_files:
                relative = Path(entry.filename).relative_to("ARCompact")
                installed = (installed_root / relative).resolve()
                assert installed.is_relative_to(installed_root), entry.filename
                assert installed.read_bytes() == archive.read(entry), entry.filename
                installed_files += 1
    print(json.dumps({"status": "PASS", "files_verified": len(manifest["files"]),
                      "source_commit": manifest["source_commit"], "license": "Apache-2.0",
                      "zip_files_verified": len(package_files),
                      "installed_files_verified": installed_files,
                      "hardware_accessed": False}, indent=2))


if __name__ == "__main__":
    main()
