"""Package each carrier as a standalone private repository with independent verification."""

import inspect
import json
from pathlib import Path

from analyze import INPUTS, parse_elf, sha256, write_json
from verify import verify_folder


def main():
    root = Path(__file__).resolve().parent.parent
    complete = json.loads((root / "byte-verification.json").read_text())
    parser_source = inspect.getsource(parse_elf)
    verify_source = inspect.getsource(verify_folder).replace("folder = root / role", "folder = root")
    for role, (filename, expected) in INPUTS.items():
        folder = root / role
        tools = folder / "tools"
        tools.mkdir(exist_ok=True)
        verifier = "\n".join([
            '"""Verify this carrier, its ELF segments, hex dump and all assembly byte rows."""',
            "", "import argparse", "import hashlib", "import json", "from pathlib import Path",
            "import re", "import struct", "", "",
            "def sha256(data):", "    return hashlib.sha256(data).hexdigest()", "", "",
            parser_source, "", verify_source, "",
            "def main():", "    parser = argparse.ArgumentParser()",
            '    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)',
            '    parser.add_argument("--output", type=Path)', "    args = parser.parse_args()",
            "    report = verify_folder(args.root, " + repr(role) + ", " + repr(filename) + ", " + repr(expected) + ")",
            "    if args.output:", '        args.output.write_text(json.dumps(report, indent=2) + "\\n")',
            "    print(json.dumps(report, indent=2))", "", "",
            'if __name__ == "__main__":', "    main()", "",
        ])
        (tools / "verify.py").write_text(verifier)
        item = next(record for record in complete["files"] if record["role"] == role)
        write_json(folder / "byte-verification.json", item)
        write_json(folder / "PROVENANCE.json", {
            "schema": "openmitrastar.quantenna-carrier-provenance/v1",
            "role": role, "original_filename": filename, "bytes": (folder / filename).stat().st_size,
            "sha256": expected, "source": "HGW500/firmware/radio/" + filename,
            "source_selection": "HGW500/firmware/radio/MANIFEST.json",
            "loader_profile": "src/linux-7.3-r26/source/qdrv/om73_fw_profiles.h",
            "loader_repository": "https://github.com/apelsito/openmitrastar-hgw500-quantenna-5ghz-driver-public",
            "parent_repository": "https://github.com/apelsito/hgw500-5ghz-firmwares-public",
            "intended_repository": "https://github.com/apelsito/hgw500-5ghz-firmware-" + role,
            "authorization": "Owner requested separate readable private repositories on 2026-11-03",
            "rea_version": "6.8.0", "objdump_version": "2.45.1",
            "objdump_sha256": "96784aca5469a645953814ad4f1672a2063154427c2c51e4a9fcbbf13dcb6f3a",
            "target_executed": False, "hardware_accessed": False,
        })
        (folder / "AGENTS.md").write_text("\n".join([
            "# Quantenna " + role.upper() + " — HGW500", "",
            "Repositorio privado de apelsito para el carrier OEM " + filename + ".",
            "El propietario autorizó su conservación y análisis en este repositorio el 3 de noviembre de 2026.",
            "Conservar el input original, su SHA-256, su procedencia y los registros de herramientas.",
            "Mantener privado hasta una instrucción expresa de publicación.", "",
            "Leer README.md, PROVENANCE.json y byte-verification.json antes de cambiar salidas.",
            "El verificador tools/verify.py usa únicamente la biblioteca estándar de Python 3 y",
            "funciona en este checkout sin depender de otros repositorios. Ejecutarlo tras cambios.", "",
            "REA 6.8.0 rechaza ARC y Ghidra 12.1.3 stock no tiene ese lenguaje. La entrega conserva",
            "decodificación ARC700 little-endian lineal, segmentos y volcados de bytes. Un futuro",
            "proveedor compatible debe reconstruir límites de funciones y contrastar direcciones y",
            "bytes antes de atribuir equivalencia a pseudocódigo. Conservar las incertidumbres.", "",
            "Trabajar offline. Guardar nuevas campañas en out/ o un destino ext4 nuevo.",
            "La autorización de análisis y organización cubre este carrier de coprocesador.",
            "Mantener claves, credenciales, calibración, store, identidad de unidad y capturas",
            "personalizadas en sus ubicaciones privadas locales. Aplican los gates de hardware",
            "del HGW500 para acciones físicas.", "",
        ]))
        (folder / ".gitignore").write_text("out/\n__pycache__/\n*.pyc\n*.gpr\n*.rep/\n*.lock\n")
        (folder / ".gitattributes").write_text("* -text\n")
        text = (folder / "README.md").read_text()
        text = text.split("\n## Verificar este repositorio", 1)[0]
        text = text.replace("[contraste independiente](../byte-verification.json)", "[contraste independiente](byte-verification.json)")
        text = text.replace("[las notas del loader](../docs/loader-notes.md)",
                            "[las notas del loader](https://github.com/apelsito/hgw500-5ghz-firmwares-public/blob/main/docs/loader-notes.md)")
        text += "\n".join([
            "", "## Verificar este repositorio", "",
            "El checkout incluye su input fijado, todos los segmentos y un verificador Python",
            "autónomo. Contrasta los hashes, los headers ELF, cada volcado hexadecimal y cada",
            "fila de bytes que objdump publicó. Puede ejecutarse con Python 3 en Linux o Windows.", "",
            "```bash", "python3 tools/verify.py --root .", "```", "",
            "La reproducción de todas las operaciones REA y ARC está en las herramientas del",
            "repositorio padre. Los comandos efectivos, códigos de salida y errores se conservan",
            "en analysis/. Para reconstruir el conjunto se clona el padre con sus submódulos.",
            "[Repositorio padre](https://github.com/apelsito/hgw500-5ghz-firmwares-public)", "",
            "[PROVENANCE.json](PROVENANCE.json) identifica el original, su selección y las herramientas.",
            "[artifact-manifest.json](artifact-manifest.json) identifica los archivos de esta entrega.",
            "Mantener este repositorio privado. La autorización permite conservar el carrier",
            "OEM de este coprocesador y su análisis en GitHub privado de apelsito.", "",
        ])
        (folder / "README.md").write_text(text)
        inventory = []
        for path in sorted(folder.rglob("*")):
            relative = path.relative_to(folder)
            if not path.is_file() or any(part in (".git", "out", "__pycache__") for part in relative.parts):
                continue
            if path.name == "artifact-manifest.json":
                continue
            data = path.read_bytes()
            inventory.append({"path": relative.as_posix(), "bytes": len(data), "sha256": sha256(data)})
        write_json(folder / "artifact-manifest.json", {
            "schema": "openmitrastar.quantenna-carrier-files/v1", "role": role,
            "date": "2026-11-03", "files": inventory,
            "total_files": len(inventory), "total_bytes": sum(item["bytes"] for item in inventory),
        })
        print(role, "standalone files", len(inventory), flush=True)
    inventory = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not path.is_file() or any(part in (".git", "out", "__pycache__") for part in relative.parts):
            continue
        if relative.as_posix() == "artifact-manifest.json":
            continue
        data = path.read_bytes()
        inventory.append({"path": relative.as_posix(), "bytes": len(data), "sha256": sha256(data)})
    write_json(root / "artifact-manifest.json", {
        "schema": "openmitrastar.quantenna-analysis-files/v1", "date": "2026-11-03",
        "files": inventory, "total_files": len(inventory),
        "total_bytes": sum(item["bytes"] for item in inventory),
        "child_repositories": [{"path": role, "repository": "https://github.com/apelsito/hgw500-5ghz-firmware-" + role}
                               for role in INPUTS],
        "source_carriers_unchanged": True, "hardware_accessed": False,
    })


if __name__ == "__main__":
    main()
