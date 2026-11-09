"""Generate readable per-carrier indices and a hash inventory from the verified exports."""

import json
from pathlib import Path
import struct

from analyze import INPUTS, parse_elf, sha256, write_json


def main():
    root = Path(__file__).resolve().parent.parent
    verification = json.loads((root / "byte-verification.json").read_text())
    for item in verification["files"]:
        role = item["role"]
        filename, expected = INPUTS[role]
        folder = root / role
        raw = (folder / filename).read_bytes()
        layout = parse_elf(raw)
        info = next(segment for segment in layout["segments"]
                    if segment["virtual_address"] == "0xffff0000")
        magic, release_type, version = struct.unpack_from("<8sII", raw, info["file_offset"])
        metadata = {"magic_hex": magic.hex(), "magic_ascii": magic.decode("ascii").rstrip("\x00"),
                    "type": release_type, "version_hex": hex(version),
                    "version_bytes": list(version.to_bytes(4, "big")),
                    "file_offset": info["file_offset"], "virtual_address": "0xffff0000"}
        write_json(folder / "analysis" / "firmware-info.json", metadata)
        rows = sum(segment.get("byte_rows", 0) for segment in item["segments"])
        verified = sum(segment.get("bytes_verified", 0) for segment in item["segments"])
        missing = sum(segment.get("bytes_without_assembly_row", 0) for segment in item["segments"])
        text = ["# " + role.upper() + " — " + filename, "",
                "Carrier OEM Quantenna seleccionado para el coprocesador " + role.upper() + ".",
                "REA 6.8.0 se ejecutó sobre su copia fijada el 3 de noviembre de 2026.", "",
                "| Propiedad | Observación |", "| --- | --- |",
                "| Bytes | " + str(len(raw)) + " |",
                "| SHA-256 | " + expected + " |",
                "| Formato | ELF32 little-endian, ARCompact e_machine 93 |",
                "| Entrada declarada | " + layout["entry"] + " |",
                "| Segmentos de programa | " + str(layout["program_header_count"]) + " |",
                "| Secciones, símbolos y DWARF | Ausentes |",
                "| FWINFO tipo | " + str(release_type) + " |",
                "| FWINFO versión | " + hex(version) + " |",
                "| Filas de ensamblador verificadas | " + str(rows) + " |",
                "| Bytes contrastados en filas de ensamblador | " + str(verified) + " |",
                "| Bytes sin fila de ensamblador | " + str(missing) + " |", "",
                "Los originales, segmentos y volcados hexadecimales conservan sus bytes.",
                "Cada fila de bytes del ensamblador ARC700 little-endian se verificó contra",
                "su segmento. Las filas con directivas `.word`, `.long` o `.short` se",
                "conservan como observaciones de datos o de instrucciones sin resolver.", "",
                "## Archivos", "",
                "- [Mapa ELF](analysis/elf-layout.json) con offsets, vaddr, paddr y tamaños.",
                "- [FWINFO](analysis/firmware-info.json) con metadata release.",
                "- [Cadenas](analysis/strings.tsv) con offset de archivo.",
                "- [Verificación](analysis/verification.json) y [contraste independiente](../byte-verification.json).",
                "- [REA entropía](analysis/rea-entropy.json) y [regiones Binwalk](analysis/rea-regions.json).",
                "- [REA headers ARC](analysis/rea-arc-headers.json) mediante GNU objdump.",
                "- [REA apertura](analysis/rea-artifact.json), [análisis Ghidra](analysis/rea-ghidra-analysis.json)",
                "  y [decompilación](analysis/rea-decompile-all.json) con sus errores de arquitectura.", "",
                "## Segmentos", "",
                "| Índice | File offset | Vaddr | Paddr | Bytes de archivo | Bytes de memoria | Lectura |",
                "| --- | --- | --- | --- | --- | --- | --- |"]
        for segment in layout["segments"]:
            name = "segment-" + str(segment["index"]).zfill(2)
            links = "BSS / sin bytes de archivo"
            if segment["file_bytes"]:
                links = "[hex](segments/" + name + ".hex.tsv)"
                if segment["flags"] & 1:
                    links += " · [ARC700](segments/" + name + ".asm)"
            text.append("| " + " | ".join([str(segment["index"]), hex(segment["file_offset"]),
                         segment["virtual_address"], segment["physical_address"],
                         str(segment["file_bytes"]), str(segment["memory_bytes"]), links]) + " |")
        text.extend(["", "La decodificación lineal puede atravesar datos presentes dentro de segmentos RWE.",
                     "La reconstrucción de límites de funciones, extensiones específicas y pseudocódigo",
                     "C sigue pendiente de un proveedor ARC compatible. La lectura de estas salidas",
                     "se apoya en [las notas del loader](../docs/loader-notes.md).", ""])
        (folder / "README.md").write_text("\n".join(text))
    inventory = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not path.is_file() or any(part in (".git", "__pycache__", "out") for part in relative.parts):
            continue
        if path.name == "artifact-manifest.json":
            continue
        data = path.read_bytes()
        inventory.append({"path": relative.as_posix(), "bytes": len(data), "sha256": sha256(data)})
    write_json(root / "artifact-manifest.json", {
        "schema": "openmitrastar.quantenna-analysis-files/v1",
        "date": "2026-11-03", "files": inventory,
        "total_files": len(inventory), "total_bytes": sum(item["bytes"] for item in inventory),
        "source_carriers_unchanged": True, "hardware_accessed": False,
        "original_input_location": "../HGW500/firmware/radio",
        "reference_loader_origin": "../HGW500/drivers/quantenna/src/linux-7.3-r26/source/qdrv",
    })
    print("manifest files", len(inventory), "bytes", sum(item["bytes"] for item in inventory))


if __name__ == "__main__":
    main()
