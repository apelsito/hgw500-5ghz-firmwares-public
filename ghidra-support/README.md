# Soporte Ghidra conservado para Quantenna

> Public source snapshot. [Scope, provenance and verification](docs/PUBLIC_SNAPSHOT.md).

Esta carpeta conserva las definiciones ARCompact y el paquete instalado que
utiliza el análisis de los firmwares Quantenna MuC y AuC. Permite reabrir sus
exports GZF en una instalación Ghidra compatible con el mismo módulo.

El proveedor es `aleph-void/ghidra-arcompact`, commit
`41703a7bbac5a316e6e72381af67d5ee0e1d9d25`. El módulo deriva del trabajo
de Nicolas Iooss y del fork Ghidra-Rare. Sus autores y cambios permanecen
en `source/CREDITS.md`, `source/GHIDRA-RARE.md` y los encabezados originales.
El código conserva la licencia Apache 2.0 en `source/LICENSE`.

## Contenido conservado

| Ruta | Contenido |
| --- | --- |
| `source/` | Snapshot completo de los archivos versionados del commit fijado |
| `source/data/languages/` | SLEIGH, procesador, compilador, lenguaje y opiniones ELF |
| `source/src/main/java/` | Extensión ELF y handler de relocaciones ARCompact |
| `source/test/` y `source/tools/` | Pruebas, corpus y generador originales |
| `ghidra_12.1.3_PUBLIC_20261025_ARCompact.zip` | Paquete exacto instalado, 218.353 bytes |
| `extension-receipt.json` | Procedencia del paquete, hash y ruta de instalación observada |
| `SOURCE_MANIFEST.json` | Hashes de cada archivo y objetos/modos Git del snapshot |
| `verify_support.py` | Verificación local del snapshot, licencia, ZIP y paquete instalado opcional |

El ZIP tiene SHA-256
`8153e331b8521d5c5bb0797aaa1d7235c8246c96f72a8c55aa9b5b26db63595d`.
La copia del código mantiene los bytes originales y los modos Git quedan
registrados en el manifiesto. Los tiempos de archivo dependen del checkout.

## Reabrir los proyectos

Usar Ghidra `12.1.3_PUBLIC` con Java 21 e instalar el ZIP desde
`File > Install Extensions`. Reiniciar Ghidra después de la instalación.
Importar el archivo GZF del firmware correspondiente. Los lenguajes
conservados son `ARCompact:LE:32:default` y `ARCompact:BE:32:default`, para
ARC600/ARC700. Los tres carriers Quantenna de esta entrega, incluido DSP,
declaran ARCompact `e_machine=93` y usan `ARCompact:LE:32:default`.

La instalación local observada está en
`/workspace/build/.config/ghidra/ghidra_12.1.3_PUBLIC/Extensions/ARCompact`.
La distribución Ghidra base está en
`/opt/engineering/tools/ghidra_12.1.3_PUBLIC`.

Verificar la entrega desde el checkout.

```powershell
python ghidra-support/verify_support.py
```

Contrastar además cada archivo del ZIP con la extensión instalada en WSL.

```powershell
wsl -d Engineering -u apelsito --exec python3 /workspace/OpenMitraStar/hgw500-5ghz-firmwares/ghidra-support/verify_support.py --installed-directory /workspace/build/.config/ghidra/ghidra_12.1.3_PUBLIC/Extensions/ARCompact
```

La receta upstream para reconstruir la extensión es `gradle buildExtension`
con `GHIDRA_INSTALL_DIR` apuntando a la distribución Ghidra. La copia del
ZIP fija el artefacto usado en esta entrega. Las pruebas y limitaciones
upstream se conservan en `source/README.md` y `source/GHIDRA-RARE.md`.
La preservación de definiciones y proyectos mantiene la posibilidad de
continuar el análisis. El alcance de cada decompilación se registra en
su carpeta de firmware.
