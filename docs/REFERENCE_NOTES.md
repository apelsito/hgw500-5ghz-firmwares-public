# Preserved component notes

Editorial copy of the previous README. Workstation paths are normalized; original source and immutable evidence are not modified. Earlier status claims belong to their named checkpoints, not the live device. Start with the current [README](../README.md).

# HGW500 — firmwares Quantenna de 5 GHz

La ampliación del 5 de noviembre recupera la tabla privada de 2.171 símbolos
de MuC con `muc/tools/recover_symbols.py`. Su análisis nativo adicional local
tiene 1.549 funciones inferidas con C exportado, frente a las 1.137 conservadas
en la entrega original. Los tres carriers y sus proyectos originales no cambian;
ver [la ampliación y sus límites](https://github.com/apelsito/hgw500-5ghz-firmware-muc-public/blob/main/README.md).

La auditoría estática de retirada se reproduce con
`python tools/audit_retirement.py --output out/retirement-NUEVO.json`.
Comprueba los tres hashes, seis símbolos privados MuC y catorce anclas nativas
de parada, excepción e IPC, con dieciocho controles negativos. MuC `KILL`
alcanza el manejador de excepción; completar una orden IPC de AuC no demuestra
la retirada de productores, DSP ni DMA. El informe no autoriza stop/unload o
reset. Los protocolos de parada de AuC y DSP siguen sin cualificar.
La campaña REA del 6 de noviembre y la verificación integral se conservan
localmente en `out/improve-20261106/`; no se han modificado los carriers.

Análisis estático y preservación de los tres carriers OEM Quantenna del HGW500.
Cada coprocesador tiene una carpeta y repositorio privado propio, integrado
como submódulo. Cada hijo conserva el original, inspecciones REA, ensamblador
lineal, análisis nativo Ghidra, pseudocódigo C y un proyecto GZF reabrible.

El 3 de noviembre de 2026 se exportaron **1.487 funciones C inferidas** y
**142.070 instrucciones Ghidra verificadas contra sus bytes originales**.
Los tres proyectos GZF se reimportaron en destinos nuevos y conservaron
igualdad en las 13 facetas de estado comprobadas. [ghidra-manifest.json](../ghidra-manifest.json)
fija los resultados, la versión del procesador y los scripts utilizados.

| Carpeta | Carrier | Bytes | Funciones y C | Instrucciones Ghidra verificadas |
| --- | --- | --- | --- | --- |
| [MuC](https://github.com/apelsito/hgw500-5ghz-firmware-muc-public/blob/main/README.md) | qtn_driver.qtn_ruby.0.bin | 1.094.927 | 1.137 | 110.398 |
| [AuC](https://github.com/apelsito/hgw500-5ghz-firmware-auc-public/blob/main/README.md) | auc_driver.nomu.0.bin | 33.342 | 55 | 1.421 |
| [DSP](https://github.com/apelsito/hgw500-5ghz-firmware-dsp-public/blob/main/README.md) | rdsp_driver.0.bin | 246.244 | 295 | 30.251 |

Los nombres MuC, AuC y DSP están vinculados a esos hashes por el perfil del
driver R26. Los tres son ELF32 little-endian con `e_machine=93`, ARCompact.
Carecen de tabla de secciones, símbolos y DWARF. Los originales mantienen
su identidad en [analysis-manifest.json](../analysis-manifest.json).

## Análisis nativo y conservación

El proveedor actual es Ghidra `12.1.3_PUBLIC`, lenguaje
`ARCompact:LE:32:default`, compiler `default`, con la extensión del commit
`41703a7bbac5a316e6e72381af67d5ee0e1d9d25` de
`aleph-void/ghidra-arcompact`. La [fuente, licencia y paquete instalado](../ghidra-support/README.md)
se conservan con hashes. Cada hijo incluye una copia del ZIP y su licencia
para reabrir su GZF desde un checkout individual.

Cada carpeta `muc/ghidra`, `auc/ghidra` y `dsp/ghidra` contiene el GZF,
C y ASM por función, inventarios, bloques de memoria, offsets originales,
contextos y avisos del análisis. `byte-verification.json` de esa carpeta
contrasta rangos e instrucciones con el carrier original y registra cero
discrepancias de bytes. `roundtrip-verification.json` compara 13 facetas
del proyecto antes y después de reimportar el GZF.

La vista principal usa direcciones virtuales del core y de enlace. Los
segmentos con direcciones repetidas se preservan como overlays separados.
El mapa conserva paddr de carga y mantiene PC en la vista del core. El
estado runtime de registros permanece desconocido cuando falta evidencia.
El [plan y los límites del loader](../docs/loader-notes.md) explican esas vistas.

Las funciones, sus nombres y los límites del C se infieren por análisis
estático. Los segmentos pueden mezclar código y datos. Los avisos sobre
loops LP y alias de direcciones permanecen en los logs y el GZF. En MuC,
las funciones `FUN_ram_8002565c` y `FUN_ram_80025dec` muestran flujos LP hacia
`0x00025ac4` y `0x00025e14`, mientras el código está mapeado en
`0x80025ac4` y `0x80025e14`. Esa interpretación necesita revisión. Las
extensiones específicas y las llamadas indirectas también mantienen
incertidumbres. El conteo de C corresponde a decompilaciones completadas. Las instrucciones verificadas cubren el 41,823 % del archivo MuC, el 11,853 % de AuC y el 42,233 % de DSP. Se conservan avisos Ghidra en 255, 4 y 106 archivos C, respectivamente. La reconstrucción estática es parcial.
La verificación de bytes y reimportación acredita la fidelidad de la
conservación, con la equivalencia funcional pendiente de evidencias propias.

## Evidencia REA y ensamblador lineal

REA 6.8.0 se ejecutó sobre los tres carriers. Entropía, regiones Binwalk y
headers mediante GNU objdump terminaron correctamente. Los recibos originales
de apertura y decompilación conservan `unsupported ELF architecture` para
ARC. El layout adicional registra el proveedor opcional pwntools sin configurar.
El análisis nativo Ghidra preservado amplía esas inspecciones.

Los listados `segments/segment-NN.asm` proceden de GNU objdump ARC 2.45.1,
con `arc:ARC700` y `-EL`. Se conservan diez listados por segmento ejecutable.
La [verificación del ensamblador lineal](../byte-verification.json) contrasta
filas, segmentos y volcados completos. Los tres bytes finales MuC sin fila
objdump permanecen en su segmento y volcado hexadecimal. Las directivas
`.word`, `.long`, `.short` y los avisos de opcode se conservan.

## Cómo leer y reabrir

1. Abrir el README de MuC, AuC o DSP y su mapa ELF.
2. Recorrer `ghidra/ghidra-functions.tsv` y los C/ASM de `ghidra/functions/`.
3. Contrastar direcciones e instrucciones en `ghidra/ghidra-instructions.tsv`
   y offsets en `ghidra/memory-source-ranges.tsv`.
4. Revisar logs, contextos y las notas del loader antes de interpretar alias.
5. Instalar el ZIP ARCompact conservado en Ghidra 12.1.3 con Java 21,
   reiniciar Ghidra e importar `ghidra/quantenna-analysis.gzf` del hijo elegido.

## Repetir y verificar

Clonar el conjunto con sus tres repositorios hijos privados.

```bash
git clone --recurse-submodules https://github.com/apelsito/hgw500-5ghz-firmwares-public.git
cd hgw500-5ghz-firmwares
```

Para una campaña Ghidra nueva, desde la raíz del padre en WSL Engineering,
indicar dos destinos ext4 ausentes.

```bash
python3 tools/ghidra/run_ghidra.py --role auc --input auc/auc_driver.nomu.0.bin --workspace ${EVIDENCE_ROOT}/quantenna-auc-NUEVO-project --output ${EVIDENCE_ROOT}/quantenna-auc-NUEVO-export
```

Cambiar `--role` y `--input` por el coprocesador elegido. El wrapper exige el
nombre y SHA-256 fijados, exporta el análisis, reimporta el GZF en otro proyecto,
compara snapshots y verifica rangos e instrucciones contra el original.
`--ghidra` permite indicar otra distribución compatible. Las mismas herramientas
están en `tools/ghidra/` de cada hijo.

Verificar el checkout con Python 3. El verificador comprueba los tres hijos,
sus inventarios completos, bytes originales y nativos, los GZF y sus 13 facetas,
el paquete ARCompact y la integridad de los archivos del padre. La salida debe
ser un archivo nuevo.

```bash
mkdir -p out
python3 tools/verify.py --root . --output out/byte-verification.json
python3 ghidra-support/verify_support.py
```

La reproducción de las inspecciones REA y del ensamblador lineal conserva
su entrada existente, con salida ausente en ext4 y el objdump ARC fijado.

```bash
python3 tools/analyze.py --source-dir . --output ${EVIDENCE_ROOT}/quantenna-rea-NUEVO --objdump /ruta/arc-snps-linux-uclibc-objdump
```

`--source-dir .` utiliza los originales de los submódulos. También admite
el directorio plano local `../HGW500/firmware/radio`. El objdump usado en la
entrega tiene SHA-256
`96784aca5469a645953814ad4f1672a2063154427c2c51e4a9fcbbf13dcb6f3a`.
La copia local está en
`${EVIDENCE_ROOT}/hgw500-quantenna-firmwares-20261103/tools/arc-objdump`.

La referencia GPL del loader conserva sus avisos. La extensión ARCompact
conserva Apache 2.0 y sus créditos. Los carriers mantienen sus bytes OEM y
procedencia. El propietario autorizó conservar los tres coprocesadores y
sus análisis en GitHub privado de apelsito.

## Arquitectura de procesamiento del HGW500

El [esquema y sus evidencias](../docs/HARDWARE_ARCHITECTURE.md), conservados el
3 de noviembre de 2026, identifican una CPU LHost ARC750 a 500 MHz y cuatro
coprocesadores: MuC, AuC, DSP y la MCU 8051 del RTL8192EE. Incluyen el inventario
SPI NOR de 16 MiB y el perfil DDR3 OEM de 128 MiB, con fuentes y límites.

![Arquitectura de procesamiento del HGW500](../docs/hardware/hgw500-processing-architecture.png)

El diagrama es una vista conceptual. La etiqueta qdrv describe el papel del
host; la integración física de 5 GHz en Core Boot R1 sigue pendiente.
