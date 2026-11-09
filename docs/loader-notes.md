# Relación entre carriers, loader R26 y análisis Ghidra

La referencia seleccionada procede de
`HGW500/drivers/quantenna/src/linux-7.3-r26/source/qdrv/`, revisión de paquete
R26. Las copias de `qdrv_fw.c`, `qdrv_fw.h` y `om73_fw_profiles.h` conservan
los bytes y headers de ese checkout y sirven para contrastar el análisis.

`om73_fw_profiles.h` vincula tamaño y SHA-256 a MuC, AuC_nomU y DSP. El loader
comprueba la identidad completa antes de escribir destinos. Esta comprobación
acredita la selección del carrier que espera esa fuente.

Cada ELF contiene un segmento de 16 bytes en dirección virtual `0xffff0000`.
La estructura `qdrv_fwinfo` lo interpreta como magic de ocho bytes, tipo
little-endian de 32 bits y versión de 32 bits. El loader reconoce `FWINFO`,
exige tipo release 1 y compara la versión con `QDRV_BLD_VER`. Esa entrada es
metadato que el loader omite en la instalación de memoria.

El carrier MuC declara dos segmentos con dirección virtual `0x80020000`.
AuC repite `0xe5000000` y `0xe50073b0`. Las entradas con un `p_paddr` explícito
se mantienen individualmente en el mapa y los listados. El loader emplea
conversiones distintas según coprocesador. Su imagen runtime necesita conservar
esas conversiones, las copias de carga y el orden de instalación de segmentos.

En DSP, las entradas de memoria X/Y en `0xdcf80000` y `0xdcfa0000` declaran
memoria y cero bytes de archivo. El loader conserva su tratamiento específico
y omite esos destinos. La extracción mantiene su descripción y distingue BSS
de los rangos que contienen bytes del carrier original.

Las primeras instrucciones observadas concuerdan con vectores ARC700.
MuC salta de `0xe0000` a `0xe0008`. AuC salta de `0xe5000000` a `0xe50073b0`.
DSP salta de `0x20000` a `0x2012c` y tiene una tabla de saltos de ocho bytes.
Estas direcciones proceden del carrier y su decodificación estática. La relación
con memoria física y ejecución precisa depende de la plataforma y el loader.

## Vista de importación Ghidra

Los tres carriers declaran ELF32 little-endian y `e_machine=93`, ARCompact.
El análisis nativo utiliza Ghidra 12.1.3, `ARCompact:LE:32:default`, compiler
`default`, y la extensión del commit
`41703a7bbac5a316e6e72381af67d5ee0e1d9d25` de `aleph-void/ghidra-arcompact`.
Su fuente completa, licencia y ZIP instalado permanecen en `ghidra-support/`.

La vista principal representa direcciones virtuales del core y de enlace.
Los segmentos que repiten dirección se preservan en overlays separados para
conservar sus bytes y sus relaciones. El importador registra este plan en
`ghidra/carrier-import.json` y `ghidra/carrier-segment-plan.tsv` de cada hijo.
Las copias con paddr de carga mantienen ese dato en el mapa. La selección de PC
usa las direcciones del core. El análisis conserva el estado inicial de registros
como desconocido cuando falta evidencia de runtime.

`ghidra/memory-source-ranges.tsv` vincula los bloques de memoria exportados
con offsets del carrier original. `ghidra/ghidra-instructions.tsv` y los archivos
ASM por función permiten contrastar las instrucciones y sus direcciones.
La verificación independiente comprueba esos rangos e instrucciones contra
el original y registra cobertura de bytes y discrepancias.

Los carriers carecen de tablas de símbolos, secciones y DWARF. Ghidra infiere
nombres y límites de funciones a partir de entradas y flujo de control. El C
exportado conserva esa naturaleza de pseudocódigo. Un segmento RWE puede incluir
código, tablas y datos. Las llamadas indirectas, las extensiones del coprocesador
y el estado de registros todavía desconocido limitan la interpretación.

## Loops LP y preservación del proyecto

El módulo ARCompact conserva los contextos de los loops de coste cero `lp`. En MuC, las reconstrucciones `FUN_ram_8002565c` y `FUN_ram_80025dec` muestran flujos hacia `0x00025ac4` y `0x00025e14`, mientras la vista mapeada usa `0x80025ac4` y `0x80025e14`. Los logs conservan esos flujos sin resolver. La interpretación de esos alias requiere revisión posterior del contexto y del módulo.
Los avisos y contextos descubiertos permanecen en el snapshot y los registros.
El fork documenta además una limitación de `PcodeEmulator` con el contexto de fin
de loop, recogida en `ghidra-support/source/README.md`. Esta campaña conserva
análisis estático y pseudocódigo con sus contextos y avisos.

Cada hijo contiene `ghidra/quantenna-analysis.gzf`. Se reimportó en un proyecto
nuevo y se comparó su estado con el snapshot previo. `ghidra/roundtrip-verification.json`
registra el resultado y las facetas contrastadas. La copia del carrier original,
el GZF, el paquete de la extensión y las herramientas permiten reabrir el análisis.
Los resultados estáticos y su conservación se mantienen separados de una
validación física del comportamiento de la radio.
