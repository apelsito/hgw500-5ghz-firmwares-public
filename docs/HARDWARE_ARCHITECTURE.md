# Arquitectura de procesamiento del HGW500

Evidencia documental del 3 de noviembre de 2026 para el HGW-500BNA-QCv2 A2.
El esquema identifica **cinco unidades programables: una CPU principal y cuatro
coprocesadores**, repartidas entre Quantenna Topaz y Realtek RTL8192EE.

![Arquitectura de procesamiento del HGW500](hardware/hgw500-processing-architecture.png)

El PNG fue aportado por el propietario y se conserva sin modificar. Su SHA-256,
tamaño y dimensiones están en [evidence.json](hardware/evidence.json). La
[transcripción Mermaid editable](hardware/hgw500-processing-architecture.mmd)
reproduce sus bloques y relaciones; no se dispone del archivo Mermaid original.

| Unidad | Ubicación | Función representada |
| --- | --- | --- |
| 1 · LHost ARC750, 500 MHz | Quantenna Topaz | CPU que ejecuta Linux y el driver host |
| 2 · MuC | Quantenna Topaz | Control y MAC de la radio de 5 GHz |
| 3 · AuC | Quantenna Topaz | Aceleración auxiliar de radio/transmisión |
| 4 · DSP | Quantenna Topaz | Procesamiento especializado de radio/señal |
| 5 · MCU 8051 | Realtek RTL8192EE | Microfirmware de la radio de 2,4 GHz |

Son unidades de ejecución integradas. El recuento no determina el número de
encapsulados de la placa ni representa cinco CPU disponibles para SMP Linux.
Las variantes Realtek 19.0 y 35.7 son versiones para la misma MCU y cuentan una vez.

## Memoria y almacenamiento

| Elemento | Evidencia disponible |
| --- | --- |
| SPI NOR | 16 MiB, JEDEC `c22018`; identificación y lectura física contrastadas |
| DDR3 | Perfil OEM de 128 MiB con bus de 16 bits: `DDR_INIT: type = 16, speed = 2, size = 134217728` |
| Ventana Linux actual | `0x8493a000..0x87ffffff`, unos 54,8 MiB; `MemTotal` observado de 51.760 KiB |
| SRAM interna | Utilizada por la etapa temprana; capacidad total pendiente de cerrar |

SPI y DDR son almacenamiento y memoria. TQE, FWT, HBM y DMA son bloques de
hardware especializados y quedan fuera del recuento de unidades con firmware
identificado. La ventana de Linux es una parte de la DDR; el mapa completo de
reservas necesita atribución adicional. Los 128 MiB son el perfil anunciado por
el OEM, sin atribuir a este documento una prueba independiente de toda la RAM.

## Fuentes y alcance

El [manifiesto de evidencia](hardware/evidence.json) conserva los hashes de las
fuentes y capturas locales consultadas y únicamente extractos técnicos revisados.
Las capturas completas de unidad permanecen locales.

- El arranque conservado identifica `ARC750`, una CPU Linux y reloj de 500 MHz.
- El [loader Quantenna preservado](https://github.com/apelsito/hgw500-5ghz-firmwares-public/blob/main/reference-loader/qdrv_fw.c)
  separa `qdrv_fw_load_muc`, `qdrv_fw_load_auc` y `qdrv_fw_load_dsp`.
- Las [interfaces TQE](https://github.com/apelsito/hgw500-5ghz-driver-reverse-engineer-public/blob/main/vendor/legacy-gpl/include/qtn/topaz_tqe_cpuif.h)
  y [HBM](https://github.com/apelsito/hgw500-5ghz-driver-reverse-engineer-public/blob/main/vendor/legacy-gpl/include/qtn/topaz_hbm_cpuif.h)
  distinguen LHost, MuC, AuC y DSP. Los
  [buzones MuC/DSP](https://github.com/apelsito/hgw500-5ghz-driver-reverse-engineer-public/blob/main/vendor/legacy-gpl/include/qtn/txbf_mbox.h)
  y los [comandos MuC/AuC](https://github.com/apelsito/hgw500-5ghz-driver-reverse-engineer-public/blob/main/vendor/legacy-gpl/include/qtn/topaz_shared_params.h)
  documentan las relaciones IPC.
- Los [tres carriers Quantenna](https://github.com/apelsito/hgw500-5ghz-firmwares-public)
  y el [microfirmware 8051](https://github.com/apelsito/hgw500-2ghz-driver-microfirmware-public)
  conservan originales, hashes y análisis separados.

Las flechas de carga/control e IPC resumen interfaces de las fuentes. No son
un diagrama completo de buses ni una traza de actividad simultánea. Los nombres
de función de cada coprocesador son descripciones generales; su reconstrucción
funcional completa y aceptación física requieren evidencia propia.

**«Linux y qdrv» representa el papel del host en la arquitectura. Core Boot R1
todavía no integra físicamente el driver de 5 GHz.** El esquema no concede
aceptación de radio, arranque DDR autónomo ni autorización de escritura de flash.
Este trabajo documental no accedió al dispositivo.
