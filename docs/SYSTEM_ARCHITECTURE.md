# HGW500 processing architecture

This is a software/control model for the HGW-500BNA-QCv2 A2, based on preserved
boot evidence, driver loaders and memory-interface headers. It is not a board
schematic or a claim that all five units are Linux SMP CPUs.

```mermaid
flowchart TB
    subgraph TOPAZ["Quantenna Topaz"]
        L["LHost ARC750 / 500 MHz / Linux"]
        M["MuC / radio MAC and control"]
        A["AuC / auxiliary radio acceleration"]
        D["DSP / radio processing"]
        X["Shared-memory IPC / TQE / HBM / DMA"]
        L -->|"firmware loading and commands"| M
        L -->|"firmware loading and commands"| A
        L -->|"firmware loading and commands"| D
        L <--> X
        M <--> X
        A <--> X
        D <--> X
    end
    subgraph RTL["Realtek RTL8192EE / 2.4 GHz"]
        R["PCIe radio and host interface"]
        U["8051 MCU / microfirmware"]
        R <--> U
    end
    L -->|"Linux host driver / PCIe"| R
    F["16 MiB SPI NOR"] --> L
    RAM["DDR3 / OEM-reported 128 MiB profile"] <--> L
```

| Execution unit | What runs there | Relevant repository |
| --- | --- | --- |
| LHost ARC750 | Linux, host radio drivers and userland | Integration and Linux 7.3 host-driver ports |
| MuC | Generic Quantenna MAC/control carrier | Quantenna firmware collection / MuC |
| AuC | Generic auxiliary carrier | Quantenna firmware collection / AuC |
| DSP | Generic radio-processing carrier | Quantenna firmware collection / DSP |
| Realtek 8051 | 19.0 or 35.7 microfirmware variant | Realtek microfirmware analysis |

The Quantenna carrier ELFs identify ARCompact, little-endian, machine 93. The
analysis backend is ARCompact:LE:32:default. Extension and loop semantics retain
explicit limitations. The 8051 analysis instead uses 8051:BE:16:default. A host
module is ARC code for Linux; it is not the same program as either radio payload.

The 128 MiB figure is the OEM DDR profile, not proof that Linux owns all RAM or
that an independent DDR initializer has qualified every byte. Recorded Linux
memory windows are smaller. SRAM capacity and all memory reservations still need
complete attribution. TQE/HBM/FWT/DMA are hardware blocks, not extra Linux CPUs.

## Original and replacement software

```mermaid
flowchart LR
    O["Original OEM family"] --> O1["Linux 2.6.35.12 / vendor modules / SquashFS"]
    O1 --> G["Generic radio payloads and board contracts"]
    N["OpenMitraStar family"] --> N1["Linux 7.3 / ported host modules / initramfs / own services"]
    N1 --> G
    N1 --> H["LYOKO HTTPS management and native API"]
    B["Preserved boot/recovery foundation"] --> O1
    B --> N1
    U["Custom U-Boot work"] -. "own reset-to-DDR remains separate" .-> B
```

Reusing a radio payload does not mean its whole semantics have been recovered.
Custom U-Boot builds have been booted/tested in the project; this is not evidence
that a completely independent boot chain and DDR initialization are finished.

## Evidence vocabulary

Original bytes, inferred pseudocode, compilable reconstruction, paired build,
RAM boot, persistent boot, client association, traffic and release acceptance
are different claims. Each belongs to a particular source selection and image.
The diagrams explain ownership and dependencies; they do not grant a physical gate.
