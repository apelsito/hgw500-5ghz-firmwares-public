# Firmware families and delivered contents

## Two families, several explicitly named checkpoints

| Family/checkpoint | Kernel and packaging | Evidence and source availability |
| --- | --- | --- |
| Original OEM | Linux 2.6.35.12; RAS header, LZMA kernel, aligned SquashFS | Reviewed script/configuration recovery and GPL references; executable recovery is partial |
| OpenMitraStar Core Boot R1 | Linux 7.3; kernel with embedded newc initramfs | Matching PID1 reconstruction, selected overlays and original checkpoint acceptance |
| OpenMitraStar API v2 R3 | Linux 7.3 common kernel; own runtime, native API, management UI and two radios | Later frozen integration source map and recorded 8 November installed acceptance; not identical to Core Boot R1 |

The repository whose name includes `latest-firmware` preserves Core Boot R1.
The main published integration repository also retains an older source snapshot.
Current maintainer source selections can be newer than remote snapshots. A
README update does not publish missing source bodies or provision private build
inputs. Follow the source manifests rather than a folder name or a moving branch.

## What belongs to an installed system

| Area | Contents / ownership |
| --- | --- |
| Early boot | Preserved boot/recovery contracts; custom U-Boot work is separately qualified |
| Kernel | Exact configuration, patches, compiler and Module.symvers for the chosen Linux 7.3 ABI |
| Host drivers | Ethernet/board support, Linux wireless/crypto support, Realtek host stack and Quantenna stack |
| Radio payloads | Realtek 8051 image and three Quantenna generic carriers, each hash-pinned |
| PID1 and runtime | Process startup, module/service ordering, bridge/DHCP and shutdown handling |
| Management | HTTPS server, session/access checks, native control API and LYOKO frontend assets |
| Unit provisioning | Identity, credentials, keys/certificates, calibration and personalized configuration; kept outside Git |

The generic source and metadata describe the installed components. A complete
flash/rootfs dump is not an appropriate substitute: it can include unit secrets
and calibration. No new image is built, installed or inferred as flashable by
these documents. External rootfs/DT/context dependencies remain explicit.

## API v2 R3 module inventory

These 46 entries come from the recorded frozen release source map. Module hashes
and sizes are retained in [firmware-inventory.json](firmware-inventory.json), with
image-relative paths only. The kernel name retains its historical `-ram` suffix;
the suffix alone does not determine whether an image was installed persistently.

| Packaged image path | Bytes |
| --- | --- |
| `modules/aead.ko` | 8,636 |
| `modules/aes.ko` | 19,236 |
| `modules/bridge.ko` | 183,812 |
| `modules/btcoexist.ko` | 170,788 |
| `modules/ccm.ko` | 14,140 |
| `modules/cfg80211.ko` | 391,460 |
| `modules/cmac.ko` | 5,856 |
| `modules/crypto_skcipher.ko` | 23,240 |
| `modules/ctr.ko` | 6,896 |
| `modules/ecb.ko` | 5,540 |
| `modules/firmware_class.ko` | 14,380 |
| `modules/gcm.ko` | 14,528 |
| `modules/gpio.ko` | 12,220 |
| `modules/hgw500_status_leds.ko` | 9,200 |
| `modules/libaes.ko` | 28,652 |
| `modules/libarc4.ko` | 3,144 |
| `modules/libgf128hash.ko` | 6,396 |
| `modules/llc.ko` | 8,792 |
| `modules/mac80211.ko` | 606,880 |
| `modules/quantenna/board_compat.ko` | 29,604 |
| `modules/quantenna/dmautil.ko` | 5,304 |
| `modules/quantenna/fwt_if.ko` | 11,912 |
| `modules/quantenna/gpio.ko` | 12,220 |
| `modules/quantenna/hbm.ko` | 21,884 |
| `modules/quantenna/iputil.ko` | 7,552 |
| `modules/quantenna/om73_sram.ko` | 13,220 |
| `modules/quantenna/qdrv.ko` | 1,371,060 |
| `modules/quantenna/qtn_platform_support.ko` | 8,464 |
| `modules/quantenna/qtn_pm_qos_compat.ko` | 6,696 |
| `modules/quantenna/qtn_tsens.ko` | 5,796 |
| `modules/quantenna/runtime_compat.ko` | 7,572 |
| `modules/quantenna/switch_tqe.ko` | 39,036 |
| `modules/quantenna/switch_vlan.ko` | 20,596 |
| `modules/quantenna/temp_sens.ko` | 5,332 |
| `modules/quantenna/topaz_congest_queue.ko` | 24,604 |
| `modules/quantenna/wlan_ccmp.ko` | 10,028 |
| `modules/quantenna/wlan_scan_ap.ko` | 16,220 |
| `modules/quantenna/wlan_scan_sta.ko` | 19,100 |
| `modules/quantenna/wlan_tkip.ko` | 13,696 |
| `modules/quantenna/wlan_xauth.ko` | 3,744 |
| `modules/rtl8192ee.ko` | 117,840 |
| `modules/rtl_pci.ko` | 51,580 |
| `modules/rtlwifi.ko` | 97,440 |
| `modules/sha256.ko` | 11,552 |
| `modules/stp.ko` | 4,060 |
| `qtn-topaz-emac-eth73.ko` | 31,696 |

## Work still in progress

- Independent reset-to-DDR boot and full memory qualification.
- Complete OEM executable/type recovery and semantics of radio payloads.
- Robust global QDRV/AuC/DSP/DMA shutdown and transition behavior.
- Candidate-specific channel/width transitions, measured RF/DFS/radar qualification and prolonged load.
- Reprovisioning every declared input for a portable full-image rebuild; one matching component does not prove whole-image reproduction.

API v2 R3 has its own recorded installed control/traffic acceptance. That does
not extend acceptance to subsequent RAM candidates or every radio control. This
documentation reads files only and makes no claim about the device's live state.
