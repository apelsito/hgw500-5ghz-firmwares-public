#!/usr/bin/env bash
# Download the public ARC700 Linux toolchains whose target libraries and programs are the
# real-binary samples of test/real-binaries.sh, check them against pinned SHA-256 sums and
# extract the samples into <dest> (default ./real-samples) as *.elf. Nothing is committed.
#
#   test/fetch-real-samples.sh [dest] [--keep-toolchain]
#
# --keep-toolchain also keeps the Bootlin toolchain in <dest>/toolchain (its arc-linux-as/ld/
# objcopy are what test/run-tests.sh uses for the emulator tests: ARC_TOOLS=<dest>/toolchain/
# arcle-750d--uclibc--stable-2025.08-1/bin/arc-linux-).
#
# Sources (all built from GPL/LGPL sources: uClibc-ng LGPL-2.1, libgcc/libstdc++/libatomic GPL-3.0
# with the GCC Runtime Library Exception, uClibc-ng utils LGPL-2.1):
#   Synopsys ARC GNU toolchain release arc-2024.12, prebuilt uClibc ARC700 Linux, little- and
#   big-endian (github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases):
#     syn-le-* / syn-be-*: libuClibc-1.0.49.so, ld-uClibc-1.0.49.so, libgcc_s.so.1,
#     libatomic.so.1.2.0, libstdc++.so.6.0.33, usr/bin/getconf, iconv, locale, sbin/ldconfig
#   Bootlin toolchain arcle-750d--uclibc--stable-2025.08-1 (toolchains.bootlin.com):
#     bl-le-*: libuClibc-1.0.54.so, ld-uClibc-1.0.54.so, libgcc_s.so.1, libatomic.so.1.2.0
set -euo pipefail
DEST=${1:-real-samples}
KEEP=${2:-}
mkdir -p "$DEST/dl"
cd "$DEST"
get() { # url sha256 file
	if [[ ! -s dl/$3 ]]; then
		curl -fsSL --retry 3 -o "dl/$3.part" "$1"
		mv "dl/$3.part" "dl/$3"
	fi
	echo "$2  dl/$3" | sha256sum -c -
}
SYN=https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2024.12-release
get $SYN/arc_gnu_2024.12_prebuilt_uclibc_le_arc700_linux_install.tar.xz \
	b9e9b6d542caeea42e1df2ff75b417175685735d2630a3e70d52c0e5b27dd109 syn-le.tar.xz
get $SYN/arc_gnu_2024.12_prebuilt_uclibc_be_arc700_linux_install.tar.xz \
	1ff33f884ea2e578089fba880d3ed41d9264dcdc3df8a29180dcfd2aa444211d syn-be.tar.xz
get https://toolchains.bootlin.com/downloads/releases/toolchains/arcle-750d/tarballs/arcle-750d--uclibc--stable-2025.08-1.tar.xz \
	dd0fb263ec10ffd15a4743974af6509a66e705c1da1dc1a72a270702e4567be0 bootlin-le.tar.xz

extract() { # tarball sysroot-prefix out-prefix files...
	local tb=$1 pre=$2 out=$3 t
	shift 3
	t=$(mktemp -d tmp.XXXXXX)
	tar -C "$t" -xJf "dl/$tb" $(printf "$pre/%s " "$@")
	for f in "$@"; do cp "$t/$pre/$f" "$out-$(basename "$f").elf"; done
	rm -rf "$t"
}
SYNFILES=(lib/libuClibc-1.0.49.so lib/ld-uClibc-1.0.49.so lib/libgcc_s.so.1 lib/libatomic.so.1.2.0
	lib/libstdc++.so.6.0.33 usr/bin/getconf usr/bin/iconv usr/bin/locale sbin/ldconfig)
extract syn-le.tar.xz arc-arc700-linux-uclibc/arc-snps-linux-uclibc/sysroot syn-le "${SYNFILES[@]}"
extract syn-be.tar.xz arceb-arc700-linux-uclibc/arceb-snps-linux-uclibc/sysroot syn-be "${SYNFILES[@]}"
extract bootlin-le.tar.xz arcle-750d--uclibc--stable-2025.08-1/arc-buildroot-linux-uclibc/sysroot bl-le \
	lib/libuClibc-1.0.54.so lib/ld-uClibc-1.0.54.so lib/libgcc_s.so.1 lib/libatomic.so.1.2.0
if [[ $KEEP == --keep-toolchain ]]; then
	mkdir -p toolchain
	[[ -d toolchain/arcle-750d--uclibc--stable-2025.08-1 ]] || tar -C toolchain -xJf dl/bootlin-le.tar.xz
fi
ls -l *.elf
