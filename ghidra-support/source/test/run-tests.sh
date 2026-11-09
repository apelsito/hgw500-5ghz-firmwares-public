#!/usr/bin/env bash
# ARCompact module tests that need no third-party downloads beyond GNU binutils/toolchain:
#   1. compile both .slaspec files (and the Java ELF support into lib/ for a development install)
#   2. decode corpora vs GNU objdump (-m ARC700 and -m ARC600), both byte orders:
#      every ARC600/ARC700 entry of binutils' arc-tbl.h (8 fillings each), every 16-bit first
#      halfword, 50,000 random slots
#   3. every-entry decode test (CoverageCheck.java, 4 seeds, union)
#   4. p-code emulator tests (EmuCheck.java; arc700 and arc600 sets, both byte orders) and a
#      deliberately broken expectation that must fail
#   5. relocation handler vs GNU ld (test/elf/relocs.s, both byte orders; test/reloc-check.sh)
#   6. if REAL_SAMPLES is set (test/fetch-real-samples.sh output): test/real-binaries.sh
#
#   test/run-tests.sh [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 whose Ghidra/Processors/ARCompact is (a symlink to)
#                       this module directory
#   BU_SRC, BU_LIB      binutils 2.45 source tree (opcodes/arc-tbl.h etc.) and a directory with
#                       libopcodes.a, libbfd.a, libsframe.a, libiberty.a of a build configured
#                       --enable-targets=all (to build test/slotdis.c; BU_LIBIBERTY if libiberty.a
#                       is elsewhere); or SLOTDIS=<binary>
#   ARC_TOOLS           GNU toolchain prefix for the emulator tests, e.g.
#                       .../arcle-750d--uclibc--stable-2025.08-1/bin/arc-linux-
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
source "$HERE/env.sh"
: "${BU_SRC:?set BU_SRC to the binutils 2.45 source tree}" "${ARC_TOOLS:?set ARC_TOOLS}"
W=$(mkdir -p "${1:-arc-test-work}" && cd "${1:-arc-test-work}" && pwd)
cd "$W"

echo "== compiling SLEIGH"
python3 "$MOD/tools/gen_arcompact.py" "$W/ops.sinc"
cmp -s "$W/ops.sinc" "$MOD/data/languages/ARCompact_ops.sinc" || echo "warning: ARCompact_ops.sinc is not the generator's output"
for s in "$MOD"/data/languages/*.slaspec; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "ERROR|^Error" || true
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
[[ -d "$MOD/src" ]] && "$HERE/build-jar.sh"

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_LIB:?set SLOTDIS, or BU_LIB}"
	SLOTDIS=$W/slotdis
	gcc -O2 -DPACKAGE=1 -DPACKAGE_VERSION=1 -o "$SLOTDIS" "$HERE/slotdis.c" -I"$BU_SRC/include" \
		-I"$BU_SRC/bfd" -I"$BU_LIB/../include" "$BU_LIB/libopcodes.a" "$BU_LIB/libbfd.a" \
		"$BU_LIB/libsframe.a" "${BU_LIBIBERTY:-$BU_LIB/libiberty.a}" -lz -lzstd
fi
export SLOTDIS BU_OPCODES=$BU_SRC/opcodes

echo "== decode corpora vs GNU objdump"
python3 "$HERE/gen_corpus.py" "$BU_SRC/opcodes/arc-tbl.h" .
"$HERE/decode-diff.sh" .

echo "== every-entry decode test"
head -c 64 /dev/zero >zero.bin
for l in LE BE; do
	for seed in 1 2 3 4; do
		"$HERE/ghidra-script.sh" raw ARCompact:$l:32:default zero.bin CoverageCheck.java "$W/cov_${l}_$seed.txt" 8192 $seed &
	done
	wait
	tot=$(grep -h '^coverage' cov_${l}_1.txt | sed 's/coverage: \([0-9]*\) constructors.*/\1/')
	un=$(cat cov_${l}_*.txt | grep '^unreached' | sort | uniq -c | awk '$1==4' | wc -l)
	echo "-- ARCompact:$l:32:default: $tot constructors, $((tot - un)) reached by at least one of 4 seeds"
	cat cov_${l}_*.txt | grep '^unreached' | sort | uniq -c | awk '$1==4 {print "   " $0}'
done

echo "== p-code emulator tests"
mkdir -p emu emu_broken
python3 "$HERE/emu_tests.py" emu "$ARC_TOOLS"
python3 "$HERE/emu_tests.py" emu_broken "$ARC_TOOLS" --break 1 >/dev/null
for c in arc700 arc600; do
	for e in le be; do
		"$HERE/ghidra-script.sh" raw "ARCompact:${e^^}:32:default" emu/emu_${c}_$e.bin EmuCheck.java \
			"$W/emu/emu_${c}_$e.txt" "$W/emu/res_${c}_$e.txt" &
	done
done
wait
for c in arc700 arc600; do
	for e in le be; do
		echo "-- $c $e: $(tail -1 emu/res_${c}_$e.txt)"
		grep -v "^PASS\|^emulator" emu/res_${c}_$e.txt || true
	done
done
"$HERE/ghidra-script.sh" raw ARCompact:LE:32:default emu_broken/emu_arc700_le.bin EmuCheck.java \
	"$W/emu_broken/emu_arc700_le.txt" "$W/emu_broken/res.txt"
echo "-- deliberately wrong expectation: $(grep '^FAIL' emu_broken/res.txt || echo 'NOT DETECTED')"

echo "== relocation handler vs GNU ld"
mkdir -p rel
"${ARC_TOOLS}as" -mcpu=arc700 "$HERE/elf/relocs.s" -o rel/relocs_le.o
"${ARC_TOOLS}as" -mcpu=arc700 -EB "$HERE/elf/relocs.s" -o rel/relocs_be.o
"$HERE/reloc-check.sh" "${ARC_TOOLS}ld" "${ARC_TOOLS}objdump" "$W/rel" rel/relocs_le.o
LDFLAGS=-EB "$HERE/reloc-check.sh" "${ARC_TOOLS}ld" "${ARC_TOOLS}objdump" "$W/rel" rel/relocs_be.o

if [[ -n ${REAL_SAMPLES:-} ]]; then
	echo "== real binaries"
	"$HERE/real-binaries.sh" "$REAL_SAMPLES" "$W/real"
fi
