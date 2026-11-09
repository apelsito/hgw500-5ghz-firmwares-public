#!/usr/bin/env bash
# Decode the corpora with Ghidra and objdump (ARC700 and ARC600) and compare, both byte orders.
#   test/decode-diff.sh <workdir>     (corpora from gen_corpus.py must be in <workdir>)
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS (slotdis binary), BU_OPCODES (binutils opcodes/ dir)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
W=$(readlink -f "$1")
cd "$W"
for e in le be; do
	L=ARCompact:${e^^}:32:default
	eb=little; [[ $e == be ]] && eb=big
	pids=()
	for c in table half fuzz; do
		rm -f g_${c}_$e.txt
		"$HERE/ghidra-slots.sh" "$L" ${c}_$e.bin 10 g_${c}_$e.txt &
		pids+=($!)
	done
	for p in "${pids[@]}"; do wait "$p"; done
	for c in table half fuzz; do
		for m in ARC700 ARC600; do "$SLOTDIS" arc:$m 10 ${c}_$e.bin -e $eb >o_${c}_${e}_$m.txt; done
		python3 "$HERE/compare.py" g_${c}_$e.txt o_${c}_${e}_ARC700.txt,o_${c}_${e}_ARC600.txt 4 \
			--corpus ${c}_$e.bin $e 10 --nps "$BU_OPCODES/arc-nps400-tbl.h" --auxregs "$BU_OPCODES/arc-regs.h" >cmp_${c}_$e.txt
		echo "-- $c $e: $(head -1 cmp_${c}_$e.txt)"
	done
done
