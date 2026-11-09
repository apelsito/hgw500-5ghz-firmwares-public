/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.NotFoundException;

/**
 * ELF relocation handler for ARCompact (EM_ARC_COMPACT = 93; ARC600 and ARC700).
 * <p>
 * Formulas follow binutils bfd/elf32-arc.c and include/elf/arc-reloc.def. Instruction
 * relocations ("ME") work on the instruction word in its natural bit order: in little-endian
 * files a 32-bit instruction or long immediate is stored as two halfwords, high halfword
 * first. P is the 32-bit aligned address of the instruction (for 32-bit fields, the address of
 * the instruction before the long immediate). Dynamic relocations (RELATIVE, GLOB_DAT,
 * JMP_SLOT, 32) are plain data words, as the uClibc and glibc dynamic linkers write them.
 * GOT/PLT-building and TLS relocations are reported, not applied.
 */
public class ARCompact_ElfRelocationHandler extends
		AbstractElfRelocationHandler<ARCompact_ElfRelocationType, ElfRelocationContext<?>> {

	public static final int EM_ARC_COMPACT = 93;

	public ARCompact_ElfRelocationHandler() {
		super(ARCompact_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == EM_ARC_COMPACT;
	}

	@Override
	public int getRelrRelocationType() {
		return ARCompact_ElfRelocationType.R_ARC_RELATIVE.typeId;
	}

	/** Read a 32-bit instruction word in natural bit order. */
	private static int getInsn(Memory mem, Address a, boolean bigEndian)
			throws MemoryAccessException {
		int w = mem.getInt(a);
		return bigEndian ? w : (w >>> 16) | (w << 16);
	}

	private static void putInsn(Memory mem, Address a, boolean bigEndian, int insn)
			throws MemoryAccessException {
		mem.setInt(a, bigEndian ? insn : (insn >>> 16) | (insn << 16));
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> ctx, ElfRelocation relocation,
			ARCompact_ElfRelocationType type, Address relocationAddress, ElfSymbol elfSymbol,
			Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory mem = program.getMemory();
		boolean be = ctx.getElfHeader().isBigEndian();
		long A = relocation.getAddend();
		long addr = relocationAddress.getOffset();
		int symIndex = relocation.getSymbolIndex();

		switch (type) {
			case R_ARC_NONE:
				return RelocationResult.SKIPPED;
			case R_ARC_RELATIVE:
				mem.setInt(relocationAddress,
					(int) (ctx.getImageBaseWordAdjustmentOffset() + A +
						(relocation.hasAddend() ? 0 : mem.getInt(relocationAddress))));
				return new RelocationResult(Status.APPLIED, 4);
			case R_ARC_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symIndex,
					elfSymbol.getSize(), ctx.getLog());
				return RelocationResult.UNSUPPORTED;
			default:
				break;
		}

		if (handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		long S = symbolValue;
		long v = S + A;
		long P = addr & ~3L;
		switch (type) {
			case R_ARC_32:
			case R_ARC_GLOB_DAT:
			case R_ARC_JMP_SLOT:
				mem.setInt(relocationAddress, (int) v);
				return new RelocationResult(Status.APPLIED, 4);
			case R_ARC_16:
				mem.setShort(relocationAddress, (short) v);
				return new RelocationResult(Status.APPLIED, 2);
			case R_ARC_8:
				mem.setByte(relocationAddress, (byte) v);
				return new RelocationResult(Status.APPLIED, 1);
			case R_ARC_32_PCREL:
				mem.setInt(relocationAddress, (int) (v - addr));
				return new RelocationResult(Status.APPLIED, 4);
			case R_ARC_32_ME:
				putInsn(mem, relocationAddress, be, (int) v);
				return new RelocationResult(Status.APPLIED, 4);
			case R_ARC_PC32:
				putInsn(mem, relocationAddress, be, (int) (v - ((addr - 4) & ~3L)));
				return new RelocationResult(Status.APPLIED, 4);
			case R_ARC_GOTOFF: {
				long got;
				try {
					got = ctx.getGOTValue();
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						"_GLOBAL_OFFSET_TABLE_ not found", ctx.getLog());
					return RelocationResult.FAILURE;
				}
				putInsn(mem, relocationAddress, be, (int) (v - got));
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_ARC_S21H_PCREL:
			case R_ARC_S21H_PCREL_PLT: {
				int d = (int) ((v - P) >> 1);
				int insn = getInsn(mem, relocationAddress, be) & ~0x7feffc0;
				insn |= ((d & 0x3ff) << 17) | (((d >> 10) & 0x3ff) << 6);
				putInsn(mem, relocationAddress, be, insn);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_ARC_S21W_PCREL:
			case R_ARC_S21W_PCREL_PLT: {
				int d = (int) ((v - P) >> 2);
				int insn = getInsn(mem, relocationAddress, be) & ~0x7fcffc0;
				insn |= ((d & 0x1ff) << 18) | (((d >> 9) & 0x3ff) << 6);
				putInsn(mem, relocationAddress, be, insn);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_ARC_S25H_PCREL:
			case R_ARC_S25H_PCREL_PLT: {
				int d = (int) ((v - P) >> 1);
				int insn = getInsn(mem, relocationAddress, be) & ~0x7feffcf;
				insn |= ((d & 0x3ff) << 17) | (((d >> 10) & 0x3ff) << 6) | ((d >> 20) & 0xf);
				putInsn(mem, relocationAddress, be, insn);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_ARC_S25W_PCREL:
			case R_ARC_S25W_PCREL_PLT: {
				int d = (int) ((v - P) >> 2);
				int insn = getInsn(mem, relocationAddress, be) & ~0x7fcffcf;
				insn |= ((d & 0x1ff) << 18) | (((d >> 9) & 0x3ff) << 6) | ((d >> 19) & 0xf);
				putInsn(mem, relocationAddress, be, insn);
				return new RelocationResult(Status.APPLIED, 4);
			}
			case R_ARC_S13_PCREL: {
				int d = (int) ((v - P) >> 2);
				short insn = mem.getShort(relocationAddress);
				mem.setShort(relocationAddress, (short) ((insn & ~0x7ff) | (d & 0x7ff)));
				return new RelocationResult(Status.APPLIED, 2);
			}
			default:
				// GOT/PLT construction (GOTPC32, PLT32, GOT32, GOTPC), small-data, section
				// offsets and TLS need linker state
				markAsUnhandled(program, relocationAddress, type, symIndex, symbolName,
					ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
	}
}
