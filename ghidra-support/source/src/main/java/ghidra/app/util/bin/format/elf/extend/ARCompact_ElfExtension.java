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
package ghidra.app.util.bin.format.elf.extend;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * ELF extension for ARCompact (ARC600/ARC700).
 * <p>
 * The PLT (bfd elf32-arc.c, ARC700 "plt_v1") starts with a 24-byte header, of which the last
 * four bytes after "j [r10]" are data, and continues with 12-byte entries
 * <pre>
 *   ld    r12,[pcl,slot-pcl]   ; 2730 7f8c + long immediate
 *   j_s.d [r12]
 *   mov_s r12,pcl
 * </pre>
 * Ghidra's default PLT markup assumes a 16-byte header and disassembles the rest of .plt
 * linearly, running into the header's data. This extension marks that data, disassembles each
 * entry and labels it with the symbol of the R_ARC_JMP_SLOT relocation of its GOT slot, so the
 * default markup turns the entries into thunks of the named external functions.
 */
public class ARCompact_ElfExtension extends ElfExtension {

	public static final int EM_ARC_COMPACT = 93;
	private static final int JMP_SLOT = 55; // R_ARC_JMP_SLOT
	private static final int LD_R12_PCL_LIMM = 0x27307f8c;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == EM_ARC_COMPACT;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"ARCompact".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_ARCompact";
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		processPlt(elfLoadHelper, monitor);
		super.processGotPlt(elfLoadHelper, monitor);
	}

	private static int insn(Memory mem, Address a, boolean be) throws MemoryAccessException {
		int w = mem.getInt(a);
		return be ? w : (w >>> 16) | (w << 16);
	}

	private void processPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {
		Program program = elfLoadHelper.getProgram();
		ElfHeader elf = elfLoadHelper.getElfHeader();
		Memory mem = program.getMemory();
		MemoryBlock plt = mem.getBlock(ElfSectionHeaderConstants.dot_plt);
		if (plt == null || !plt.isInitialized() || elf.isRelocatable()) {
			return;
		}
		boolean be = elf.isBigEndian();
		long adj = elfLoadHelper.getImageBaseWordAdjustmentOffset();
		Map<Long, String> slotNames = new HashMap<>();
		for (ElfRelocationTable table : elf.getRelocationTables()) {
			ElfSymbolTable symtab = table.getAssociatedSymbolTable();
			if (symtab == null) {
				continue;
			}
			ElfSymbol[] syms = symtab.getSymbols();
			for (ElfRelocation r : table.getRelocations()) {
				int idx = r.getSymbolIndex();
				if (r.getType() != JMP_SLOT || idx <= 0 || idx >= syms.length) {
					continue;
				}
				String name = syms[idx].getNameAsString();
				if (name != null && !name.isEmpty()) {
					slotNames.put((r.getOffset() + adj) & 0xffffffffL, name);
				}
			}
		}
		Address first = null;
		AddressSet entries = new AddressSet();
		try {
			for (Address a = plt.getStart(); a.add(11).compareTo(plt.getEnd()) <= 0;) {
				if (insn(mem, a, be) != LD_R12_PCL_LIMM) {
					a = a.add(first == null ? 2 : 12);
					continue;
				}
				if (first == null) {
					first = a;
				}
				long slot = ((a.getOffset() & ~3L) + insn(mem, a.add(4), be)) & 0xffffffffL;
				entries.add(a, a.add(11));
				String name = slotNames.get(slot);
				if (name != null) {
					Symbol sym = program.getSymbolTable().getPrimarySymbol(a);
					if (sym == null || sym.getSource() == SourceType.DEFAULT) {
						program.getSymbolTable().createLabel(a, name, SourceType.IMPORTED);
					}
				}
				a = a.add(12);
			}
			if (first == null) {
				return;
			}
			// the header's code ends with "j [r10]"; the bytes after it are data
			Address hdr = plt.getStart();
			for (Address a = hdr; a.add(3).compareTo(first) < 0; a = a.add(2)) {
				if (insn(mem, a, be) == 0x20200280) { // j [r10]
					for (Address d = a.add(4); d.add(3).compareTo(first) <= 0; d = d.add(4)) {
						program.getListing().createData(d, DWordDataType.dataType);
					}
					break;
				}
			}
			Disassembler dis = Disassembler.getDisassembler(program, monitor, m -> {
				/* silent */ });
			dis.disassemble(hdr, new AddressSet(hdr, first.subtract(1)), false);
			dis.disassemble(entries.getMinAddress(), entries, false);
		}
		catch (Exception e) {
			elfLoadHelper.log("ARCompact: PLT markup failed: " + e.getMessage());
		}
	}
}
