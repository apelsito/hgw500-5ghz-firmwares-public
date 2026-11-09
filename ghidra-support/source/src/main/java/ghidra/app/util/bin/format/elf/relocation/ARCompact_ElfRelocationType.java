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

/**
 * ARCompact (ARC600/ARC700) ELF relocation types, numbered as in binutils
 * include/elf/arc-reloc.def.
 */
public enum ARCompact_ElfRelocationType implements ElfRelocationType {

	R_ARC_NONE(0),
	R_ARC_8(1),
	R_ARC_16(2),
	R_ARC_24(3),
	R_ARC_32(4),
	R_ARC_N8(8),
	R_ARC_N16(9),
	R_ARC_N24(10),
	R_ARC_N32(11),
	R_ARC_SDA(12),
	R_ARC_SECTOFF(13),
	R_ARC_S21H_PCREL(14),
	R_ARC_S21W_PCREL(15),
	R_ARC_S25H_PCREL(16),
	R_ARC_S25W_PCREL(17),
	R_ARC_SDA32(18),
	R_ARC_SDA_LDST(19),
	R_ARC_SDA_LDST1(20),
	R_ARC_SDA_LDST2(21),
	R_ARC_SDA16_LD(22),
	R_ARC_SDA16_LD1(23),
	R_ARC_SDA16_LD2(24),
	R_ARC_S13_PCREL(25),
	R_ARC_W(26),
	R_ARC_32_ME(27),
	R_ARC_32_ME_S(105),
	R_ARC_N32_ME(28),
	R_ARC_SECTOFF_ME(29),
	R_ARC_SDA32_ME(30),
	R_ARC_W_ME(31),
	R_ARC_SECTOFF_ME_1(41),
	R_ARC_SECTOFF_ME_2(42),
	R_ARC_SECTOFF_1(43),
	R_ARC_SECTOFF_2(44),
	R_ARC_SDA_12(45),
	R_ARC_SDA16_ST2(48),
	R_ARC_32_PCREL(49),
	R_ARC_PC32(50),
	R_ARC_GOT32(59),
	R_ARC_GOTPC32(51),
	R_ARC_PLT32(52),
	R_ARC_COPY(53),
	R_ARC_GLOB_DAT(54),
	R_ARC_JMP_SLOT(55),
	R_ARC_RELATIVE(56),
	R_ARC_GOTOFF(57),
	R_ARC_GOTPC(58),
	R_ARC_S21W_PCREL_PLT(60),
	R_ARC_S25H_PCREL_PLT(61),
	R_ARC_JLI_SECTOFF(63),
	R_ARC_TLS_DTPMOD(66),
	R_ARC_TLS_TPOFF(68),
	R_ARC_TLS_GD_GOT(69),
	R_ARC_TLS_GD_LD(70),
	R_ARC_TLS_GD_CALL(71),
	R_ARC_TLS_IE_GOT(72),
	R_ARC_TLS_DTPOFF(67),
	R_ARC_TLS_DTPOFF_S9(73),
	R_ARC_TLS_LE_S9(74),
	R_ARC_TLS_LE_32(75),
	R_ARC_S25W_PCREL_PLT(76),
	R_ARC_S21H_PCREL_PLT(77);

	public final int typeId;

	private ARCompact_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
