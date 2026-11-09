import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

/** Preserve ELF segments in their core/link-time spaces before ARC analysis. */
public class MapQuantennaCarrier extends GhidraScript {
    private long uint(ByteBuffer buffer, int offset) {
        return Integer.toUnsignedLong(buffer.getInt(offset));
    }

    private String digest(byte[] bytes) throws Exception {
        StringBuilder text = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }

    private String expected(String role) {
        if (role.equals("muc")) {
            return "71dcd32849f122c09397490914227af6f77e51c34d15615028faa3d0fabb0fe4";
        }
        if (role.equals("auc")) {
            return "c10018f4fe384d753a800bbbcd5ef3c85c568d0852c221009063282d30fd85f6";
        }
        if (role.equals("dsp")) {
            return "87c882910d87cd29ba2004c4154e9240291aaad6aedb0ff4d90c7a5570be79fd";
        }
        throw new IllegalArgumentException("Role must be muc, auc or dsp");
    }

    private boolean conflicts(Address start, long length) throws Exception {
        if (length == 0) {
            return false;
        }
        Address end = start.add(length - 1);
        return currentProgram.getMemory().intersects(start, end);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("MapQuantennaCarrier.java original.bin role output-directory");
        }
        File original = new File(args[0]);
        String role = args[1];
        File output = new File(args[2]);
        output.mkdirs();
        byte[] raw = Files.readAllBytes(original.toPath());
        String sha = digest(raw);
        if (!sha.equals(expected(role))) {
            throw new IllegalArgumentException("Carrier hash differs from the pinned OEM input");
        }
        if (currentProgram.getLanguage().isBigEndian()) {
            throw new IllegalArgumentException("Carrier requires an explicitly little-endian ARC language");
        }
        if (raw.length < 52 || raw[0] != 0x7f || raw[1] != 'E' || raw[2] != 'L' || raw[3] != 'F' ||
                raw[4] != 1 || raw[5] != 1) {
            throw new IllegalArgumentException("Expected ELF32 little-endian carrier");
        }
        ByteBuffer header = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        int machine = Short.toUnsignedInt(header.getShort(18));
        long entry = uint(header, 24);
        long programOffset = uint(header, 28);
        int programSize = Short.toUnsignedInt(header.getShort(42));
        int programCount = Short.toUnsignedInt(header.getShort(44));
        if (machine != 93 || programSize != 32 || programOffset + (long) programSize * programCount > raw.length) {
            throw new IllegalArgumentException("Invalid ARCompact program table");
        }
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.getStart().getAddressSpace().getName().equals("auxregs")) {
                memory.removeBlock(block, monitor);
            }
        }
        FileBytes fileBytes = memory.createFileBytes(original.getName(), 0, raw.length,
                new ByteArrayInputStream(raw), monitor);
        AddressSpace core = currentProgram.getAddressFactory().getDefaultAddressSpace();
        try (PrintWriter plan = new PrintWriter(new File(output, "carrier-segment-plan.tsv"))) {
            plan.println("segment\tfile_offset\tfile_bytes\tmemory_bytes\tvaddr\tpaddr\tflags\tview\tblock\tspace\tstart\tsha256");
            for (int index = 0; index < programCount; index++) {
                monitor.checkCancelled();
                int offset = Math.toIntExact(programOffset + (long) index * programSize);
                long type = uint(header, offset);
                long fileOffset = uint(header, offset + 4);
                long virtual = uint(header, offset + 8);
                long physical = uint(header, offset + 12);
                long fileSize = uint(header, offset + 16);
                long memorySize = uint(header, offset + 20);
                long flags = uint(header, offset + 24);
                if (type != 1 || fileSize > memorySize || fileOffset + fileSize > raw.length ||
                        virtual + memorySize > 0x100000000L) {
                    throw new IllegalArgumentException("Invalid segment " + index);
                }
                boolean info = virtual == 0xffff0000L;
                boolean dspXY = role.equals("dsp") && virtual >= 0xd0000000L && virtual <= 0xdfffffffL;
                String view = info ? "nonloaded_FWINFO" : dspXY ? "nonloaded_DSP_XY_descriptor" : "core_linktime_primary";
                Address start = info || dspXY ? AddressSpace.OTHER_SPACE.getAddress(virtual) : core.getAddress(virtual);
                boolean overlay = info || dspXY || conflicts(start, memorySize);
                if (overlay && !info && !dspXY) {
                    view = "alternate_linktime_overlay";
                }
                String name = String.format("%s_segment_%02d", role, index);
                MemoryBlock initialized = null;
                if (fileSize != 0) {
                    initialized = memory.createInitializedBlock(name, start, fileBytes, fileOffset, fileSize, overlay);
                    initialized.setRead((flags & 4) != 0);
                    initialized.setWrite((flags & 2) != 0);
                    initialized.setExecute(!info && !dspXY && (flags & 1) != 0);
                    initialized.setComment("OEM ELF segment " + index + "; vaddr=0x" + Long.toHexString(virtual) +
                            "; paddr=0x" + Long.toHexString(physical) + "; file_offset=" + fileOffset +
                            "; view=" + view + ". Paddr is retained as provenance, not substituted for core PC.");
                }
                Address actual = initialized != null ? initialized.getStart() : start;
                if (memorySize > fileSize) {
                    Address bssStart = actual.add(fileSize);
                    MemoryBlock bss = memory.createUninitializedBlock(name + "_declared_BSS", bssStart,
                            memorySize - fileSize, initialized == null && overlay);
                    bss.setRead((flags & 4) != 0);
                    bss.setWrite((flags & 2) != 0);
                    bss.setExecute(false);
                    bss.setComment("Declared zero-file-byte memory extent. Target execution state is not observed.");
                    if (initialized == null) {
                        actual = bss.getStart();
                    }
                }
                plan.println(index + "\t" + fileOffset + "\t" + fileSize + "\t" + memorySize + "\t0x" +
                        Long.toHexString(virtual) + "\t0x" + Long.toHexString(physical) + "\t" + flags + "\t" + view +
                        "\t" + name + "\t" + actual.getAddressSpace().getName() + "\t0x" + Long.toHexString(actual.getOffset()) +
                        "\t" + digest(Arrays.copyOfRange(raw, (int) fileOffset, (int) (fileOffset + fileSize))));
            }
        }
        Address entryAddress = core.getAddress(entry);
        MemoryBlock entryBlock = memory.getBlock(entryAddress);
        if (entryBlock == null || !entryBlock.isInitialized() || !entryBlock.isExecute()) {
            throw new IllegalArgumentException("Entry is not backed by an executable primary core block");
        }
        createLabel(entryAddress, role + "_carrier_entry", true, SourceType.USER_DEFINED);
        currentProgram.getSymbolTable().addExternalEntryPoint(entryAddress);
        disassemble(entryAddress);
        // ARC vector slots are verified by the actual installed decoder. No SP/CPU register values are invented.
        for (int slot = 0; slot < (role.equals("muc") ? 1 : 32); slot++) {
            Address vector = entryAddress.add(8L * slot);
            Instruction instruction = getInstructionAt(vector);
            if (instruction == null) {
                disassemble(vector);
                instruction = getInstructionAt(vector);
            }
            if (instruction == null || !instruction.getMnemonicString().equals("j") || instruction.getLength() != 8) {
                break;
            }
            for (Address destination : instruction.getFlows()) {
                MemoryBlock block = memory.getBlock(destination);
                if (block != null && block.isInitialized() && block.isExecute()) {
                    currentProgram.getSymbolTable().addExternalEntryPoint(destination);
                    createLabel(destination, String.format("%s_vector_target_%02d", role, slot), true, SourceType.USER_DEFINED);
                    disassemble(destination);
                }
            }
        }
        try (PrintWriter writer = new PrintWriter(new File(output, "carrier-import.json"))) {
            writer.println("{\"schema\":\"openmitrastar.ghidra-quantenna-preservation/v1\",\"role\":\"" + role +
                    "\",\"sha256\":\"" + sha + "\",\"entry\":\"0x" + Long.toHexString(entry) +
                    "\",\"language\":\"" + currentProgram.getLanguageID() + "\",\"primary_view\":\"core/link-time virtual addresses\"," +
                    "\"duplicate_segments\":\"separate overlays\",\"paddr_substituted_for_pc\":false," +
                    "\"register_state_invented\":false,\"target_executed\":false,\"hardware_accessed\":false}");
        }
        println("QUANTENNA_SEGMENTS_PRESERVED role=" + role + " entry=" + entryAddress + " sha256=" + sha);
    }
}
