import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.GzfExporter;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;

/** Export Ghidra observations, reconstructed functions and a portable project snapshot. */
public class ExportQuantenna extends GhidraScript {
    private String digest(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }

    private String cell(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    private String filename(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("ExportQuantenna.java output-directory [decompile-timeout-seconds]");
        }
        File output = new File(args[0]);
        output.mkdirs();
        File functionsDir = new File(output, "functions");
        File blocksDir = new File(output, "memory-blocks");
        functionsDir.mkdirs();
        blocksDir.mkdirs();
        int timeout = args.length == 2 ? Integer.parseInt(args[1]) : 15;
        Memory memory = currentProgram.getMemory();
        int blockCount = 0;
        int instructions = 0;
        int mappedInstructions = 0;
        int byteMismatches = 0;
        int functions = 0;
        int reconstructed = 0;
        int failures = 0;

        try (PrintWriter files = new PrintWriter(new File(output, "original-file-bytes.tsv"))) {
            files.println("file\toriginal_name\tfile_offset\tbytes\tsha256");
            int index = 0;
            for (FileBytes source : memory.getAllFileBytes()) {
                monitor.checkCancelled();
                byte[] original = new byte[Math.toIntExact(source.getSize())];
                source.getOriginalBytes(0, original);
                String name = "original-file-" + index + ".bin";
                Files.write(new File(output, name).toPath(), original);
                files.println(name + "\t" + cell(source.getFilename()) + "\t" + source.getFileOffset() +
                        "\t" + original.length + "\t" + digest(original));
                index++;
            }
        }

        try (PrintWriter blocks = new PrintWriter(new File(output, "memory-blocks.tsv"));
                PrintWriter mappings = new PrintWriter(new File(output, "memory-source-ranges.tsv"))) {
            blocks.println("block\tspace\tstart\tlength\tinitialized\tread\twrite\texecute\tfile\tsha256\tcomment");
            mappings.println("block\tspace\tstart\tlength\tfile_offset\tsource_name\tsource_description");
            for (MemoryBlock block : memory.getBlocks()) {
                monitor.checkCancelled();
                String name = String.format("%03d_", blockCount) + filename(block.getName()) + ".bin";
                String sha = "";
                if (block.isInitialized()) {
                    byte[] bytes = new byte[Math.toIntExact(block.getSize())];
                    memory.getBytes(block.getStart(), bytes);
                    Files.write(new File(blocksDir, name).toPath(), bytes);
                    sha = digest(bytes);
                } else {
                    name = "";
                }
                blocks.println(cell(block.getName()) + "\t" + block.getStart().getAddressSpace().getName() + "\t0x" +
                        Long.toHexString(block.getStart().getOffset()) + "\t" + block.getSize() + "\t" +
                        block.isInitialized() + "\t" + block.isRead() + "\t" + block.isWrite() + "\t" + block.isExecute() +
                        "\t" + name + "\t" + sha + "\t" + cell(block.getComment()));
                for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                    long fileOffset = -1;
                    String sourceName = "";
                    if (source.getFileBytes().isPresent()) {
                        FileBytes file = source.getFileBytes().get();
                        fileOffset = file.getFileOffset() + source.getFileBytesOffset();
                        sourceName = file.getFilename();
                    }
                    mappings.println(cell(block.getName()) + "\t" + source.getMinAddress().getAddressSpace().getName() +
                            "\t0x" + Long.toHexString(source.getMinAddress().getOffset()) + "\t" + source.getLength() +
                            "\t" + fileOffset + "\t" + cell(sourceName) + "\t" + cell(source.getDescription()));
                }
                blockCount++;
            }
        }

        try (PrintWriter rows = new PrintWriter(new File(output, "ghidra-instructions.tsv"));
                PrintWriter references = new PrintWriter(new File(output, "ghidra-references.tsv"));
                PrintWriter assembly = new PrintWriter(new File(output, "ghidra-disassembly.S"))) {
            rows.println("space\taddress\tfile_offset\tbytes\tinstruction\tfile_bytes_match");
            references.println("from_space\tfrom\tto_space\tto\ttype");
            assembly.println("; Ghidra instruction inventory with preserved addresses, bytes and original file offsets.");
            InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = iterator.next();
                Address address = instruction.getAddress();
                byte[] bytes = instruction.getBytes();
                AddressSourceInfo source = memory.getAddressSourceInfo(address);
                long offset = source == null ? -1 : source.getFileOffset();
                boolean match = offset >= 0;
                for (int i = 0; i < bytes.length && match; i++) {
                    AddressSourceInfo item = memory.getAddressSourceInfo(address.add(i));
                    match = item != null && item.getFileOffset() == offset + i && item.getOriginalValue() == bytes[i];
                }
                rows.println(address.getAddressSpace().getName() + "\t0x" + Long.toHexString(address.getOffset()) +
                        "\t" + offset + "\t" + hex(bytes) + "\t" + cell(instruction) + "\t" + match);
                assembly.println(address + "\t" + hex(bytes) + "\t" + instruction + "\t; file_offset=" + offset);
                if (offset >= 0) {
                    mappedInstructions++;
                    if (!match) {
                        byteMismatches++;
                    }
                }
                for (Reference reference : instruction.getReferencesFrom()) {
                    references.println(reference.getFromAddress().getAddressSpace().getName() + "\t0x" +
                            Long.toHexString(reference.getFromAddress().getOffset()) + "\t" +
                            reference.getToAddress().getAddressSpace().getName() + "\t0x" +
                            Long.toHexString(reference.getToAddress().getOffset()) + "\t" + reference.getReferenceType());
                }
                instructions++;
            }
        }

        DecompInterface decompiler = new DecompInterface();
        boolean opened = decompiler.openProgram(currentProgram);
        try (PrintWriter inventory = new PrintWriter(new File(output, "ghidra-functions.tsv"))) {
            inventory.println("space\tentry\tname\tbody_bytes\tfile_offset\texternal\tdecompiled\tc_file\tasm_file\terror");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                Address entry = function.getEntryPoint();
                String base = filename(entry.getAddressSpace().getName()) + "_" + Long.toHexString(entry.getOffset());
                String asmName = base + ".asm";
                try (PrintWriter assembly = new PrintWriter(new File(functionsDir, asmName))) {
                    assembly.println("; Ghidra ARC instruction reconstruction. Addresses and bytes are preserved below.");
                    assembly.println("; function " + cell(function.getName()) + " entry " + entry);
                    InstructionIterator body = currentProgram.getListing().getInstructions(function.getBody(), true);
                    while (body.hasNext()) {
                        Instruction instruction = body.next();
                        assembly.println(instruction.getAddress() + "\t" + hex(instruction.getBytes()) + "\t" + instruction);
                    }
                }
                boolean done = false;
                String error = "";
                String cName = "";
                if (!function.isExternal() && opened) {
                    DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                    done = result.decompileCompleted() && result.getDecompiledFunction() != null;
                    if (done) {
                        cName = base + ".c";
                        try (PrintWriter source = new PrintWriter(new File(functionsDir, cName))) {
                            source.println("/* Ghidra pseudocode derived from OEM firmware. */");
                            source.println("/* language " + currentProgram.getLanguageID() + "; entry " + entry + " */");
                            source.println(result.getDecompiledFunction().getC());
                        }
                        reconstructed++;
                    } else {
                        error = result.getErrorMessage();
                        failures++;
                        Files.writeString(new File(functionsDir, base + ".decompile-error.txt").toPath(), String.valueOf(error));
                    }
                } else {
                    error = function.isExternal() ? "external function" : decompiler.getLastMessage();
                }
                AddressSourceInfo entrySource = memory.getAddressSourceInfo(entry);
                inventory.println(entry.getAddressSpace().getName() + "\t0x" + Long.toHexString(entry.getOffset()) + "\t" +
                        cell(function.getName()) + "\t" + function.getBody().getNumAddresses() + "\t" +
                        (entrySource == null ? -1 : entrySource.getFileOffset()) + "\t" + function.isExternal() + "\t" +
                        done + "\t" + cName + "\t" + asmName + "\t" + cell(error));
                functions++;
            }
        } finally {
            decompiler.dispose();
        }
        currentProgram.setExecutablePath(currentProgram.getName());
        currentProgram.getOptions(Program.PROGRAM_INFO).removeOption("FSRL");
        File snapshot = new File(output, "quantenna-analysis.gzf");
        GzfExporter exporter = new GzfExporter();
        // Packed export requires a committed database without this script's active transaction.
        end(true);
        try {
            if (!exporter.export(snapshot, currentProgram, null, monitor)) {
                throw new IllegalStateException("Portable Ghidra project export failed: " + exporter.getMessageLog());
            }
        } finally {
            start();
        }
        try (PrintWriter result = new PrintWriter(new File(output, "ghidra-export.json"))) {
            result.println("{\"schema\":\"openmitrastar.ghidra-quantenna-export/v1\",\"language\":\"" +
                    currentProgram.getLanguageID() + "\",\"compiler\":\"" + currentProgram.getCompilerSpec().getCompilerSpecID() +
                    "\",\"blocks\":" + blockCount + ",\"functions\":" + functions + ",\"instructions\":" + instructions +
                    ",\"file_mapped_instructions\":" + mappedInstructions + ",\"instruction_byte_mismatches\":" + byteMismatches +
                    ",\"decompiled_functions\":" + reconstructed + ",\"decompile_failures\":" + failures +
                    ",\"snapshot\":\"quantenna-analysis.gzf\",\"snapshot_sha256\":\"" + digest(Files.readAllBytes(snapshot.toPath())) +
                    "\",\"target_executed\":false,\"hardware_accessed\":false}");
        }
        println("QUANTENNA_EXPORTED functions=" + functions + " C=" + reconstructed + " instructions=" + instructions +
                " byte_mismatches=" + byteMismatches);
        if (byteMismatches != 0) {
            throw new IllegalStateException("Some instruction bytes differ from their original file mappings");
        }
    }
}
