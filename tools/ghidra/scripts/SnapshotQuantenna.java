import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/** Canonical read-only snapshot for preservation and GZF import comparisons. */
public class SnapshotQuantenna extends GhidraScript {
    private final Map<String, Object> manifest = new TreeMap<>();
    private final Map<String, Object> artifacts = new TreeMap<>();
    private File output;
    private File outputJson;

    private AddressSet allAddresses() {
        AddressSet universe = new AddressSet();
        for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
            if (space.isMemorySpace() || space.getType() == AddressSpace.TYPE_EXTERNAL) {
                universe.add(space.getMinAddress(), space.getMaxAddress());
            }
        }
        return universe;
    }

    private String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private String sha(byte[] bytes) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private String textHash(String value) throws Exception {
        return value == null ? "" : sha(value.getBytes(StandardCharsets.UTF_8));
    }

    private String cell(Object value) {
        if (value == null) {
            return "";
        }
        return String.valueOf(value).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\r", "\\r").replace("\n", "\\n");
    }

    private String row(Object... values) {
        List<String> cells = new ArrayList<>();
        for (Object value : values) {
            cells.add(cell(value));
        }
        return String.join("\t", cells);
    }

    private String address(Address value) {
        return value == null ? "" : value.getAddressSpace().getName() + ":" + value.toString(false);
    }

    private String basename(String path) {
        if (path == null) {
            return "";
        }
        String normalized = path.replace('\\', '/');
        return normalized.substring(normalized.lastIndexOf('/') + 1);
    }

    private String body(AddressSetView set) {
        List<String> ranges = new ArrayList<>();
        AddressRangeIterator iterator = set.getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            ranges.add(address(range.getMinAddress()) + ".." + address(range.getMaxAddress()));
        }
        Collections.sort(ranges);
        return String.join(",", ranges);
    }

    private void write(String name, String header, List<String> rows) throws Exception {
        Collections.sort(rows);
        byte[] bytes = (header + "\n" + String.join("\n", rows) + (rows.isEmpty() ? "" : "\n"))
            .getBytes(StandardCharsets.UTF_8);
        Files.write(new File(output, name + ".tsv").toPath(), bytes);
        Map<String, Object> entry = new TreeMap<>();
        entry.put("rows", rows.size());
        entry.put("bytes", bytes.length);
        entry.put("sha256", sha(bytes));
        artifacts.put(name + ".tsv", entry);
    }

    private String memoryHash(MemoryBlock block) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        long offset = 0;
        while (offset < block.getSize()) {
            monitor.checkCancelled();
            int wanted = (int) Math.min(buffer.length, block.getSize() - offset);
            int read = currentProgram.getMemory().getBytes(block.getStart().add(offset), buffer, 0, wanted);
            if (read != wanted) {
                throw new IllegalStateException("Incomplete initialized memory read");
            }
            digest.update(buffer, 0, read);
            offset += read;
        }
        return hex(digest.digest());
    }

    private String originalBytesHash(FileBytes source) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        long offset = 0;
        while (offset < source.getSize()) {
            monitor.checkCancelled();
            int wanted = (int) Math.min(buffer.length, source.getSize() - offset);
            int read = source.getOriginalBytes(offset, buffer, 0, wanted);
            if (read != wanted) {
                throw new IllegalStateException("Incomplete stored original file read");
            }
            digest.update(buffer, 0, read);
            offset += read;
        }
        return hex(digest.digest());
    }

    private void memory() throws Exception {
        List<String> blocks = new ArrayList<>();
        List<String> sources = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            blocks.add(row(block.getName(), address(block.getStart()), address(block.getEnd()),
                block.getSize(), block.getType(), block.isInitialized(), block.isRead(), block.isWrite(),
                block.isExecute(), block.isVolatile(), block.isArtificial(),
                block.isInitialized() ? memoryHash(block) : "", textHash(block.getComment())));
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                FileBytes fileBytes = source.getFileBytes().orElse(null);
                sources.add(row(block.getName(), address(source.getMinAddress()), address(source.getMaxAddress()),
                    source.getLength(), source.getFileBytesOffset(),
                    fileBytes == null ? "" : basename(fileBytes.getFilename())));
            }
        }
        write("memory-blocks", "name\tstart\tend\tbytes\ttype\tinitialized\tread\twrite\texecute\tvolatile\tartificial\tsha256\tcomment_sha256", blocks);
        write("memory-sources", "block\tstart\tend\tbytes\tfile_bytes_offset\tfile_basename", sources);
        List<String> files = new ArrayList<>();
        for (FileBytes source : memory.getAllFileBytes()) {
            files.add(row(basename(source.getFilename()), source.getFileOffset(), source.getSize(), originalBytesHash(source)));
        }
        write("original-file-bytes", "basename\tfile_offset\tbytes\tsha256", files);
    }

    private void listing() throws Exception {
        Listing listing = currentProgram.getListing();
        List<String> instructions = new ArrayList<>();
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            instructions.add(row(address(instruction.getAddress()), instruction.getLength(),
                hex(instruction.getBytes()), instruction.toString(), instruction.getFlowType(),
                address(instruction.getFallThrough())));
        }
        write("instructions", "address\tlength\tbytes_hex\ttext\tflow_type\tfallthrough", instructions);
        List<String> data = new ArrayList<>();
        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data item = dataIterator.next();
            data.add(row(address(item.getAddress()), item.getLength(), item.getDataType().getPathName()));
        }
        write("defined-data", "address\tlength\tdatatype", data);
        List<String> comments = new ArrayList<>();
        AddressIterator addresses = listing.getCommentAddressIterator(allAddresses(), true);
        while (addresses.hasNext()) {
            Address position = addresses.next();
            for (CommentType type : CommentType.values()) {
                String comment = listing.getComment(type, position);
                if (comment != null) {
                    comments.add(row(address(position), type.name(), comment.length(), textHash(comment)));
                }
            }
        }
        write("comments", "address\ttype\tcharacters\ttext_sha256", comments);
    }

    private void functions() throws Exception {
        List<String> functions = new ArrayList<>();
        List<String> variables = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            functions.add(row(address(function.getEntryPoint()), function.getName(true), body(function.getBody()),
                function.getPrototypeString(true, false), function.getCallingConventionName(),
                function.isThunk(), function.hasVarArgs(), function.hasNoReturn(), function.getSignatureSource(),
                textHash(function.getComment()), textHash(function.getRepeatableComment())));
            for (Variable variable : function.getAllVariables()) {
                variables.add(row(address(function.getEntryPoint()), variable.getName(), variable.getDataType().getPathName(),
                    variable.getVariableStorage().toString(), variable.getFirstUseOffset(),
                    variable.getSource(), textHash(variable.getComment())));
            }
        }
        write("functions", "entry\tname\tbody\tprototype\tcalling_convention\tthunk\tvarargs\tnoreturn\tsignature_source\tcomment_sha256\trepeatable_comment_sha256", functions);
        write("variables", "function_entry\tname\tdatatype\tstorage\tfirst_use\tsource\tcomment_sha256", variables);
    }

    private void symbolsAndReferences() throws Exception {
        List<String> symbols = new ArrayList<>();
        SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            symbols.add(row(address(symbol.getAddress()), symbol.getName(true), symbol.getSymbolType(),
                symbol.getSource(), symbol.isPrimary(), symbol.isPinned(), symbol.isExternal()));
        }
        write("symbols", "address\tname\ttype\tsource\tprimary\tpinned\texternal", symbols);
        List<String> references = new ArrayList<>();
        ReferenceManager manager = currentProgram.getReferenceManager();
        AddressIterator sources = manager.getReferenceSourceIterator(allAddresses(), true);
        while (sources.hasNext()) {
            for (Reference reference : manager.getReferencesFrom(sources.next())) {
                references.add(row(address(reference.getFromAddress()), address(reference.getToAddress()),
                    reference.getOperandIndex(), reference.getReferenceType(), reference.getSource(),
                    reference.isPrimary(), reference.isExternalReference()));
            }
        }
        write("references", "from\tto\toperand\ttype\tsource\tprimary\texternal", references);
        List<String> bookmarks = new ArrayList<>();
        Iterator<Bookmark> bookmarkIterator = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (bookmarkIterator.hasNext()) {
            Bookmark bookmark = bookmarkIterator.next();
            bookmarks.add(row(address(bookmark.getAddress()), bookmark.getTypeString(), bookmark.getCategory(), textHash(bookmark.getComment())));
        }
        write("bookmarks", "address\ttype\tcategory\tcomment_sha256", bookmarks);
    }

    private void datatypes() throws Exception {
        List<String> types = new ArrayList<>();
        List<String> details = new ArrayList<>();
        Iterator<DataType> iterator = currentProgram.getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            DataType type = iterator.next();
            String path = type.getPathName();
            types.add(row(path, type.getClass().getSimpleName(), type.getLength(), type.getAlignment(), textHash(type.getDescription())));
            if (type instanceof Composite) {
                for (DataTypeComponent component : ((Composite) type).getComponents()) {
                    details.add(row(path, "component", component.getOrdinal(), component.getOffset(), component.getLength(),
                        component.getDataType().getPathName(), component.getFieldName(), textHash(component.getComment())));
                }
            }
            if (type instanceof Array) {
                Array array = (Array) type;
                details.add(row(path, "array", array.getNumElements(), array.getElementLength(), array.getDataType().getPathName()));
            }
            if (type instanceof Pointer) {
                DataType target = ((Pointer) type).getDataType();
                details.add(row(path, "pointer", target == null ? "" : target.getPathName()));
            }
            if (type instanceof TypeDef) {
                details.add(row(path, "typedef", ((TypeDef) type).getDataType().getPathName()));
            }
            if (type instanceof BitFieldDataType) {
                BitFieldDataType field = (BitFieldDataType) type;
                details.add(row(path, "bitfield", field.getBitSize(), field.getBitOffset(), field.getBaseDataType().getPathName()));
            }
            if (type instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum enumeration = (ghidra.program.model.data.Enum) type;
                for (String name : enumeration.getNames()) {
                    details.add(row(path, "enum", name, enumeration.getValue(name), textHash(enumeration.getComment(name))));
                }
            }
            if (type instanceof FunctionDefinition) {
                FunctionDefinition function = (FunctionDefinition) type;
                details.add(row(path, "function", function.getReturnType().getPathName(), function.getCallingConventionName(), function.hasVarArgs()));
                for (ParameterDefinition parameter : function.getArguments()) {
                    details.add(row(path, "parameter", parameter.getOrdinal(), parameter.getName(), parameter.getDataType().getPathName(), textHash(parameter.getComment())));
                }
            }
        }
        write("datatypes", "path\tclass\tlength\talignment\tdescription_sha256", types);
        write("datatype-details", "path\tkind\tfields", details);
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("SnapshotQuantenna.java NEW_OUTPUT_JSON");
        }
        outputJson = new File(arguments[0]).getAbsoluteFile();
        String stem = outputJson.getName().replaceFirst("\\.json$", "");
        output = new File(outputJson.getParentFile(), stem + ".facets");
        if (outputJson.exists() || output.exists() || !output.mkdirs()) {
            throw new IllegalArgumentException("Choose an absent JSON and facets directory");
        }
        manifest.put("schema", "openmitrastar.ghidra-program-snapshot/v1");
        manifest.put("ghidra_version", Application.getApplicationVersion());
        manifest.put("language_id", currentProgram.getLanguageID().toString());
        manifest.put("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        manifest.put("image_base", address(currentProgram.getImageBase()));
        manifest.put("default_pointer_size", currentProgram.getDefaultPointerSize());
        manifest.put("executable_sha256", currentProgram.getExecutableSHA256());
        manifest.put("executable_format", currentProgram.getExecutableFormat());
        memory();
        listing();
        functions();
        symbolsAndReferences();
        datatypes();
        manifest.put("artifacts", artifacts);
        manifest.put("comment_content_export", "sha256 only");
        manifest.put("omitted_container_metadata", "storage project path, program name, executable path, timestamps, database IDs");
        Files.writeString(outputJson.toPath(),
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(manifest) + "\n", StandardCharsets.UTF_8);
        println("Canonical read-only snapshot exported");
    }
}
