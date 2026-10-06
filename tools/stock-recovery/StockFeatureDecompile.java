// Bounded stock feature decompilation; pseudocode is evidence, not verified source.
//@category StockRecovery
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class StockFeatureDecompile extends GhidraScript {
    private JsonArray types;
    private final Map<Integer, DataType> cache = new HashMap<>();
    private DataType datatype(int id) {
        if (id == 0) return VoidDataType.dataType;
        if (cache.containsKey(id)) return cache.get(id);
        JsonObject type = types.get(id).getAsJsonObject();
        int kind = type.get("kind").getAsInt(), size = type.get("size").getAsInt();
        String name = type.get("name").getAsString();
        DataType result;
        switch (kind) {
            case 1:
                boolean signed = (type.getAsJsonArray("raw").get(0).getAsLong() & 0x01000000L) != 0;
                if (name.equals("_Bool")) result = BooleanDataType.dataType;
                else if (size == 8) result = signed ? LongLongDataType.dataType : UnsignedLongLongDataType.dataType;
                else if (size == 4) result = signed ? IntegerDataType.dataType : UnsignedIntegerDataType.dataType;
                else if (size == 2) result = signed ? ShortDataType.dataType : UnsignedShortDataType.dataType;
                else if (size == 1) result = signed ? CharDataType.dataType : UnsignedCharDataType.dataType;
                else result = Undefined.getUndefinedDataType(size);
                break;
            case 2:
                result = new PointerDataType(datatype(size), 8, currentProgram.getDataTypeManager()); break;
            case 3:
                JsonArray array = type.getAsJsonArray("raw");
                DataType element = datatype(array.get(0).getAsInt());
                result = new ArrayDataType(element, array.get(2).getAsInt(), element.getLength()); break;
            case 4: case 5: case 7:
                // Opaque named record only: exact BTF fields stay in btf-contracts.json.
                result = new StructureDataType(new CategoryPath("/StockBTF"),
                    (name.isEmpty() ? "anonymous" : name) + "_btf" + id,
                    kind == 7 ? 0 : size, currentProgram.getDataTypeManager());
                break;
            case 6: case 19:
                result = size == 8 ? LongLongDataType.dataType : IntegerDataType.dataType; break;
            case 8: case 9: case 10: case 11: case 18:
                result = datatype(size); break;
            case 13:
                FunctionDefinitionDataType callback = new FunctionDefinitionDataType("btf_callback" + id);
                cache.put(id, callback);
                callback.setReturnType(datatype(size));
                JsonArray arguments = type.getAsJsonArray("raw");
                List<ParameterDefinition> definitions = new ArrayList<>();
                for (int i = 0; i < arguments.size(); i += 2) {
                    int argumentType = arguments.get(i + 1).getAsInt();
                    if (argumentType == 0) { callback.setVarArgs(true); break; }
                    definitions.add(new ParameterDefinitionImpl("arg" + (i / 2), datatype(argumentType), null));
                }
                callback.setArguments(definitions.toArray(new ParameterDefinition[0]));
                result = callback; break;
            default:
                // Explicitly fail on unsupported signature types instead of guessing.
                throw new IllegalArgumentException("unsupported prototype kind=" + kind + " id=" + id);
        }
        cache.put(id, result); return result;
    }
    private void signature(Function function, int id) throws Exception {
        if (id == 0) return;
        function.setCallingConvention("__cdecl");
        JsonObject named = types.get(id).getAsJsonObject();
        JsonObject prototype = types.get(named.get("size").getAsInt()).getAsJsonObject();
        if (prototype.get("kind").getAsInt() != 13) throw new IllegalArgumentException("not FUNC_PROTO");
        function.setReturnType(datatype(prototype.get("size").getAsInt()), SourceType.IMPORTED);
        JsonArray raw = prototype.getAsJsonArray("raw");
        List<Parameter> parameters = new ArrayList<>();
        for (int i = 0; i < raw.size(); i += 2) {
            int type = raw.get(i + 1).getAsInt();
            if (type == 0) { function.setVarArgs(true); break; }
            parameters.add(new ParameterImpl("arg" + (i / 2), datatype(type), currentProgram));
        }
        function.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.IMPORTED);
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Paths.get(args[1]);
        Files.createDirectories(output);
        types = JsonParser.parseString(Files.readString(Paths.get(args[2]))).getAsJsonArray();
        List<String[]> selected = new ArrayList<>();
        int labels = 0;
        for (String row : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            String[] fields = row.split("\t");
            Address address = toAddr(fields[0]);
            if (currentProgram.getMemory().contains(address)) {
                createLabel(address, fields[2], true, SourceType.IMPORTED);
                labels++;
            }
            if (fields[3].equals("1")) selected.add(fields);
            if (!fields[3].equals("0") && currentProgram.getMemory().contains(address)) {
                Function function = getFunctionAt(address);
                if (function == null) function = currentProgram.getFunctionManager().createFunction(
                    fields[2], address, new AddressSet(address), SourceType.IMPORTED);
                signature(function, Integer.parseInt(fields[5]));
                if (Set.of("__stack_chk_fail", "fortify_panic", "panic").contains(fields[2]))
                    function.setNoReturn(true);
            }
        }
        println("STOCK labels=" + labels + " selected=" + selected.size());
        for (String[] row : selected) {
            monitor.checkCancelled();
            Address entry = toAddr(row[0]), end = toAddr(row[4]).subtract(1);
            AddressSet allowed = new AddressSet(entry, end);
            DisassembleCommand command = new DisassembleCommand(entry, allowed, true);
            command.applyTo(currentProgram, monitor);
            Function function = getFunctionAt(entry);
            if (function == null) function = createFunction(entry, row[2]);
            if (function != null) function.setBody(allowed);
            if (function == null) println("CREATE_FAILED " + row[2]);
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int success = 0, failure = 0;
        try (PrintWriter status = new PrintWriter(output.resolve("status.tsv").toFile(), "UTF-8")) {
            status.println("symbol\tentry\tstatus\tbody_bytes\terror");
            for (String[] row : selected) {
                monitor.checkCancelled();
                Function function = getFunctionAt(toAddr(row[0]));
                if (function == null) {
                    status.println(row[2] + "\t" + row[0] + "\tmissing_function\t0\t");
                    failure++; continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String filename = row[2].replaceAll("[^A-Za-z0-9_.-]", "_") + ".pseudo.c";
                    Files.writeString(output.resolve(filename),
                        "/* AUTO-GENERATED PSEUDOCODE; NOT VERIFIED REIMPLEMENTATION. Entry " + row[0] + " */\n" +
                        result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                    String c = result.getDecompiledFunction().getC();
                    boolean bad = c.contains("halt_baddata") || c.contains("Truncating control flow") ||
                        result.getErrorMessage().contains("pcode error");
                    status.println(row[2] + "\t" + row[0] + "\t" +
                        (bad ? "decompiled_with_gaps" : "decompiled_unverified") + "\t" +
                        function.getBody().getNumAddresses() + "\t" + result.getErrorMessage().replace('\n', ' '));
                    success++;
                } else {
                    status.println(row[2] + "\t" + row[0] + "\tfailed\t" + function.getBody().getNumAddresses() + "\t" +
                        result.getErrorMessage().replace('\n', ' ').replace('\t', ' '));
                    failure++;
                }
                status.flush();
                println("STOCK " + (success + failure) + "/" + selected.size() + " " + row[2]);
            }
        } finally { decompiler.dispose(); }
        Files.writeString(output.resolve("summary.txt"), "Pseudocode successes=" + success + " failures=" + failure +
            "\nNo semantic completeness, recompilability or hardware claim.\n", StandardCharsets.UTF_8);
    }
}
