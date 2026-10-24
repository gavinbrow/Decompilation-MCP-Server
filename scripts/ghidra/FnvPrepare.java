// Bounded private preparation for FNV; inferred C is not matching contribution source.
// @category FNV
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.*;

public class FnvPrepare extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Request JSON and output JSON required");
        Path output = Path.of(args[1]);
        JsonObject request = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        Address entry = toAddr(request.get("address").getAsString());
        int size = request.get("size").getAsInt();
        Address end = entry.add(size - 1);
        if (!currentProgram.getMemory().contains(entry) || !currentProgram.getMemory().contains(end))
            throw new IllegalArgumentException("Packet span is outside the private image");
        AddressSet body = new AddressSet(entry, end);
        Disassembler decoder = Disassembler.getDisassembler(currentProgram, monitor, null);
        decoder.disassemble(entry, body, true);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function function = functions.getFunctionAt(entry);
        if (function == null) {
            function = functions.createFunction(request.get("symbol").getAsString(), entry, body, SourceType.USER_DEFINED);
        } else {
            function.setBody(body);
        }
        JsonObject context = request.getAsJsonObject("context");
        JsonArray warnings = new JsonArray();
        if (context.has("target_convention") && !context.get("target_convention").isJsonNull()) {
            try { function.setCallingConvention(context.get("target_convention").getAsString()); }
            catch (Exception error) { warnings.add("Packet calling convention could not be applied: " + error.getClass().getSimpleName()); }
        } else warnings.add("Target calling convention is inferred; packet did not specify one");
        JsonArray appliedCalls = new JsonArray();
        // Explicit context ABI declarations can label callees without decoding their bodies.
        for (JsonElement element : context.getAsJsonArray("explicit_call_conventions")) {
            JsonObject call = element.getAsJsonObject();
            Address callAddress = toAddr(call.get("address").getAsString());
            if (!currentProgram.getMemory().contains(callAddress) || body.contains(callAddress)) continue;
            try {
                Function callee = functions.getFunctionAt(callAddress);
                if (callee == null) callee = functions.createFunction(call.get("name").getAsString(), callAddress,
                    new AddressSet(callAddress, callAddress), SourceType.USER_DEFINED);
                callee.setCallingConvention(call.get("convention").getAsString());
                appliedCalls.add(call);
            } catch (Exception error) { warnings.add("Context callee declaration not applied: " + call.get("name").getAsString()); }
        }
        // The decompiler may otherwise follow a tail-jump outside a manually
        // bounded body and silently reconstruct a different, larger function.
        // Declare those destinations as separate functions; do not decode them.
        JsonArray externalBranches = new JsonArray();
        JsonArray boundaryOverrides = new JsonArray();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction.getFlowOverride() == FlowOverride.CALL_RETURN)
                instruction.setFlowOverride(FlowOverride.NONE);
            if (!instruction.getFlowType().isJump()) continue;
            for (Address destination : instruction.getFlows()) {
                if (body.contains(destination)) continue;
                externalBranches.add(destination.toString());
                if (currentProgram.getMemory().contains(destination) && functions.getFunctionAt(destination) == null) {
                    functions.createFunction("FUN_" + destination.toString(), destination,
                        new AddressSet(destination, destination), SourceType.USER_DEFINED);
                }
                if (!instruction.getFlowType().isConditional()) {
                    // Analysis database only: represent the exact tail transfer
                    // as call+return so Ghidra cannot absorb its destination.
                    // No instruction bytes or official checker inputs change.
                    instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                    boundaryOverrides.add(instruction.getAddress().toString());
                }
            }
        }
        if (externalBranches.size() > 0) warnings.add("Out-of-span branches are separate unknown callees; review tail-call ABI");
        DecompInterface decompiler = new DecompInterface();
        JsonObject result = new JsonObject();
        try {
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults decompiled = decompiler.decompileFunction(function, request.get("seconds").getAsInt(), monitor);
            result.addProperty("decompile_completed", decompiled.decompileCompleted());
            result.addProperty("error", decompiled.getErrorMessage());
            result.addProperty("symbol", function.getName());
            result.addProperty("address", entry.toString());
            result.addProperty("size", size);
            result.addProperty("prototype", function.getPrototypeString(true, false));
            result.addProperty("calling_convention", function.getCallingConventionName());
            result.addProperty("context_types_imported", false);
            result.add("explicit_call_conventions_applied", appliedCalls);
            result.add("external_branch_destinations", externalBranches);
            result.add("analysis_only_tail_call_boundaries", boundaryOverrides);
            result.add("warnings", warnings);
            JsonArray variables = new JsonArray();
            int outsideSpan = 0;
            if (decompiled.getHighFunction() != null) {
                Iterator<HighSymbol> symbols = decompiled.getHighFunction().getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    HighSymbol variable = symbols.next();
                    JsonObject item = new JsonObject();
                    item.addProperty("name", variable.getName());
                    item.addProperty("type", variable.getDataType().getDisplayName());
                    item.addProperty("storage", variable.getStorage().toString());
                    item.addProperty("parameter", variable.isParameter());
                    variables.add(item);
                }
                Iterator<PcodeOpAST> operations = decompiled.getHighFunction().getPcodeOps();
                while (operations.hasNext()) if (!body.contains(operations.next().getSeqnum().getTarget())) outsideSpan++;
            }
            result.add("variables", variables);
            result.addProperty("pcode_operations_outside_packet_span", outsideSpan);
            if (outsideSpan > 0) {
                result.addProperty("decompile_completed", false);
                warnings.add("Rejected decompiler result because it includes operations outside the original packet span");
            }
            if (decompiled.decompileCompleted() && outsideSpan == 0 && decompiled.getDecompiledFunction() != null) {
                String c = "/* UNTRUSTED GHIDRA DRAFT: review types, ABI, symbols; not submission source. */\n" +
                    decompiled.getDecompiledFunction().getC();
                Files.writeString(output.resolveSibling("draft.c"), c, StandardCharsets.UTF_8);
            }
        } finally { decompiler.dispose(); }
        Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(result), StandardCharsets.UTF_8);
    }
}
