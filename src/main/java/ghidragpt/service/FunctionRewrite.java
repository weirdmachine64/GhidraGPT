package ghidragpt.service;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidragpt.ui.Console;
import ghidragpt.service.APIClient;
import ghidragpt.utils.PromptBuilder;
import ghidragpt.utils.ResponseParser;
import ghidragpt.utils.GhidraFunctionModifier;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Comprehensive function rewrite service that combines function and variable renaming
 * to make code as human-readable as possible
 */
public class FunctionRewrite {
    
    private final DecompInterface decompiler;
    private final APIClient apiClient;
    private final Console console;
    private final PromptBuilder promptBuilder;
    private final ResponseParser responseParser;
    private final ObjectMapper objectMapper;
    private GhidraFunctionModifier functionModifier;
    
    public FunctionRewrite(APIClient apiClient, Console console) {
        this.apiClient = apiClient;
        this.console = console;
        this.decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        this.promptBuilder = new PromptBuilder();
        this.responseParser = new ResponseParser();
        this.functionModifier = null; // Will be initialized per operation
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Comprehensive function rewrite: renames function, variables, sets types, and adds comments
     */
    public EnhancementResult rewriteFunction(Function function, Program program, TaskMonitor monitor) {
        EnhancementResult result = new EnhancementResult();
        result.functionName = function.getName();
        result.originalFunctionName = function.getName();
        
        try {
            monitor.setMessage("Analyzing function for comprehensive function rewrite...");
            
            // Initialize decompiler
            if (!decompiler.openProgram(program)) {
                result.errors.add("Failed to initialize decompiler");
                return result;
            }
            
            // Decompile the function
            DecompileResults decompileResults = decompiler.decompileFunction(function, 30, monitor);
            if (decompileResults == null || decompileResults.getDecompiledFunction() == null) {
                result.errors.add("Failed to decompile function: " + function.getName());
                return result;
            }
            
            HighFunction highFunction = decompileResults.getHighFunction();
            String decompiledCode = decompileResults.getDecompiledFunction().getC();
            
            // Create function analysis using domain model
            FunctionAnalysis functionAnalysis = new FunctionAnalysis(function, true);
            
            // Extract variable information using domain model
            List<VariableAnalysis> variables = extractVariableAnalyses(function, highFunction);
            functionAnalysis.getVariables().addAll(variables);
            
            // Generate comprehensive rewrite prompt using PromptBuilder
            String enhancementPrompt = generateComprehensiveRewritePrompt(function, decompiledCode, functionAnalysis);
            
            monitor.setMessage("Getting model suggestions for comprehensive function rewrite...");
            monitor.setProgress(30);
            
            // Get model response with streaming
            String aiResponse;
            long startTime = System.currentTimeMillis();
            try {
                APIClient.GPTProvider provider = apiClient.getProvider();
                
                // Print analysis header using console
                if (console != null) {
                    console.printAnalysisHeader("✨ Comprehensive Function Rewrite", function.getName(), 
                        provider.toString(), apiClient.getModel(), enhancementPrompt.length());
                }
                
                final StringBuilder streamBuffer = new StringBuilder();
                
                aiResponse = apiClient.sendRequest(enhancementPrompt, new APIClient.StreamCallback() {
                    private boolean isFirstResponse = true;
                    
                    @Override
                    public void onPartialResponse(String partialContent) {
                        streamBuffer.append(partialContent);
                        
                        // Print header on first response
                        if (isFirstResponse) {
                            if (console != null) {
                                console.printStreamHeader();
                            }
                            isFirstResponse = false;
                        }
                        
                        // Stream response directly to console
                        if (console != null) {
                            console.appendStreamingText(partialContent);
                        }
                        
                        // Update monitor with simple streaming indicator
                        monitor.setMessage("Streaming model response...");
                    }
                    
                    @Override
                    public void onComplete(String fullContent) {
                        // Don't print completion message here - wait until JSON is successfully parsed
                        monitor.setMessage("Processing model suggestions...");
                        monitor.setProgress(70);
                    }
                    
                    @Override
                    public void onError(Exception error) {
                        if (console != null) {
                            console.printStreamError("model analysis", error.getMessage());
                        }
                    }
                });
            } catch (java.net.SocketTimeoutException e) {
                throw new RuntimeException("Request timed out. Function may be too complex. Consider breaking it down into smaller functions.", e);
            } catch (java.io.IOException e) {
                if (e.getMessage().contains("timeout")) {
                    throw new RuntimeException("Network timeout occurred. Check your internet connection or try again later.", e);
                }
                throw e;
            }
            
            monitor.setProgress(70);
            
            // Parse model response for comprehensive rewrite specification
            ComprehensiveRewriteSpec rewriteSpec = parseComprehensiveRewriteResponse(aiResponse);
            
            // Now that JSON parsing is successful, print the completion message
            long duration = System.currentTimeMillis() - startTime;
            if (console != null) {
                console.printStreamComplete("model analysis", duration, aiResponse.length());
            }
            
            monitor.setMessage("Applying comprehensive function rewrite...");
            monitor.setProgress(80);
            
            // Extract variable information for the rewrite application
            Map<String, VariableInfo> variableMap = extractVariableInformation(function, highFunction);
            
            // Apply the comprehensive rewrite changes
            result = applyComprehensiveRewrite(function, program, variableMap, rewriteSpec, monitor);
            
            monitor.setProgress(100);
            
        } catch (Exception e) {
            String errorMsg = "Error during comprehensive function rewrite: " + e.getMessage();
            
            // Provide more specific error messages for common timeout issues
            if (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout")) {
                errorMsg = "Function analysis timed out. This can happen with very large or complex functions. " +
                          "Try: 1) Check your internet connection, 2) Use a faster model, 3) Break down large functions, or 4) Try again later.";
            }
            
            result.errors.add(errorMsg);
            Msg.error(this, "Comprehensive function rewrite error", e);
        }
        
        return result;
    }
    
    /**
     * Extract variable information from function
     */
    private Map<String, VariableInfo> extractVariableInformation(Function function, HighFunction highFunction) {
        Map<String, VariableInfo> variableMap = new HashMap<>();
        
        // Get function parameters
        Parameter[] parameters = function.getParameters();
        for (Parameter param : parameters) {
            VariableInfo info = new VariableInfo();
            info.name = param.getName();
            info.type = param.getDataType().getDisplayName();
            info.isParameter = true;
            info.variable = param;
            variableMap.put(param.getName(), info);
        }
        
        // Get local variables
        Variable[] localVars = function.getLocalVariables();
        for (Variable var : localVars) {
            if (!variableMap.containsKey(var.getName())) {
                VariableInfo info = new VariableInfo();
                info.name = var.getName();
                info.type = var.getDataType().getDisplayName();
                info.isParameter = false;
                info.variable = var;
                variableMap.put(var.getName(), info);
            }
        }
        
        // Enhance with HighSymbol information and capture ALL variables from decompiler
        if (highFunction != null) {
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();
                
                // Update existing variable info or create new for decompiler temporaries
                VariableInfo info = variableMap.get(symbolName);
                if (info == null) {
                    // This is a decompiler temporary (iVar1, uVar1, etc.)
                    info = new VariableInfo();
                    info.name = symbolName;
                    HighVariable highVar = symbol.getHighVariable();
                    if (highVar != null) {
                        info.type = highVar.getDataType().getDisplayName();
                    } else {
                        info.type = "unknown";
                    }
                    info.isParameter = symbol.isParameter();
                    variableMap.put(symbolName, info);
                }
                
                // Set high-level information for all variables
                info.highSymbol = symbol;
                info.highVariable = symbol.getHighVariable();
            }
        }
        
        return variableMap;
    }
    
    /**
     * Extract variable analyses from function for domain model
     */
    private List<VariableAnalysis> extractVariableAnalyses(Function function, HighFunction highFunction) {
        List<VariableAnalysis> analyses = new ArrayList<>();
        
        // Get function parameters
        Parameter[] parameters = function.getParameters();
        for (Parameter param : parameters) {
            analyses.add(new VariableAnalysis(param.getName(), param.getDataType(), true));
        }
        
        // Get local variables
        Variable[] localVars = function.getLocalVariables();
        for (Variable var : localVars) {
            analyses.add(new VariableAnalysis(var.getName(), var.getDataType(), false));
        }
        
        // Add any additional variables from HighFunction if available
        if (highFunction != null) {
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();
                
                // Check if we already have this variable
                boolean alreadyExists = analyses.stream().anyMatch(va -> va.getName().equals(symbolName));
                if (!alreadyExists) {
                    analyses.add(new VariableAnalysis(symbolName, symbol.getDataType(), symbol.isParameter()));
                }
            }
        }
        
        return analyses;
    }
    
    /**
     * Generate comprehensive rewrite prompt for model analysis
     */
    private String generateComprehensiveRewritePrompt(Function function, String decompiledCode, FunctionAnalysis functionAnalysis) {
        StringBuilder prompt = new StringBuilder();
        // TIW:
        prompt.append("Analyze this decompiled function and provide a comprehensive rewrite specification to make it as human-readable as possible. Always use camel case names.\n\n");
        prompt.append("Current function: ").append(function.getName()).append("\n\n");
        prompt.append("Decompiled code:\n").append(decompiledCode).append("\n\n");
        
        // Categorize variables for better analysis
        StringBuilder parameters = new StringBuilder();
        StringBuilder localVars = new StringBuilder();
        StringBuilder tempVars = new StringBuilder();
        StringBuilder stackVars = new StringBuilder();
        StringBuilder wellNamedVars = new StringBuilder();
        StringBuilder undefinedTypes = new StringBuilder();
        
        for (VariableAnalysis varAnalysis : functionAnalysis.getVariables()) {
            String varDesc = "- " + varAnalysis.getName() + " (" + varAnalysis.getTypeDisplayName() + ")";
            
            if (varAnalysis.isParameter()) {
                parameters.append(varDesc).append("\n");
            } else if (varAnalysis.getName().matches("^[iufl]Var\\d+$")) {
                // Decompiler temporaries like iVar1, uVar2, etc.
                tempVars.append(varDesc).append(" - decompiler temporary\n");
            } else if (varAnalysis.getName().matches("^[ui]Stack_\\d+$|^local_\\d+$")) {
                // Stack variables like uStack_20, local_38, etc.
                stackVars.append(varDesc).append(" - stack variable\n");
            } else if (varAnalysis.getName().matches("^[A-Z][a-zA-Z0-9_]*$") && varAnalysis.getName().length() > 3) {
                // Variables that already have reasonable names (like ControlPc, FunctionEntry)
                wellNamedVars.append(varDesc).append(" - already well-named\n");
            } else {
                localVars.append(varDesc).append("\n");
            }
            
            // Track variables with unclear types
            if (varAnalysis.needsTypeAnalysis()) {
                undefinedTypes.append("- ").append(varAnalysis.getName()).append(" (").append(varAnalysis.getTypeDisplayName())
                    .append(") - analyze usage to suggest better type\n");
            }
        }
        
        if (parameters.length() > 0) {
            prompt.append("Parameters:\n").append(parameters).append("\n");
        }
        if (localVars.length() > 0) {
            prompt.append("Local Variables:\n").append(localVars).append("\n");
        }
        if (tempVars.length() > 0) {
            prompt.append("Decompiler Temporaries (need meaningful names):\n").append(tempVars).append("\n");
        }
        if (stackVars.length() > 0) {
            prompt.append("Stack Variables (may need renaming):\n").append(stackVars).append("\n");
        }
        if (wellNamedVars.length() > 0) {
            prompt.append("Well-Named Variables (consider keeping):\n").append(wellNamedVars).append("\n");
        }
        if (undefinedTypes.length() > 0) {
            prompt.append("Variables with unclear types (suggest better types):\n").append(undefinedTypes).append("\n");
        }
        
        prompt.append("Analysis Instructions:\n");
        prompt.append("1. Suggest a descriptive function name based on what the function does\n");
        prompt.append("2. Rename variables to reflect their purpose/usage\n");
        prompt.append("3. For unclear types, suggest more specific types based on usage patterns\n");
        prompt.append("4. Suggest a proper function prototype/signature if the current one seems incorrect\n");
        prompt.append("5. Add helpful comments for complex logic, important operations, or unclear code sections\n");
        prompt.append("6. Focus on renaming generic names (param_1, local_38, uStack_20, etc.)\n");
        prompt.append("7. Pay attention to:\n");
        prompt.append("   - Function parameters and their roles\n");
        prompt.append("   - Loop counters, flags, temporary storage\n");
        prompt.append("   - Return values and error codes\n");
        prompt.append("   - Data size patterns (int vs long vs pointer)\n\n");
        
        prompt.append("Answer strictly in this JSON format with no extra output:\n");
        prompt.append("{\n");
        prompt.append("  \"function_name\": \"descriptive_function_name\",\n");
        prompt.append("  \"variable_renames\": {\n");
        prompt.append("    \"old_variable\": \"new_variable\",\n");
        prompt.append("    ...\n");
        prompt.append("  },\n");
        prompt.append("  \"variable_types\": {\n");
        prompt.append("    \"variable_name\": \"suggested_type\",\n");
        prompt.append("    ...\n");
        prompt.append("  },\n");
        prompt.append("  \"function_prototype\": \"void function_name(type param1, type param2)\",\n");
        prompt.append("  \"comments\": {\n");
        prompt.append("    \"address\": \"comment text\",\n");
        prompt.append("    ...\n");
        prompt.append("  }\n");
        prompt.append("}\n\n");
        
        prompt.append("Examples:\n");
        prompt.append("{\n");
        prompt.append("  \"function_name\": \"handle_security_failure\",\n");
        prompt.append("  \"variable_renames\": {\n");
        prompt.append("    \"param_1\": \"violationAddress\",\n");
        prompt.append("    \"local_38\": \"imageBaseBuffer\",\n");
        prompt.append("    \"uStack_20\": \"stackParameter\",\n");
        prompt.append("    \"mbr_0x18\": \"m_rotationX\",\n");
        prompt.append("    \"field13_0x38\": \"m_defaultFieldOfView\"\n");
        prompt.append("  },\n");
        prompt.append("  \"variable_types\": {\n");
        prompt.append("    \"violationAddress\": \"PVOID\",\n");
        prompt.append("    \"imageBaseBuffer\": \"DWORD64*\"\n");
        prompt.append("  },\n");
        prompt.append("  \"function_prototype\": \"NTSTATUS handle_security_failure(PVOID violationAddress, ULONG violationCode)\",\n");
        prompt.append("  \"comments\": {\n");
        prompt.append("    \"0x1400010a0\": \"Check if violation address is valid\",\n");
        prompt.append("    \"0x1400010c5\": \"Log security event before returning\"\n");
        prompt.append("  }\n");
        prompt.append("}\n\n");
        
        prompt.append("Notes:\n");
        prompt.append("- Keep well-named variables like 'ControlPc' and 'FunctionEntry' unless you have significantly better names.\n");
        prompt.append("- For struct/class member fields (mbr_*, field*_0x*), use m_ prefix with camelCase (e.g. mbr_0x18 -> m_rotationX, field13_0x38 -> m_defaultFieldOfView)\n");
        prompt.append("- For addresses in comments, use hex format like '0x1400010a0'\n");
        prompt.append("- Only include fields that need changes - omit empty objects\n");
        prompt.append("- Function prototype should be a complete C function signature\n");
        
        return prompt.toString();
    }
    
    /**
     * Parses model response to extract function renames and variable renames
     * Uses simple text format only
     */
    private EnhancementSuggestions parseEnhancementResponse(String response) {
        EnhancementSuggestions suggestions = new EnhancementSuggestions();
        parseTextResponse(response, suggestions);
        return suggestions;
    }
    
    /**
     * Holds enhancement suggestions from model
     */
    private static class EnhancementSuggestions {
        String functionName;
        Map<String, String> variableRenames = new HashMap<>();
        Map<String, String> typeHints = new HashMap<>();
    }
    
    /**
     * Parses comprehensive rewrite response from model (JSON format)
     */
    private ComprehensiveRewriteSpec parseComprehensiveRewriteResponse(String response) {
        ComprehensiveRewriteSpec spec = new ComprehensiveRewriteSpec();
        
        try {
            // Extract JSON from response (model might add extra text)
            int jsonStart = response.indexOf("{");
            int jsonEnd = response.lastIndexOf("}") + 1;
            
            if (jsonStart == -1 || jsonEnd == -1) {
                // Fallback to old parsing if no JSON found
                Msg.warn(this, "No JSON found in response, falling back to text parsing");
                EnhancementSuggestions fallback = parseEnhancementResponse(response);
                spec.functionName = fallback.functionName;
                spec.variableRenames = fallback.variableRenames;
                spec.variableTypes = fallback.typeHints;
                return spec;
            }
            
            String jsonStr = response.substring(jsonStart, jsonEnd);
            
            // Simple JSON parsing (since we don't have a full JSON library)
            spec = parseSimpleJson(jsonStr);
            
        } catch (Exception e) {
            Msg.error(this, "Failed to parse comprehensive rewrite response: " + e.getMessage());
            // Fallback to old parsing
            EnhancementSuggestions fallback = parseEnhancementResponse(response);
            spec.functionName = fallback.functionName;
            spec.variableRenames = fallback.variableRenames;
            spec.variableTypes = fallback.typeHints;
        }
        
        return spec;
    }
    
    /**
     * Parse JSON response using Ghidra's built-in Jackson ObjectMapper
     */
    private ComprehensiveRewriteSpec parseSimpleJson(String jsonStr) {
        ComprehensiveRewriteSpec spec = new ComprehensiveRewriteSpec();

        try {
            JsonNode rootNode = objectMapper.readTree(jsonStr);

            // Extract function_name
            if (rootNode.has("function_name")) {
                spec.functionName = rootNode.get("function_name").asText();
            }

            // Extract function_prototype
            if (rootNode.has("function_prototype")) {
                spec.functionPrototype = rootNode.get("function_prototype").asText();
            }

            // Extract variable_renames object
            if (rootNode.has("variable_renames")) {
                spec.variableRenames = parseJsonObject(rootNode.get("variable_renames"));
            }

            // Extract variable_types object
            if (rootNode.has("variable_types")) {
                spec.variableTypes = parseJsonObject(rootNode.get("variable_types"));
            }

            // Extract comments object
            if (rootNode.has("comments")) {
                spec.comments = parseJsonObject(rootNode.get("comments"));
            }

        } catch (Exception e) {
            Msg.error(this, "Failed to parse JSON response with ObjectMapper: " + e.getMessage());
            // Fallback to text parsing
            EnhancementSuggestions fallback = parseEnhancementResponse(jsonStr);
            spec.functionName = fallback.functionName;
            spec.variableRenames = fallback.variableRenames;
            spec.variableTypes = fallback.typeHints;
        }

        return spec;
    }
    
    /**
     * Parse a JSON object field using Jackson
     */
    private Map<String, String> parseJsonObject(JsonNode jsonNode) {
        Map<String, String> result = new HashMap<>();
        
        if (jsonNode != null && jsonNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = jsonNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                result.put(field.getKey(), field.getValue().asText());
            }
        }
        
        return result;
    }
    
    /**
     * Parse text format response
     */
    private void parseTextResponse(String response, EnhancementSuggestions suggestions) {
        // Extract function name suggestion
        Pattern functionPattern = Pattern.compile("FUNCTION_NAME:\\s*([\\w_]+)", Pattern.CASE_INSENSITIVE);
        Matcher functionMatcher = functionPattern.matcher(response);

        if (functionMatcher.find()) {
            String newFunctionName = functionMatcher.group(1).trim();
            if (isValidFunctionName(newFunctionName)) {
                suggestions.functionName = newFunctionName;
            }
        }
        
        // Extract variable renames
        Pattern renamePattern = Pattern.compile("RENAME:\\s*([\\w_]+)\\s*->\\s*([\\w_]+)", Pattern.CASE_INSENSITIVE);
        Matcher renameMatcher = renamePattern.matcher(response);
        
        while (renameMatcher.find()) {
            String oldName = renameMatcher.group(1).trim();
            String newName = renameMatcher.group(2).trim();
            
            if (isValidVariableName(newName) && !oldName.equals(newName)) {
                suggestions.variableRenames.put(oldName, newName);
            }
        }
        
        // Extract type hints
        Pattern typeHintPattern = Pattern.compile("TYPE_HINT:\\s*([\\w_]+)\\s*->\\s*([\\w_*\\[\\]]+)", Pattern.CASE_INSENSITIVE);
        Matcher typeHintMatcher = typeHintPattern.matcher(response);
        
        while (typeHintMatcher.find()) {
            String varName = typeHintMatcher.group(1).trim();
            String typeName = typeHintMatcher.group(2).trim();
            
            if (!varName.isEmpty() && !typeName.isEmpty()) {
                suggestions.typeHints.put(varName, typeName);
            }
        }
    }
    
    /**
     * Applies comprehensive rewrite changes using proper Ghidra APIs
     */
    private EnhancementResult applyComprehensiveRewrite(Function function, Program program, 
            Map<String, VariableInfo> variableMap, ComprehensiveRewriteSpec spec, TaskMonitor monitor) {
        
        EnhancementResult result = new EnhancementResult();
        result.functionName = function.getName();
        result.originalFunctionName = function.getName();
        
        int transactionID = program.startTransaction("Comprehensive Function Rewrite: " + function.getName());
        boolean success = false;
        
        try {
            // TIW:
            /*// 1. Apply function rename first
            if (spec.functionName != null && !spec.functionName.equals(function.getName())) {
                try {
                    function.setName(spec.functionName, SourceType.USER_DEFINED);
                    result.newFunctionName = spec.functionName;
                    result.functionRenamed = true;
                    Msg.info(this, "Renamed function: " + result.originalFunctionName + " -> " + spec.functionName);
                } catch (DuplicateNameException | InvalidInputException e) {
                    result.errors.add("Failed to rename function to " + spec.functionName + ": " + e.getMessage());
                }
            }
            
            // 2. Apply function prototype if specified
            if (spec.functionPrototype != null && !spec.functionPrototype.trim().isEmpty()) {
                try {
                    applyFunctionPrototype(function, program, spec.functionPrototype);
                    result.message = "Function prototype updated";
                    Msg.info(this, "Updated function prototype: " + spec.functionPrototype);
                } catch (Exception e) {
                    result.errors.add("Failed to update function prototype: " + e.getMessage());
                    Msg.error(this, "Prototype update failed", e);
                }
            }*/
            
            // 3. Apply member field type changes FIRST (before renames)
            // Changing undefined1 -> float creates a proper 4-byte component that can then be renamed
            int fieldTypeCount = 0;
            for (Map.Entry<String, String> typeChange : spec.variableTypes.entrySet()) {
                String varName = typeChange.getKey();
                String newType = typeChange.getValue();
                
                if (applyMemberFieldTypeChange(function, program, varName, newType, spec.variableRenames)) {
                    fieldTypeCount++;
                    result.typeUpdates.put(varName, newType);
                    Msg.info(this, "Changed struct field type for " + varName + " to " + newType);
                }
            }
            
            // 4. Apply variable renames using HighFunctionDBUtil, with member field fallback
            int renameCount = 0;
            int fieldRenameCount = 0;
            for (Map.Entry<String, String> rename : spec.variableRenames.entrySet()) {
                String oldName = rename.getKey();
                String newName = rename.getValue();
                
                if (applyVariableRename(function, program, oldName, newName)) {
                    renameCount++;
                    result.variableRenames.put(oldName, newName);
                    Msg.info(this, "Renamed variable: " + oldName + " -> " + newName);
                } else if (isMemberFieldName(oldName) && applyMemberFieldRename(function, program, oldName, newName)) {
                    fieldRenameCount++;
                    result.variableRenames.put(oldName, newName);
                    Msg.info(this, "Renamed struct field: " + oldName + " -> " + newName);
                } else {
                    result.errors.add("Failed to rename variable: " + oldName);
                }
            }
            
            // 5. Apply remaining variable type changes (non-member-field locals/params)
            int typeCount = 0;
            for (Map.Entry<String, String> typeChange : spec.variableTypes.entrySet()) {
                String varName = typeChange.getKey();
                String newType = typeChange.getValue();
                
                // Skip if already handled as member field type change
                if (result.typeUpdates.containsKey(varName)) {
                    continue;
                }
                
                if (applyVariableTypeChange(function, program, varName, newType)) {
                    typeCount++;
                    result.typeUpdates.put(varName, newType);
                    Msg.info(this, "Changed type for " + varName + " to " + newType);
                } else {
                    result.errors.add("Failed to change type for variable: " + varName);
                }
            }
            
            // 6. Apply comments - try inline first, collect failures for plate comment
            int commentCount = 0;
            List<String> unplacedComments = new ArrayList<>();
            for (Map.Entry<String, String> comment : spec.comments.entrySet()) {
                String addressStr = comment.getKey();
                String commentText = comment.getValue();
                
                if (applyComment(function, program, addressStr, commentText)) {
                    commentCount++;
                    Msg.info(this, "Added comment at " + addressStr + ": " + commentText);
                } else {
                    unplacedComments.add("[" + addressStr + "] " + commentText);
                }
            }
            
            // Write unplaced comments as a function plate comment so AI insights are not lost
            if (!unplacedComments.isEmpty()) {
                StringBuilder plateComment = new StringBuilder();
                String existingComment = function.getComment();
                if (existingComment != null && !existingComment.isEmpty()) {
                    // Strip any previous AI Guesswork Notes section before appending new ones
                    int aiNotesIdx = existingComment.indexOf("AI Guesswork Notes:");
                    if (aiNotesIdx >= 0) {
                        existingComment = existingComment.substring(0, aiNotesIdx).trim();
                    }
                    if (!existingComment.isEmpty()) {
                        plateComment.append(existingComment).append("\n\n");
                    }
                }
                plateComment.append("AI Guesswork Notes:\n");
                for (String c : unplacedComments) {
                    plateComment.append("  ").append(c).append("\n");
                }
                function.setComment(plateComment.toString().trim());
                commentCount += unplacedComments.size();
                Msg.info(this, "Added " + unplacedComments.size() + " comment(s) as function plate comment");
            }
            
            success = true;
            
            // Build result message
            StringBuilder message = new StringBuilder();
            if (result.functionRenamed) {
                message.append("Function renamed: ").append(result.originalFunctionName)
                       .append(" → ").append(result.newFunctionName).append("\n");
            }
            
            if (renameCount > 0) {
                message.append("Successfully renamed ").append(renameCount).append(" variable(s)\n");
            }
            
            if (fieldRenameCount > 0) {
                message.append("Successfully renamed ").append(fieldRenameCount).append(" struct field(s)\n");
            }
            
            if (typeCount > 0) {
                message.append("Successfully updated types for ").append(typeCount).append(" variable(s)\n");
            }
            
            if (fieldTypeCount > 0) {
                message.append("Successfully updated types for ").append(fieldTypeCount).append(" struct field(s)\n");
            }
            
            if (commentCount > 0) {
                message.append("Successfully added ").append(commentCount).append(" comment(s)\n");
            }
            
            if (spec.functionPrototype != null) {
                message.append("Function prototype updated\n");
            }
            
            if (!result.functionRenamed && renameCount == 0 && fieldRenameCount == 0 && typeCount == 0 && fieldTypeCount == 0 && commentCount == 0 && spec.functionPrototype == null) {
                message.append("No changes were applied");
            }
            
            result.message = message.toString();
            
        } finally {
            program.endTransaction(transactionID, success);
        }
        
        return result;
    }
    
    /**
     * Apply function prototype using proper Ghidra APIs
     */
    private void applyFunctionPrototype(Function function, Program program, String prototype) throws Exception {
        DataTypeManager dtm = program.getDataTypeManager();
        
        // Parse the function signature
        FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);
        FunctionDefinitionDataType sig = parser.parse(null, prototype);
        
        if (sig == null) {
            throw new Exception("Failed to parse function prototype: " + prototype);
        }
        
        // Apply the signature
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
            function.getEntryPoint(), sig, SourceType.USER_DEFINED);
        
        if (!cmd.applyTo(program, new ConsoleTaskMonitor())) {
            throw new Exception("Failed to apply function signature: " + cmd.getStatusMsg());
        }
    }
    
    /**
     * Apply variable rename using HighFunctionDBUtil
     */
    private boolean applyVariableRename(Function function, Program program, String oldName, String newName) {
        try {
            // Decompile to get HighFunction
            DecompileResults results = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) {
                return false;
            }
            
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return false;
            }
            
            // Find the symbol
            HighSymbol symbol = findSymbolByName(highFunction, oldName);
            if (symbol == null) {
                return false;
            }
            
            // Check if rename is needed
            if (oldName.equals(newName)) {
                return true; // Already has the desired name
            }
            
            // Apply the rename
            boolean commitRequired = checkFullCommit(symbol, highFunction);
            
            int tx = program.startTransaction("Rename variable: " + oldName + " -> " + newName);
            try {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                        HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, function.getSignatureSource());
                }
                
                HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                return true;
            } finally {
                program.endTransaction(tx, true);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error renaming variable " + oldName, e);
            return false;
        }
    }
    
    /**
     * Check if a name looks like a Ghidra auto-generated member field name
     */
    private boolean isMemberFieldName(String name) {
        return name.startsWith("mbr_") || name.startsWith("field");
    }
    
    /**
     * Apply member field rename on the struct data type.
     * Extracts the hex offset from the field name, resolves the struct from the 'this' parameter,
     * and renames the component at that offset.
     */
    private boolean applyMemberFieldRename(Function function, Program program, String oldName, String newName) {
        try {
            // Extract hex offset from field name (e.g. "mbr_0x18" -> 0x18, "field13_0x38" -> 0x38)
            Matcher offsetMatcher = Pattern.compile("0x([0-9a-fA-F]+)").matcher(oldName);
            if (!offsetMatcher.find()) {
                return false;
            }
            int fieldOffset = Integer.parseInt(offsetMatcher.group(1), 16);
            
            // Get the 'this' parameter's struct type
            Parameter[] params = function.getParameters();
            if (params.length == 0) {
                return false;
            }
            
            // Find a pointer-to-struct parameter (typically 'this' is first)
            Structure struct = null;
            for (Parameter param : params) {
                DataType paramType = param.getDataType();
                if (paramType instanceof Pointer) {
                    DataType baseType = ((Pointer) paramType).getDataType();
                    if (baseType instanceof Structure) {
                        struct = (Structure) baseType;
                        break;
                    }
                }
            }
            
            if (struct == null) {
                return false;
            }
            
            // Find the component at the offset
            DataTypeComponent component = struct.getComponentAt(fieldOffset);
            if (component == null) {
                return false;
            }
            
            // Only rename if the current field name is auto-generated (not user-named)
            String currentFieldName = component.getFieldName();
            if (currentFieldName != null && !isMemberFieldName(currentFieldName)) {
                Msg.info(this, "Skipping rename for field at offset 0x" + Integer.toHexString(fieldOffset) + 
                    " - current name '" + currentFieldName + "' appears to be user-defined");
                return false;
            }
            
            // Rename the field
            try {
                component.setFieldName(newName);
                Msg.info(this, "Renamed struct field on " + struct.getName() + ": " + oldName + " -> " + newName + " at offset 0x" + Integer.toHexString(fieldOffset));
                return true;
            } catch (DuplicateNameException e) {
                Msg.warn(this, "Duplicate field name: " + newName + " on struct " + struct.getName());
                return false;
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error renaming member field " + oldName, e);
            return false;
        }
    }
    
    /**
     * Apply type change to a struct member field.
     * Resolves the original field name from the renames map to extract the hex offset.
     * Only changes the type if the current type is undefined.
     */
    private boolean applyMemberFieldTypeChange(Function function, Program program, 
            String varName, String newType, Map<String, String> variableRenames) {
        try {
            // The varName in variable_types uses the NEW name (post-rename).
            // Find the original field name from the renames map.
            String originalFieldName = null;
            for (Map.Entry<String, String> rename : variableRenames.entrySet()) {
                if (rename.getValue().equals(varName)) {
                    originalFieldName = rename.getKey();
                    break;
                }
            }
            
            if (originalFieldName == null) {
                originalFieldName = varName;
            }
            
            // Must be a member field name (original) or m_ prefixed (already renamed)
            if (!isMemberFieldName(originalFieldName) && !varName.startsWith("m_")) {
                return false;
            }
            
            // Extract hex offset from the original field name
            String nameForOffset = isMemberFieldName(originalFieldName) ? originalFieldName : varName;
            Matcher offsetMatcher = Pattern.compile("0x([0-9a-fA-F]+)").matcher(nameForOffset);
            if (!offsetMatcher.find()) {
                return false;
            }
            int fieldOffset = Integer.parseInt(offsetMatcher.group(1), 16);
            
            // Find pointer-to-struct from parameters
            Parameter[] params = function.getParameters();
            if (params.length == 0) {
                return false;
            }
            
            Structure struct = null;
            for (Parameter param : params) {
                DataType paramType = param.getDataType();
                if (paramType instanceof Pointer) {
                    DataType baseType = ((Pointer) paramType).getDataType();
                    if (baseType instanceof Structure) {
                        struct = (Structure) baseType;
                        break;
                    }
                }
            }
            
            if (struct == null) {
                return false;
            }
            
            // Find the component at the offset
            DataTypeComponent component = struct.getComponentAt(fieldOffset);
            if (component == null) {
                return false;
            }
            
            // Only change type if current type is undefined
            String currentTypeName = component.getDataType().getName().toLowerCase();
            if (!currentTypeName.contains("undefined")) {
                Msg.info(this, "Skipping type change for field at offset 0x" + Integer.toHexString(fieldOffset) + 
                    " - current type '" + component.getDataType().getName() + "' is not undefined");
                return false;
            }
            
            // Resolve the new data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);
            if (dataType == null) {
                Msg.warn(this, "Could not resolve data type: " + newType);
                return false;
            }
            
            // Replace the component at the offset with the new type
            struct.replaceAtOffset(fieldOffset, dataType, dataType.getLength(), 
                component.getFieldName(), component.getComment());
            Msg.info(this, "Changed struct field type on " + struct.getName() + " at offset 0x" + 
                Integer.toHexString(fieldOffset) + ": " + currentTypeName + " -> " + newType);
            return true;
            
        } catch (Exception e) {
            Msg.error(this, "Error changing type for member field " + varName, e);
            return false;
        }
    }
    
    /**
     * Apply variable type change using HighFunctionDBUtil
     */
    private boolean applyVariableTypeChange(Function function, Program program, String varName, String newType) {
        try {
            // Decompile to get HighFunction
            DecompileResults results = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) {
                return false;
            }
            
            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return false;
            }
            
            // Find the symbol
            HighSymbol symbol = findSymbolByName(highFunction, varName);
            if (symbol == null) {
                return false;
            }
            
            // Resolve the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);
            if (dataType == null) {
                Msg.warn(this, "Could not resolve data type: " + newType);
                return false;
            }
            
            // Apply the type change
            int tx = program.startTransaction("Change variable type: " + varName + " -> " + newType);
            try {
                HighFunctionDBUtil.updateDBVariable(symbol, symbol.getName(), dataType, SourceType.USER_DEFINED);
                return true;
            } finally {
                program.endTransaction(tx, true);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error changing type for variable " + varName, e);
            return false;
        }
    }
    
    /**
     * Apply comment at a specific address within a function.
     * Tries the address as absolute first, then subtracts 0x400000 for rehomed binaries,
     * then as an offset from the function entry point.
     * Places comments as EOL (inline) comments.
     */
    private boolean applyComment(Function function, Program program, String addressStr, String commentText) {
        try {
            Address entryPoint = function.getEntryPoint();
            
            // 1. Try as absolute address
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr != null && function.getBody().contains(addr)) {
                program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, commentText);
                return true;
            }
            
            // 2. Try subtracting 0x400000 (AI gives original PE base addresses)
            try {
                long rawAddr = Long.decode(addressStr);
                long adjusted = rawAddr - 0x400000;
                if (adjusted > 0) {
                    Address adjAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(adjusted);
                    if (adjAddr != null && function.getBody().contains(adjAddr)) {
                        program.getListing().setComment(adjAddr, CodeUnit.EOL_COMMENT, commentText);
                        return true;
                    }
                }
            } catch (NumberFormatException | ghidra.program.model.address.AddressOutOfBoundsException e) {
                // fall through
            }
            
            // 3. Try as offset from function entry point
            try {
                long offset = Long.decode(addressStr);
                Address offsetAddr = entryPoint.add(offset);
                if (function.getBody().contains(offsetAddr)) {
                    program.getListing().setComment(offsetAddr, CodeUnit.EOL_COMMENT, commentText);
                    return true;
                }
            } catch (NumberFormatException | ghidra.program.model.address.AddressOutOfBoundsException e) {
                // fall through
            }
            
            Msg.warn(this, "Comment address '" + addressStr + "' could not be resolved within function " + function.getName());
            return false;
            
        } catch (Exception e) {
            Msg.error(this, "Error adding comment at " + addressStr, e);
            return false;
        }
    }

    /**
     * Find a symbol by name in the high function
     */
    private HighSymbol findSymbolByName(HighFunction highFunction, String name) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (symbol.getName().equals(name)) {
                return symbol;
            }
        }
        return null;
    }
    
    /**
     * Check if full commit is required 
     */
    private static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }
    
    /**
     * Resolve data type from string
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                return dtm.getDataType("/int"); // fallback
        }
    }
    
    /**
     * Find data type by name in all categories
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Applies all enhancement changes in a single transaction
     */
    private EnhancementResult applyEnhancementChanges(Function function, Program program, 
            Map<String, VariableInfo> variableMap, EnhancementSuggestions suggestions, TaskMonitor monitor) {
        
        EnhancementResult result = new EnhancementResult();
        result.functionName = function.getName();
        result.originalFunctionName = function.getName();
        
        int transactionID = program.startTransaction("Enhance Function: " + function.getName());
        boolean success = false;
        
        try {
            // Apply function rename first
            if (suggestions.functionName != null && !suggestions.functionName.equals(function.getName())) {
                try {
                    function.setName(suggestions.functionName, SourceType.USER_DEFINED);
                    result.newFunctionName = suggestions.functionName;
                    result.functionRenamed = true;
                } catch (DuplicateNameException | InvalidInputException e) {
                    result.errors.add("Failed to rename function to " + suggestions.functionName + ": " + e.getMessage());
                }
            }
            
            // Apply variable renames using direct variable approach
            int renameCount = 0;
            for (Map.Entry<String, String> rename : suggestions.variableRenames.entrySet()) {
                String oldName = rename.getKey();
                String newName = rename.getValue();
                
                VariableInfo varInfo = variableMap.get(oldName);
                if (varInfo == null) {
                    result.errors.add("Variable not found in function scope: " + oldName);
                    continue;
                }
                
                try {
                    boolean renamed = false;
                    
                    // Single solid strategy: Direct variable renaming
                    if (varInfo.variable != null) {
                        try {
                            varInfo.variable.setName(newName, SourceType.USER_DEFINED);
                            renamed = true;
                            renameCount++;
                            result.variableRenames.put(oldName, newName);
                        } catch (DuplicateNameException | InvalidInputException e) {
                            result.errors.add("Could not rename variable " + oldName + ": " + e.getMessage());
                        }
                    } else {
                        result.errors.add("Variable " + oldName + " has no renameable reference");
                    }
                    
                } catch (Exception e) {
                    result.errors.add("Unexpected error renaming " + oldName + ": " + e.getMessage());
                }
            }
            
            // Process type hints (suggestions only - actual type changes are complex)
            int typeHintCount = 0;
            for (Map.Entry<String, String> typeHint : suggestions.typeHints.entrySet()) {
                String varName = typeHint.getKey();
                String suggestedType = typeHint.getValue();
                
                // For now, just record the type hints as suggestions
                // Actually changing types in Ghidra requires careful handling of data flow
                result.typeUpdates.put(varName, suggestedType);
                typeHintCount++;
            }
            
            success = true;
            
            // Build result message
            StringBuilder message = new StringBuilder();
            if (result.functionRenamed) {
                message.append("Function renamed: ").append(result.originalFunctionName)
                       .append(" → ").append(result.newFunctionName).append("\n");
            }
            
            if (renameCount > 0) {
                message.append("Successfully renamed ").append(renameCount).append(" variable(s)\n");
            }
            
            if (typeHintCount > 0) {
                message.append("Generated ").append(typeHintCount).append(" type suggestion(s)\n");
            }
            
            if (!result.functionRenamed && renameCount == 0 && typeHintCount == 0) {
                message.append("No enhancement changes were applied");
            }
            
            result.message = message.toString();
            
        } finally {
            program.endTransaction(transactionID, success);
        }
        
        return result;
    }
    
    /**
     * Validates function name
     */
    private boolean isValidFunctionName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        
        // Must start with letter or underscore
        if (!Character.isLetter(name.charAt(0)) && name.charAt(0) != '_') {
            return false;
        }
        
        // Must contain only letters, digits, and underscores
        for (int i = 1; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Validates variable name
     */
    private boolean isValidVariableName(String name) {
        return isValidFunctionName(name); // Same rules apply
    }
    
    /**
     * Clean up resources
     */
    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
        }
    }
    
    /**
     * Holds variable information
     */
    private static class VariableInfo {
        String name;
        String type;
        boolean isParameter;
        Variable variable;
        HighSymbol highSymbol;
        HighVariable highVariable;  // For decompiler variable renaming
    }
    
    /**
     * Holds comprehensive rewrite suggestions from model
     */
    private static class ComprehensiveRewriteSpec {
        String functionName;
        Map<String, String> variableRenames = new HashMap<>();
        Map<String, String> variableTypes = new HashMap<>();
        String functionPrototype;
        Map<String, String> comments = new HashMap<>();
    }
    
    /**
     * Result of enhancement operation
     */
    public static class EnhancementResult {
        public String functionName;
        public String originalFunctionName;
        public String newFunctionName;
        public boolean functionRenamed = false;
        public Map<String, String> variableRenames = new HashMap<>();
        public Map<String, String> typeUpdates = new HashMap<>();
        public List<String> errors = new ArrayList<>();
        public String message;
        
        public String getReport() {
            StringBuilder report = new StringBuilder();
            report.append(message).append("\n\n");
            
            if (functionRenamed) {
                report.append("Function Rename:\n");
                report.append("  ").append(originalFunctionName).append(" → ").append(newFunctionName).append("\n\n");
            }
            
            if (!variableRenames.isEmpty()) {
                report.append("Variable Renames Applied:\n");
                for (Map.Entry<String, String> rename : variableRenames.entrySet()) {
                    report.append("  ").append(rename.getKey()).append(" → ").append(rename.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!typeUpdates.isEmpty()) {
                report.append("Type Improvements Suggested:\n");
                for (Map.Entry<String, String> typeUpdate : typeUpdates.entrySet()) {
                    report.append("  ").append(typeUpdate.getKey()).append(" → ").append(typeUpdate.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!errors.isEmpty()) {
                report.append("Errors encountered:\n");
                for (String error : errors) {
                    report.append("  - ").append(error).append("\n");
                }
            }
            
            return report.toString();
        }
    }
}
