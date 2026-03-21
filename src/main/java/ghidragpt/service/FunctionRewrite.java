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
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
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
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidragpt.ui.Console;
import ghidragpt.service.APIClient;
import ghidragpt.utils.PromptBuilder;
import ghidragpt.utils.ResponseParser;
import ghidragpt.utils.GhidraFunctionModifier;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import ghidra.program.model.address.Address;
import ghidragpt.config.ConfigurationManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.LinkedHashMap;

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
    private final ConfigurationManager configManager;
    private GhidraFunctionModifier functionModifier;
    
    public FunctionRewrite(APIClient apiClient, Console console, ConfigurationManager configManager) {
        this.apiClient = apiClient;
        this.console = console;
        this.configManager = configManager;
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
            
            // Generate address-annotated decompiled code for accurate comment placement
            String annotatedCode = generateAddressAnnotatedCode(decompileResults);
            
            // Create function analysis using domain model
            FunctionAnalysis functionAnalysis = new FunctionAnalysis(function, true);
            
            // Extract variable information using domain model
            List<VariableAnalysis> variables = extractVariableAnalyses(function, highFunction);
            functionAnalysis.getVariables().addAll(variables);
            
            // Extract global variable references from the decompiler
            List<GlobalVarInfo> globalRefs = extractGlobalReferences(highFunction);
            
            // Generate comprehensive rewrite prompt using PromptBuilder
            String enhancementPrompt = generateComprehensiveRewritePrompt(function, annotatedCode != null ? annotatedCode : decompiledCode, functionAnalysis, globalRefs);
            
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
            
            // Parsing model response for comprehensive rewrite specification
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
     * Extract global variables referenced by this function from the decompiler's global symbol map.
     */
    private List<GlobalVarInfo> extractGlobalReferences(HighFunction highFunction) {
        List<GlobalVarInfo> globals = new ArrayList<>();
        if (highFunction == null) {
            return globals;
        }

        GlobalSymbolMap globalMap = highFunction.getGlobalSymbolMap();
        if (globalMap == null) {
            return globals;
        }

        Iterator<HighSymbol> symbols = globalMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String name = symbol.getName();
            if (name == null || name.isEmpty()) {
                continue;
            }

            GlobalVarInfo info = new GlobalVarInfo();
            info.name = name;
            info.address = symbol.getStorage().getMinAddress();

            HighVariable highVar = symbol.getHighVariable();
            if (highVar != null && highVar.getDataType() != null) {
                info.type = highVar.getDataType().getDisplayName();
            } else if (symbol.getDataType() != null) {
                info.type = symbol.getDataType().getDisplayName();
            } else {
                info.type = "unknown";
            }

            globals.add(info);
        }

        return globals;
    }
    
    /**
     * Generate address-annotated decompiled code.
     * Each statement line is prefixed with its instruction address from the decompiler token tree,
     * so the LLM can reference exact addresses for comment placement.
     */
    private String generateAddressAnnotatedCode(DecompileResults decompileResults) {
        try {
            ClangTokenGroup markup = decompileResults.getCCodeMarkup();
            if (markup == null) {
                return null;
            }
            
            // Flatten all tokens in order
            List<ClangToken> allTokens = new ArrayList<>();
            collectTokens(markup, allTokens);
            
            // Build lines: group tokens by line breaks, track first address per line
            StringBuilder result = new StringBuilder();
            StringBuilder currentLine = new StringBuilder();
            Address lineAddr = null;
            
            for (ClangToken token : allTokens) {
                String text = token.toString();
                
                // Check for line breaks
                if (text.contains("\n")) {
                    // Emit current line with address annotation
                    String lineText = currentLine.toString();
                    if (!lineText.trim().isEmpty()) {
                        if (lineAddr != null) {
                            result.append("/* ").append(lineAddr.toString()).append(" */ ");
                        }
                        result.append(lineText);
                    }
                    result.append("\n");
                    currentLine = new StringBuilder();
                    lineAddr = null;
                } else {
                    currentLine.append(text);
                    // Capture first meaningful address for this line
                    if (lineAddr == null) {
                        Address tokenAddr = token.getMinAddress();
                        if (tokenAddr != null) {
                            lineAddr = tokenAddr;
                        }
                    }
                }
            }
            
            // Emit last line
            String lineText = currentLine.toString();
            if (!lineText.trim().isEmpty()) {
                if (lineAddr != null) {
                    result.append("/* ").append(lineAddr.toString()).append(" */ ");
                }
                result.append(lineText);
                result.append("\n");
            }
            
            return result.toString();
        } catch (Exception e) {
            Msg.warn(this, "Failed to generate address-annotated code: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Recursively collect all ClangTokens from a ClangNode tree in order.
     */
    private void collectTokens(ClangNode node, List<ClangToken> tokens) {
        if (node instanceof ClangToken) {
            tokens.add((ClangToken) node);
        } else {
            for (int i = 0; i < node.numChildren(); i++) {
                collectTokens(node.Child(i), tokens);
            }
        }
    }
    
    /**
     * Generate comprehensive rewrite prompt for model analysis
     */
    private String generateComprehensiveRewritePrompt(Function function, String decompiledCode, FunctionAnalysis functionAnalysis, List<GlobalVarInfo> globalRefs) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this decompiled function and provide a comprehensive rewrite specification to make it as human-readable as possible.\n");
        if (configManager != null) {
            String customInstructions = configManager.getCustomInstructions();
            if (customInstructions != null && !customInstructions.trim().isEmpty()) {
                prompt.append(customInstructions.trim()).append("\n");
            }
        }
        prompt.append("\n");
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
        
        // Add global variables referenced by this function
        if (globalRefs != null && !globalRefs.isEmpty()) {
            StringBuilder globalsSection = new StringBuilder();
            for (GlobalVarInfo global : globalRefs) {
                globalsSection.append("- ").append(global.name)
                    .append(" @ ").append(global.address)
                    .append(" (").append(global.type).append(")\n");
            }
            prompt.append("Referenced Global Variables (DAT_*, cls_*, etc.):\n")
                  .append(globalsSection).append("\n");
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
        prompt.append("   - Data size patterns (int vs long vs pointer)\n");
        prompt.append("8. For global variables (DAT_*, cls_*), suggest descriptive names and types based on how they are used in this function\n\n");
        
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
        prompt.append("    \"0x414f52\": \"comment text (use address from annotated code)\",\n");
        prompt.append("    ...\n");
        prompt.append("  },\n");
        prompt.append("  \"global_renames\": {\n");
        prompt.append("    \"DAT_0054a938\": \"descriptiveName\",\n");
        prompt.append("    ...\n");
        prompt.append("  },\n");
        prompt.append("  \"global_types\": {\n");
        prompt.append("    \"DAT_0054a938\": \"float\",\n");
        prompt.append("    ...\n");
        prompt.append("  }\n");
        prompt.append("}\n\n");
        
        prompt.append("Examples:\n");
        prompt.append("{\n");
        prompt.append("  \"function_name\": \"handle_security_failure\",\n");
        prompt.append("  \"variable_renames\": {\n");
        prompt.append("    \"param_1\": \"violationAddress\",\n");
        prompt.append("    \"local_38\": \"imageBaseBuffer\",\n");
        prompt.append("    \"uStack_20\": \"stackParameter\"\n");
        prompt.append("  },\n");
        prompt.append("  \"variable_types\": {\n");
        prompt.append("    \"violationAddress\": \"PVOID\",\n");
        prompt.append("    \"imageBaseBuffer\": \"DWORD64*\"\n");
        prompt.append("  },\n");
        prompt.append("  \"function_prototype\": \"NTSTATUS handle_security_failure(PVOID violationAddress, ULONG violationCode)\",\n");
        prompt.append("  \"comments\": {\n");
        prompt.append("    \"0x1400010a0\": \"Check if violation address is valid\",\n");
        prompt.append("    \"0x1400010c5\": \"Log security event before returning\"\n");
        prompt.append("  },\n");
        prompt.append("  \"global_renames\": {\n");
        prompt.append("    \"DAT_0054a938\": \"defaultMouseX\",\n");
        prompt.append("    \"DAT_0054a93c\": \"defaultMouseY\"\n");
        prompt.append("  },\n");
        prompt.append("  \"global_types\": {\n");
        prompt.append("    \"DAT_0054a938\": \"float\",\n");
        prompt.append("    \"DAT_0054a93c\": \"float\"\n");
        prompt.append("  }\n");
        prompt.append("}\n\n");
        
        prompt.append("Notes:\n");
        prompt.append("- Keep well-named variables like 'ControlPc' and 'FunctionEntry' unless you have significantly better names.\n");
        prompt.append("- For comments, use the exact hex addresses shown in the /* addr */ annotations of the decompiled code\n");
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

            // Extract global_renames object
            if (rootNode.has("global_renames")) {
                spec.globalRenames = parseJsonObject(rootNode.get("global_renames"));
            }

            // Extract global_types object
            if (rootNode.has("global_types")) {
                spec.globalTypes = parseJsonObject(rootNode.get("global_types"));
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
            // 1. Apply function rename if enabled in config
            
            if (configManager != null && configManager.isApplyFunctionRename()
                    && spec.functionName != null && !spec.functionName.equals(function.getName())) {
                try {
                    function.setName(spec.functionName, SourceType.USER_DEFINED);
                    result.newFunctionName = spec.functionName;
                    result.functionRenamed = true;
                    result.suggestionOutcomes.add(new SuggestionOutcome("Function Rename", result.originalFunctionName + " \u2192 " + spec.functionName, true, null));
                    Msg.info(this, "Renamed function: " + result.originalFunctionName + " -> " + spec.functionName);
                } catch (DuplicateNameException | InvalidInputException e) {
                    result.suggestionOutcomes.add(new SuggestionOutcome("Function Rename", result.originalFunctionName + " \u2192 " + spec.functionName, false, e.getMessage()));
                    result.errors.add("Failed to rename function to " + spec.functionName + ": " + e.getMessage());
                }
            }
            
            // 2. Apply function prototype if enabled in config
            if (configManager != null && configManager.isApplyFunctionPrototype()
                    && spec.functionPrototype != null && !spec.functionPrototype.trim().isEmpty()) {
                try {
                    applyFunctionPrototype(function, program, spec.functionPrototype);
                    result.suggestionOutcomes.add(new SuggestionOutcome("Function Prototype", spec.functionPrototype, true, null));
                    Msg.info(this, "Updated function prototype: " + spec.functionPrototype);
                } catch (Exception e) {
                    result.suggestionOutcomes.add(new SuggestionOutcome("Function Prototype", spec.functionPrototype, false, e.getMessage()));
                    result.errors.add("Failed to update function prototype: " + e.getMessage());
                    Msg.error(this, "Prototype update failed", e);
                }
            }
            
            // 3. Apply member field type changes FIRST (before renames)
            // Changing undefined1 -> float creates a proper 4-byte component that can then be renamed
            int fieldTypeCount = 0;
            for (Map.Entry<String, String> typeChange : spec.variableTypes.entrySet()) {
                String varName = typeChange.getKey();
                String newType = typeChange.getValue();
                
                if (applyMemberFieldTypeChange(function, program, varName, newType, spec.variableRenames)) {
                    fieldTypeCount++;
                    result.typeUpdates.put(varName, newType);
                    result.suggestionOutcomes.add(new SuggestionOutcome("Field Type", varName + " \u2192 " + newType, true, null));
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
                    result.suggestionOutcomes.add(new SuggestionOutcome("Variable Rename", oldName + " \u2192 " + newName, true, null));
                    Msg.info(this, "Renamed variable: " + oldName + " -> " + newName);
                } else if (isMemberFieldName(oldName) && applyMemberFieldRename(function, program, oldName, newName)) {
                    fieldRenameCount++;
                    result.variableRenames.put(oldName, newName);
                    result.suggestionOutcomes.add(new SuggestionOutcome("Field Rename", oldName + " \u2192 " + newName, true, null));
                    Msg.info(this, "Renamed struct field: " + oldName + " -> " + newName);
                } else if ("this".equals(oldName)) {
                    // Skipping 'this' is expected - Ghidra does not allow renaming auto-parameters
                    Msg.info(this, "Skipping rename of auto-parameter 'this'");
                } else {
                    result.suggestionOutcomes.add(new SuggestionOutcome("Variable Rename", oldName + " \u2192 " + newName, false, "Variable not found in decompiler output"));
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
                    result.suggestionOutcomes.add(new SuggestionOutcome("Type Change", varName + " \u2192 " + newType, true, null));
                    Msg.info(this, "Changed type for " + varName + " to " + newType);
                } else {
                    result.suggestionOutcomes.add(new SuggestionOutcome("Type Change", varName + " \u2192 " + newType, false, "Variable not found or type could not be resolved"));
                    result.errors.add("Failed to change type for variable: " + varName);
                }
            }
            
            // 6. Apply all comments as a single plate comment on the function
            int commentCount = 0;
            if (!spec.comments.isEmpty()) {
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
                for (Map.Entry<String, String> comment : spec.comments.entrySet()) {
                    plateComment.append("  [").append(comment.getKey()).append("] ").append(comment.getValue()).append("\n");
                    commentCount++;
                    result.suggestionOutcomes.add(new SuggestionOutcome("Comment", comment.getValue(), true, null));
                }
                function.setComment(plateComment.toString().trim());
                Msg.info(this, "Added " + commentCount + " comment(s) as function plate comment");
            }
            
            // 7. Apply global variable type changes FIRST (before renames, so we resolve by old name)
            int globalTypeCount = 0;
            for (Map.Entry<String, String> typeChange : spec.globalTypes.entrySet()) {
                String globalName = typeChange.getKey();
                String newType = typeChange.getValue();
                if (applyGlobalTypeChange(program, globalName, newType)) {
                    globalTypeCount++;
                    result.globalTypeUpdates.put(globalName, newType);
                    result.suggestionOutcomes.add(new SuggestionOutcome(
                        "Global Type", globalName + " \u2192 " + newType, true, null));
                    Msg.info(this, "Changed global type: " + globalName + " -> " + newType);
                } else {
                    result.suggestionOutcomes.add(new SuggestionOutcome(
                        "Global Type", globalName + " \u2192 " + newType, false, "Could not resolve global or type"));
                }
            }
            
            // 8. Apply global variable renames
            int globalRenameCount = 0;
            for (Map.Entry<String, String> rename : spec.globalRenames.entrySet()) {
                String oldName = rename.getKey();
                String newName = rename.getValue();
                // Skip identity renames
                if (oldName.equals(newName)) {
                    continue;
                }
                if (!isDefaultGlobalName(oldName)) {
                    result.suggestionOutcomes.add(new SuggestionOutcome(
                        "Global Rename", oldName + " \u2192 " + newName, false, "Already user-renamed"));
                    continue;
                }
                if (applyGlobalRename(program, oldName, newName)) {
                    globalRenameCount++;
                    result.globalRenames.put(oldName, newName);
                    result.suggestionOutcomes.add(new SuggestionOutcome(
                        "Global Rename", oldName + " \u2192 " + newName, true, null));
                    Msg.info(this, "Renamed global: " + oldName + " -> " + newName);
                } else {
                    result.suggestionOutcomes.add(new SuggestionOutcome(
                        "Global Rename", oldName + " \u2192 " + newName, false, "Symbol not found in program"));
                }
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
            
            if (globalRenameCount > 0) {
                message.append("Successfully renamed ").append(globalRenameCount).append(" global(s)\n");
            }
            
            if (globalTypeCount > 0) {
                message.append("Successfully updated types for ").append(globalTypeCount).append(" global(s)\n");
            }
            
            if (!result.functionRenamed && renameCount == 0 && fieldRenameCount == 0 && typeCount == 0 && fieldTypeCount == 0 && commentCount == 0 && globalRenameCount == 0 && globalTypeCount == 0 && spec.functionPrototype == null) {
                message.append("No changes were applied");
            }
            
            result.message = message.toString();
            
        } finally {
            program.endTransaction(transactionID, success);
        }
        
        // Print per-suggestion summary to console with color
        if (console != null && !result.suggestionOutcomes.isEmpty()
                && configManager != null && configManager.isPrintRewriteSummary()) {
            List<String[]> lines = new ArrayList<>();
            for (SuggestionOutcome outcome : result.suggestionOutcomes) {
                if (!outcome.applied) continue;
                lines.add(new String[]{"OK", "[OK] [" + outcome.category + "] " + outcome.suggestion});
            }
            for (SuggestionOutcome outcome : result.suggestionOutcomes) {
                if (outcome.applied) continue;
                String text = "[FAIL] [" + outcome.category + "] " + outcome.suggestion;
                if (outcome.reason != null) {
                    text += "  -> Reason: " + outcome.reason;
                }
                lines.add(new String[]{"FAIL", text});
            }
            console.printSuggestionSummary(function.getName(), lines);
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
            // Skip 'this' auto-parameter - Ghidra does not allow renaming it
            if ("this".equals(oldName)) {
                Msg.info(this, "Skipping rename of auto-parameter 'this'");
                return false;
            }
            
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
     * Check if a name looks like a struct member field name (auto-generated or user-renamed)
     */
    private boolean isMemberFieldName(String name) {
        return name.startsWith("mbr_") || name.startsWith("field") || name.startsWith("m_");
    }
    
    /**
     * Apply member field rename on the struct data type.
     * Searches by field name across the top-level struct and all nested structs,
     * since fields like field9_0x60 may live on a nested struct (e.g. this->m_viewStuff.field9_0x60).
     * Falls back to offset-based lookup on the top-level struct if name search fails.
     */
    private boolean applyMemberFieldRename(Function function, Program program, String oldName, String newName) {
        try {
            // Get the 'this' parameter's struct type
            Parameter[] params = function.getParameters();
            if (params.length == 0) {
                return false;
            }
            
            // Find a pointer-to-struct parameter (typically 'this' is first)
            Structure topStruct = null;
            for (Parameter param : params) {
                DataType paramType = param.getDataType();
                if (paramType instanceof Pointer) {
                    DataType baseType = ((Pointer) paramType).getDataType();
                    if (baseType instanceof Structure) {
                        topStruct = (Structure) baseType;
                        break;
                    }
                }
            }
            
            if (topStruct == null) {
                return false;
            }
            
            // Strategy 1: Search by field name across struct hierarchy (handles nested structs)
            DataTypeComponent found = findComponentByName(topStruct, oldName);
            if (found != null) {
                try {
                    found.setFieldName(newName);
                    Msg.info(this, "Renamed struct field: " + oldName + " -> " + newName);
                    return true;
                } catch (DuplicateNameException e) {
                    Msg.warn(this, "Duplicate field name: " + newName);
                    return false;
                }
            }
            
            // Strategy 2: Offset-based lookup on top-level struct (for mbr_0x18, field13_0x38 patterns)
            Matcher offsetMatcher = Pattern.compile("0x([0-9a-fA-F]+)").matcher(oldName);
            if (offsetMatcher.find()) {
                int fieldOffset = Integer.parseInt(offsetMatcher.group(1), 16);
                
                // Try top-level struct first
                DataTypeComponent component = topStruct.getComponentAt(fieldOffset);
                if (component != null) {
                    String currentFieldName = component.getFieldName();
                    if (currentFieldName == null || isMemberFieldName(currentFieldName)) {
                        try {
                            component.setFieldName(newName);
                            Msg.info(this, "Renamed struct field on " + topStruct.getName() + ": " + oldName + " -> " + newName + " at offset 0x" + Integer.toHexString(fieldOffset));
                            return true;
                        } catch (DuplicateNameException e) {
                            Msg.warn(this, "Duplicate field name: " + newName + " on struct " + topStruct.getName());
                            return false;
                        }
                    }
                }
                
                // Try nested structs at that offset
                DataTypeComponent nestedResult = findComponentByOffsetInNestedStructs(topStruct, fieldOffset);
                if (nestedResult != null) {
                    String currentFieldName = nestedResult.getFieldName();
                    if (currentFieldName == null || isMemberFieldName(currentFieldName)) {
                        try {
                            nestedResult.setFieldName(newName);
                            Msg.info(this, "Renamed nested struct field: " + oldName + " -> " + newName + " at offset 0x" + Integer.toHexString(fieldOffset));
                            return true;
                        } catch (DuplicateNameException e) {
                            Msg.warn(this, "Duplicate field name: " + newName);
                            return false;
                        }
                    }
                }
            }
            
            return false;
            
        } catch (Exception e) {
            Msg.error(this, "Error renaming member field " + oldName, e);
            return false;
        }
    }
    
    /**
     * Search for a component by field name in a struct and all its nested structs.
     * Checks the entire top level first before recursing into nested structs.
     */
    private DataTypeComponent findComponentByName(Structure struct, String fieldName) {
        // First pass: check direct fields only
        for (DataTypeComponent component : struct.getComponents()) {
            String name = component.getFieldName();
            if (fieldName.equals(name)) {
                return component;
            }
        }
        // Second pass: recurse into nested structs
        for (DataTypeComponent component : struct.getComponents()) {
            DataType dt = component.getDataType();
            if (dt instanceof Structure) {
                DataTypeComponent nested = findComponentByName((Structure) dt, fieldName);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }
    
    /**
     * Search for a component at a given offset in nested structs (not the top-level struct).
     */
    private DataTypeComponent findComponentByOffsetInNestedStructs(Structure struct, int offset) {
        for (DataTypeComponent component : struct.getComponents()) {
            DataType dt = component.getDataType();
            if (dt instanceof Structure) {
                Structure nested = (Structure) dt;
                DataTypeComponent found = nested.getComponentAt(offset);
                if (found != null) {
                    return found;
                }
                // Recurse deeper
                DataTypeComponent deeper = findComponentByOffsetInNestedStructs(nested, offset);
                if (deeper != null) {
                    return deeper;
                }
            }
        }
        return null;
    }
    
    /**
     * Apply type change to a struct member field.
     * Searches by field name across nested structs, with offset-based fallback.
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
            
            // Find pointer-to-struct from parameters
            Parameter[] params = function.getParameters();
            if (params.length == 0) {
                return false;
            }
            
            Structure topStruct = null;
            for (Parameter param : params) {
                DataType paramType = param.getDataType();
                if (paramType instanceof Pointer) {
                    DataType baseType = ((Pointer) paramType).getDataType();
                    if (baseType instanceof Structure) {
                        topStruct = (Structure) baseType;
                        break;
                    }
                }
            }
            
            if (topStruct == null) {
                return false;
            }
            
            // Strategy 1: Find by original field name across struct hierarchy
            DataTypeComponent component = findComponentByName(topStruct, originalFieldName);
            
            // Strategy 2: Find by offset on top-level struct, then nested structs
            if (component == null) {
                String nameForOffset = isMemberFieldName(originalFieldName) ? originalFieldName : varName;
                Matcher offsetMatcher = Pattern.compile("0x([0-9a-fA-F]+)").matcher(nameForOffset);
                if (offsetMatcher.find()) {
                    int fieldOffset = Integer.parseInt(offsetMatcher.group(1), 16);
                    component = topStruct.getComponentAt(fieldOffset);
                    if (component == null) {
                        component = findComponentByOffsetInNestedStructs(topStruct, fieldOffset);
                    }
                }
            }
            
            if (component == null) {
                return false;
            }
            
            // Only change type if current type is undefined
            String currentTypeName = component.getDataType().getName().toLowerCase();
            if (!currentTypeName.contains("undefined")) {
                Msg.info(this, "Skipping type change for " + varName + 
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
            
            // Replace the component with the new type
            // Need to find the parent struct that owns this component
            Structure ownerStruct = findOwnerStruct(topStruct, component);
            if (ownerStruct == null) {
                ownerStruct = topStruct;
            }
            int fieldOffset = component.getOffset();
            ownerStruct.replaceAtOffset(fieldOffset, dataType, dataType.getLength(), 
                component.getFieldName(), component.getComment());
            Msg.info(this, "Changed struct field type: " + currentTypeName + " -> " + newType + " for " + varName);
            return true;
            
        } catch (Exception e) {
            Msg.error(this, "Error changing type for member field " + varName, e);
            return false;
        }
    }
    
    /**
     * Find the struct that directly owns a given component.
     */
    private Structure findOwnerStruct(Structure struct, DataTypeComponent target) {
        for (DataTypeComponent component : struct.getComponents()) {
            if (component == target) {
                return struct;
            }
            DataType dt = component.getDataType();
            if (dt instanceof Structure) {
                Structure found = findOwnerStruct((Structure) dt, target);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
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
     * Apply a global variable rename using the program's SymbolTable.
     * Only renames globals that still have default auto-generated names.
     */
    private boolean applyGlobalRename(Program program, String oldName, String newName) {
        try {
            if (!isDefaultGlobalName(oldName)) {
                Msg.info(this, "Skipping global rename: " + oldName + " is not a default name (already user-renamed)");
                return false;
            }
            
            SymbolTable symbolTable = program.getSymbolTable();
            
            // Try to find by name in the global namespace
            Iterator<Symbol> symbols = symbolTable.getSymbols(oldName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.isGlobal()) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    return true;
                }
            }
            
            // Fallback: try to parse address from DAT_ pattern and find symbol at that address
            if (oldName.startsWith("DAT_")) {
                String addrStr = oldName.substring(4); // strip "DAT_"
                Address addr = program.getAddressFactory().getAddress(addrStr);
                if (addr != null) {
                    Symbol symbol = symbolTable.getPrimarySymbol(addr);
                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                        return true;
                    }
                }
            }
            
            Msg.warn(this, "Global symbol not found for rename: " + oldName);
            return false;
        } catch (DuplicateNameException | InvalidInputException e) {
            Msg.error(this, "Error renaming global " + oldName + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Check if a global symbol name is a default auto-generated name.
     * Ghidra generates names like DAT_, FUN_, cls_, LAB_, s_, PTR_, EXT_, etc.
     */
    private boolean isDefaultGlobalName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        return name.matches("^(DAT|FUN|cls|LAB|PTR|EXT|s|switchD|caseD|GUID|thunk_FUN|AddrTable)_[0-9a-fA-Fx]+$")
            || name.matches("^(meth|vftable|Class)_0x[0-9a-fA-F]+$");
    }
    
    /**
     * Apply a global variable type change.
     * Finds the data at the symbol's address and re-creates it with the new type.
     */
    private boolean applyGlobalTypeChange(Program program, String globalName, String newTypeName) {
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            Address addr = null;
            
            // Find the address of this global
            Iterator<Symbol> symbols = symbolTable.getSymbols(globalName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.isGlobal()) {
                    addr = symbol.getAddress();
                    break;
                }
            }
            
            // Fallback: parse address from DAT_ pattern
            if (addr == null && globalName.startsWith("DAT_")) {
                String addrStr = globalName.substring(4);
                addr = program.getAddressFactory().getAddress(addrStr);
            }
            
            if (addr == null) {
                Msg.warn(this, "Global symbol address not found for type change: " + globalName);
                return false;
            }
            
            // Resolve the target data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newTypeName);
            if (dataType == null) {
                Msg.warn(this, "Could not resolve data type: " + newTypeName);
                return false;
            }
            
            // Apply the type at the address
            Listing listing = program.getListing();
            listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);
            listing.createData(addr, dataType);
            Msg.info(this, "Applied global type " + newTypeName + " at " + addr);
            return true;
            
        } catch (Exception e) {
            Msg.error(this, "Error changing type for global " + globalName + ": " + e.getMessage());
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
     * Holds global variable information referenced by a function
     */
    private static class GlobalVarInfo {
        String name;
        String type;
        Address address;
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
     * Tracks the outcome of a single suggestion
     */
    public static class SuggestionOutcome {
        public String category;   // e.g. "Variable Rename", "Type Change", "Comment"
        public String suggestion; // human-readable description
        public boolean applied;
        public String reason;     // null if applied, otherwise the failure reason

        public SuggestionOutcome(String category, String suggestion, boolean applied, String reason) {
            this.category = category;
            this.suggestion = suggestion;
            this.applied = applied;
            this.reason = reason;
        }
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
        Map<String, String> globalRenames = new HashMap<>();
        Map<String, String> globalTypes = new HashMap<>();
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
        public Map<String, String> globalRenames = new HashMap<>();
        public Map<String, String> globalTypeUpdates = new HashMap<>();
        public List<String> errors = new ArrayList<>();
        public List<SuggestionOutcome> suggestionOutcomes = new ArrayList<>();
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
            
            if (!globalRenames.isEmpty()) {
                report.append("Global Rename Suggestions:\n");
                for (Map.Entry<String, String> rename : globalRenames.entrySet()) {
                    report.append("  ").append(rename.getKey()).append(" \u2192 ").append(rename.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!globalTypeUpdates.isEmpty()) {
                report.append("Global Type Suggestions:\n");
                for (Map.Entry<String, String> typeUpdate : globalTypeUpdates.entrySet()) {
                    report.append("  ").append(typeUpdate.getKey()).append(" \u2192 ").append(typeUpdate.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!errors.isEmpty()) {
                report.append("Errors encountered:\n");
                for (String error : errors) {
                    report.append("  - ").append(error).append("\n");
                }
            }
            
            if (!suggestionOutcomes.isEmpty()) {
                report.append("\nSuggestion Summary:\n");
                report.append("-".repeat(60)).append("\n");
                for (SuggestionOutcome outcome : suggestionOutcomes) {
                    if (!outcome.applied) continue;
                    report.append("[OK] [").append(outcome.category).append("] ").append(outcome.suggestion).append("\n");
                }
                for (SuggestionOutcome outcome : suggestionOutcomes) {
                    if (outcome.applied) continue;
                    report.append("[FAIL] [").append(outcome.category).append("] ").append(outcome.suggestion);
                    if (outcome.reason != null) {
                        report.append("  -> Reason: ").append(outcome.reason);
                    }
                    report.append("\n");
                }
                report.append("-".repeat(60)).append("\n");
            }
            
            return report.toString();
        }
    }
}
