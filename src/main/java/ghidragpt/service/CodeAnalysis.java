package ghidragpt.service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidragpt.ui.GhidraGPTConsole;

import java.io.IOException;
import java.util.Iterator;

/**
 * Service for analyzing code using GPT models
 */
public class CodeAnalysis {
    
    private final APIClient apiClient;
    private final DecompInterface decompiler;
    private final FunctionRewrite functionRewriteService;
    private final GhidraGPTConsole console;
    
    public CodeAnalysis(APIClient apiClient, GhidraGPTConsole console) {
        this.apiClient = apiClient;
        this.console = console;
        this.decompiler = new DecompInterface();
        this.functionRewriteService = new FunctionRewrite(apiClient, console);
    }
    
    public void initializeDecompiler(Program program) {
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }
    
    public void dispose() {
        decompiler.dispose();
        functionRewriteService.dispose();
    }
    
    /**
     * Comprehensively rewrite function: rename function and variables for maximum readability
     */
    public String rewriteFunction(Function function, Program program, TaskMonitor monitor) {
        try {
            if (!isServiceConfigured()) {
                return createConfigurationError();
            }
            
            monitor.setMessage("Comprehensively enhancing function...");

            FunctionRewrite.EnhancementResult result = 
                functionRewriteService.rewriteFunction(function, program, monitor);
            
            return result.getReport();
            
        } catch (Exception e) {
            Msg.error(this, "Error enhancing function: " + e.getMessage(), e);
            return "Error during function rewrite: " + e.getMessage();
        }
    }
    
    /**
     * Detect potential vulnerabilities in the function
     */
    public String detectVulnerabilities(Function function, Program program, TaskMonitor monitor) {
        try {
            initializeDecompiler(program);
            DecompileResults results = decompiler.decompileFunction(function, 10, monitor); // Reduced timeout for speed
            if (results == null || !results.decompileCompleted()) {
                return "Failed to decompile function: " + function.getName();
            }
            
            String decompiledCode = results.getDecompiledFunction().getC();
            
            StringBuilder contextInfo = new StringBuilder();
            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(function.getEntryPoint());
            for (Symbol symbol : symbols) {
                contextInfo.append("Symbol: ").append(symbol.getName()).append("\n");
            }
            
            if (!isServiceConfigured()) {
                return createConfigurationError();
            }
            
            String prompt = buildVulnerabilityPrompt(decompiledCode, contextInfo.toString());
            try {
                // Print analysis header using console
                long startTime = System.currentTimeMillis();
                APIClient.GPTProvider provider = apiClient.getProvider();
                if (console != null) {
                    console.printAnalysisHeader("⚠ Vulnerability Detection", function.getName(), 
                        provider.toString(), apiClient.getModel(), prompt.length());
                }
                
                // Use StringBuilder to collect streaming response
                final StringBuilder responseBuilder = new StringBuilder();
                
                // Send request with streaming
                String response = apiClient.sendRequest(prompt, new APIClient.StreamCallback() {
                    private boolean isFirstResponse = true;
                    
                    @Override
                    public void onPartialResponse(String partialContent) {
                        responseBuilder.append(partialContent);
                        
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
                    }
                    
                    @Override
                    public void onComplete(String fullContent) {
                        long duration = System.currentTimeMillis() - startTime;
                        if (console != null) {
                            console.printStreamComplete("vulnerability detection", duration, fullContent.length());
                        }
                    }
                    
                    @Override
                    public void onError(Exception error) {
                        if (console != null) {
                            console.printStreamError("vulnerability detection", error.getMessage());
                        }
                    }
                });
                
                return response;
            } catch (IOException e) {
                return "API Error: " + e.getMessage();
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error detecting vulnerabilities: " + e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * Generate a detailed explanation of the function
     */
    public String explainFunction(Function function, Program program, TaskMonitor monitor) {
        try {
            initializeDecompiler(program);
            DecompileResults results = decompiler.decompileFunction(function, 10, monitor); // Reduced timeout for speed
            if (results == null || !results.decompileCompleted()) {
                return "Failed to decompile function: " + function.getName();
            }
            
            String decompiledCode = results.getDecompiledFunction().getC();
            
            if (!isServiceConfigured()) {
                return createConfigurationError();
            }
            
            String prompt = buildExplanationPrompt(decompiledCode, function.getName());
            try {
                // Print analysis header using console
                long startTime = System.currentTimeMillis();
                APIClient.GPTProvider provider = apiClient.getProvider();
                if (console != null) {
                    console.printAnalysisHeader("◉ Function Explanation", function.getName(),
                        provider.toString(), apiClient.getModel(), prompt.length());
                }                // Send request with streaming
                String response = apiClient.sendRequest(prompt, new APIClient.StreamCallback() {
                    private boolean isFirstResponse = true;
                    
                    @Override
                    public void onPartialResponse(String partialContent) {
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
                    }
                    
                    @Override
                    public void onComplete(String fullContent) {
                        long duration = System.currentTimeMillis() - startTime;
                        if (console != null) {
                            console.printStreamComplete("function explanation", duration, fullContent.length());
                        }
                    }
                    
                    @Override
                    public void onError(Exception error) {
                        if (console != null) {
                            console.printStreamError("function explanation", error.getMessage());
                        }
                    }
                });
                
                return response;
            } catch (IOException e) {
                return "API Error: " + e.getMessage();
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error explaining function: " + e.getMessage(), e);
            return "Error: " + e.getMessage();
        }
    }
    
    // Helper methods for configuration and error handling
    private boolean isServiceConfigured() {
        // Ollama doesn't require API key, all others do
        if (apiClient.getProvider() == APIClient.GPTProvider.OLLAMA) {
            return true; // Ollama only needs to be selected, no API key required
        }
        return apiClient.getApiKey() != null && !apiClient.getApiKey().trim().isEmpty();
    }
    
    private String createConfigurationError() {
        return "Configuration Error:\n" + createConfigurationStatus() + 
               "\n\nPlease configure the API settings in the Configuration tab.";
    }
    
    private String createEmptyResponseError() {
        return "Empty or no response from model service.\n\n" +
               "Possible causes:\n" +
               "1. API key is invalid or expired\n" +
               "2. Network connectivity issues\n" +
               "3. API rate limits exceeded\n" +
               "4. Service is temporarily unavailable\n\n" +
               createConfigurationStatus();
    }
    
    private String createConfigurationStatus() {
        StringBuilder status = new StringBuilder();
        status.append("Current Configuration:\n");
        status.append("Provider: ").append(apiClient.getProvider()).append("\n");
        status.append("Model: ").append(apiClient.getModel().isEmpty() ? "default" : apiClient.getModel()).append("\n");
        status.append("API Key: ").append(apiClient.getApiKey() != null && !apiClient.getApiKey().trim().isEmpty() ? "configured" : "not configured").append("\n");
        
        // All providers now require API key configuration
        
        return status.toString();
    }
    
    // Prompt building methods
    private String buildVulnerabilityPrompt(String code, String contextInfo) {
        return "SECURITY ANALYSIS - Find REAL, EXPLOITABLE vulnerabilities only:\n\n" +
               "Context: " + contextInfo + "\n\n" +
               "Code:\n" + code + "\n\n" +
               "STRICT CRITERIA - Only report vulnerabilities that are:\n" +
               "✓ DEFINITELY exploitable (not theoretical)\n" +
               "✓ Have clear attack vectors\n" +
               "✓ Medium to High severity impact\n" +
               "✓ Realistic in real-world scenarios\n\n" +
               "IGNORE:\n" +
               "✗ Theoretical vulnerabilities with no clear exploit\n" +
               "✗ Low-impact issues that require unrealistic conditions\n" +
               "✗ Code style or minor issues\n" +
               "✗ \"Potential\" vulnerabilities without concrete evidence\n\n" +
               "FORMAT: For each real vulnerability found:\n" +
               " [•] Vulnerability Name\n" +
               " [Vulnerability Name here]\n\n" +
               " [▲] Severity\n" +
               " [High/Medium]\n\n" +
               " [!] Exploitability\n" +
               " [How exactly can this be exploited?]\n\n" +
               " [×] Impact\n" +
               " [What damage can be done?]\n\n" +
               " [→] Location\n" +
               " [Specific line/function]\n\n" +
               "If no real vulnerabilities found, respond: \"[√] No exploitable vulnerabilities detected.\" " +
               "with no extra details";
    }
    
    private String buildExplanationPrompt(String code, String functionName) {
        return "CONCISE FUNCTION ANALYSIS for: " + functionName + "\n\n" +
               "Code:\n" + code + "\n\n" +
               "Provide a BRIEF, focused explanation in this format:\n\n" +
               "[•] Purpose\n" +
               "[One sentence describing what this function does]\n\n" +
               "[»] How it works\n" +
               "[2-3 bullet points of key operations]\n\n" +
               "[◦] Key Details\n" +
               "[Important parameters, return values, or notable behavior]\n\n" +
               "Keep it under 150 words total unless needed. Focus on WHAT and HOW, not line-by-line details.";
    }
}
