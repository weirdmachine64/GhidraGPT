package ghidragpt.service;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.data.DataType;
import java.util.List;
import java.util.ArrayList;

/**
 * Domain model representing a function analysis result
 */
public class FunctionAnalysis {
    private final String functionName;
    private final String signature;
    private final List<VariableAnalysis> variables;
    private final List<String> issues;
    private final FunctionComplexity complexity;
    private final boolean hasDecompilerOutput;

    public enum FunctionComplexity {
        SIMPLE, MODERATE, COMPLEX, VERY_COMPLEX
    }

    public FunctionAnalysis(Function function, boolean hasDecompilerOutput) {
        this.functionName = function.getName();
        this.signature = buildSignature(function);
        this.variables = analyzeVariables(function);
        this.issues = new ArrayList<>();
        this.complexity = determineComplexity(function);
        this.hasDecompilerOutput = hasDecompilerOutput;
    }

    private String buildSignature(Function function) {
        StringBuilder sb = new StringBuilder();
        sb.append(function.getReturnType().getDisplayName())
          .append(" ")
          .append(function.getName())
          .append("(");

        Parameter[] params = function.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(params[i].getDataType().getDisplayName())
              .append(" ")
              .append(params[i].getName());
        }
        sb.append(")");
        return sb.toString();
    }

    private List<VariableAnalysis> analyzeVariables(Function function) {
        List<VariableAnalysis> vars = new ArrayList<>();

        // Add parameters
        for (Parameter param : function.getParameters()) {
            vars.add(new VariableAnalysis(param.getName(), param.getDataType(), true));
        }

        // Add local variables (would need to be extracted from decompiler output)
        // This is a placeholder for now
        return vars;
    }

    private FunctionComplexity determineComplexity(Function function) {
        int paramCount = function.getParameterCount();
        long instructionCount = function.getBody().getNumAddresses();

        if (instructionCount < 20 && paramCount <= 2) {
            return FunctionComplexity.SIMPLE;
        } else if (instructionCount < 100 && paramCount <= 4) {
            return FunctionComplexity.MODERATE;
        } else if (instructionCount < 500) {
            return FunctionComplexity.COMPLEX;
        } else {
            return FunctionComplexity.VERY_COMPLEX;
        }
    }

    public void addIssue(String issue) {
        issues.add(issue);
    }

    public String getFunctionName() { return functionName; }
    public String getSignature() { return signature; }
    public List<VariableAnalysis> getVariables() { return variables; }
    public List<String> getIssues() { return issues; }
    public FunctionComplexity getComplexity() { return complexity; }
    public boolean hasDecompilerOutput() { return hasDecompilerOutput; }

    public boolean needsAnalysis() {
        return complexity != FunctionComplexity.SIMPLE ||
               !issues.isEmpty() ||
               variables.stream().anyMatch(VariableAnalysis::needsTypeAnalysis);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Function: ").append(functionName).append("\n");
        sb.append("Signature: ").append(signature).append("\n");
        sb.append("Complexity: ").append(complexity).append("\n");
        sb.append("Variables:\n");
        variables.forEach(v -> sb.append("  ").append(v).append("\n"));
        if (!issues.isEmpty()) {
            sb.append("Issues:\n");
            issues.forEach(i -> sb.append("  - ").append(i).append("\n"));
        }
        return sb.toString();
    }
}