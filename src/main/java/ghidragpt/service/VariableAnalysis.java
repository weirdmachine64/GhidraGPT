package ghidragpt.service;

import ghidra.program.model.data.DataType;

/**
 * Domain model representing a variable in function analysis
 */
public class VariableAnalysis {
    private final String name;
    private final DataType type;
    private final VariableCategory category;
    private final boolean isParameter;

    public enum VariableCategory {
        PARAMETER, LOCAL, TEMPORARY, STACK, WELL_NAMED
    }

    public VariableAnalysis(String name, DataType type, boolean isParameter) {
        this.name = name;
        this.type = type;
        this.isParameter = isParameter;
        this.category = categorizeVariable(name, isParameter);
    }

    private VariableCategory categorizeVariable(String name, boolean isParameter) {
        if (isParameter) {
            return VariableCategory.PARAMETER;
        }

        if (name.matches("^[iufl]Var\\d+$")) {
            return VariableCategory.TEMPORARY;
        }

        if (name.matches("^[ui]Stack_\\d+$|^local_\\d+$")) {
            return VariableCategory.STACK;
        }

        if (name.matches("^[A-Z][a-zA-Z0-9_]*$") && name.length() > 3) {
            return VariableCategory.WELL_NAMED;
        }

        return VariableCategory.LOCAL;
    }

    public String getName() { return name; }
    public DataType getType() { return type; }
    public VariableCategory getCategory() { return category; }
    public boolean isParameter() { return isParameter; }

    public String getTypeDisplayName() {
        return type != null ? type.getDisplayName() : "unknown";
    }

    public boolean needsTypeAnalysis() {
        String typeName = getTypeDisplayName();
        return typeName.contains("undefined") ||
               typeName.equals("int") ||
               typeName.equals("uint") ||
               typeName.equals("void*");
    }

    @Override
    public String toString() {
        return String.format("- %s (%s)", name, getTypeDisplayName());
    }
}