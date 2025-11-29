package ghidragpt.utils;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Utility class for modifying functions in Ghidra
 */
public class GhidraFunctionModifier {
    private final Program program;
    private final TaskMonitor monitor;

    public GhidraFunctionModifier(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    /**
     * Updates a function's name if the new name is valid and different
     */
    public boolean updateFunctionName(Function function, String newName) {
        if (newName == null || newName.trim().isEmpty() ||
            newName.equals(function.getName())) {
            return false;
        }

        try {
            SymbolTable symbolTable = program.getSymbolTable();
            Address entryPoint = function.getEntryPoint();

            // Check if name already exists
            if (symbolTable.getSymbols(newName).hasNext()) {
                return false;
            }

            // Rename the function
            function.setName(newName, SourceType.USER_DEFINED);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Updates a function's comment
     */
    public boolean updateFunctionComment(Function function, String comment) {
        if (comment == null || comment.trim().isEmpty()) {
            return false;
        }

        try {
            function.setComment(comment);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Updates a function's repeatable comment
     */
    public boolean updateFunctionRepeatableComment(Function function, String comment) {
        if (comment == null || comment.trim().isEmpty()) {
            return false;
        }

        try {
            function.setRepeatableComment(comment);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates if a function name is acceptable
     */
    public static boolean isValidFunctionName(String name) {
        if (name == null || name.trim().isEmpty()) {
            return false;
        }

        // Check for valid identifier characters
        if (!name.matches("[a-zA-Z_][a-zA-Z0-9_]*")) {
            return false;
        }

        // Check for reserved keywords (basic check)
        String[] reservedWords = {"if", "else", "for", "while", "do", "switch",
                                "case", "break", "continue", "return", "goto",
                                "class", "struct", "union", "enum", "typedef"};

        String lowerName = name.toLowerCase();
        for (String reserved : reservedWords) {
            if (lowerName.equals(reserved)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Gets the function manager for the current program
     */
    public FunctionManager getFunctionManager() {
        return program.getFunctionManager();
    }

    /**
     * Gets the current program
     */
    public Program getProgram() {
        return program;
    }

    /**
     * Gets the task monitor
     */
    public TaskMonitor getMonitor() {
        return monitor;
    }
}