package ghidragpt.utils;

/**
 * Builds prompts for model analysis of functions
 */
public class PromptBuilder {
    private final StringBuilder content = new StringBuilder();

    public PromptBuilder addSection(String title, String content) {
        this.content.append(title).append(":\n").append(content).append("\n\n");
        return this;
    }

    public PromptBuilder addInstructions(String instructions) {
        content.append("Analysis Instructions:\n").append(instructions).append("\n\n");
        return this;
    }

    public PromptBuilder addExamples(String examples) {
        content.append("Examples:\n").append(examples).append("\n\n");
        return this;
    }

    public PromptBuilder addNotes(String notes) {
        content.append("Notes:\n").append(notes).append("\n");
        return this;
    }

    public String build() {
        return content.toString();
    }

    public static PromptBuilder createFunctionAnalysisPrompt(String functionName, String decompiledCode) {
        return new PromptBuilder()
            .addSection("Current function", functionName)
            .addSection("Decompiled code", decompiledCode);
    }
}