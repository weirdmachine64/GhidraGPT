package ghidragpt.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link PromptBuilder}.
 */
class PromptBuilderTest {

    @Test
    void addSection_formatsTitleAndContent() {
        String out = new PromptBuilder()
                .addSection("Current function", "sub_401000")
                .build();
        assertEquals("Current function:\nsub_401000\n\n", out);
    }

    @Test
    void builderMethodsChainAndAccumulate() {
        String out = new PromptBuilder()
                .addSection("A", "1")
                .addInstructions("do the thing")
                .addNotes("be careful")
                .build();
        assertTrue(out.contains("A:\n1"));
        assertTrue(out.contains("Analysis Instructions:\ndo the thing"));
        assertTrue(out.contains("Notes:\nbe careful"));
    }

    @Test
    void createFunctionAnalysisPrompt_includesNameAndCode() {
        String out = PromptBuilder
                .createFunctionAnalysisPrompt("check_password", "int check_password(char *p) { return 0; }")
                .build();
        assertTrue(out.contains("check_password"), "prompt should mention the function name");
        assertTrue(out.contains("int check_password(char *p)"), "prompt should embed the decompiled code");
    }

    @Test
    void emptyBuilderProducesEmptyString() {
        assertEquals("", new PromptBuilder().build());
    }
}
