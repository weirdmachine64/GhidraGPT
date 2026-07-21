package ghidragpt.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ResponseParser}.
 *
 * These document the parser's current behavior, including its known
 * Java-oriented bias (see {@code isValidFunctionCode}), so that a future
 * rework toward decompiled C output has a baseline to compare against.
 */
class ResponseParserTest {

    // ----- extractFunctionCode -----

    @Test
    void extractFunctionCode_returnsNullForNullOrEmpty() {
        assertNull(ResponseParser.extractFunctionCode(null));
        assertNull(ResponseParser.extractFunctionCode(""));
        assertNull(ResponseParser.extractFunctionCode("   \n  "));
    }

    @Test
    void extractFunctionCode_readsJsonCodeField() {
        String json = "{\"code\": \"public int f() { return 1; }\"}";
        assertEquals("public int f() { return 1; }", ResponseParser.extractFunctionCode(json));
    }

    @Test
    void extractFunctionCode_readsJsonRewrittenCodeField() {
        String json = "{\"rewritten_code\": \"public void g() {}\"}";
        assertEquals("public void g() {}", ResponseParser.extractFunctionCode(json));
    }

    @Test
    void extractFunctionCode_extractsFromFencedCodeBlock() {
        String response =
            "Here is the improved version:\n" +
            "```java\n" +
            "public int add(int a, int b) {\n" +
            "    return a + b;\n" +
            "}\n" +
            "```\n";
        String code = ResponseParser.extractFunctionCode(response);
        assertNotNull(code);
        assertTrue(code.contains("public int add"), "expected the function body, got: " + code);
        assertFalse(code.contains("```"), "fences should be stripped");
    }

    @Test
    void extractFunctionCode_fallsBackToBareFunctionPattern() {
        // No JSON, no fences: the raw text is itself a function.
        String response = "public int q() { return 0; }";
        String code = ResponseParser.extractFunctionCode(response);
        assertNotNull(code);
        assertTrue(code.contains("public int q"));
    }

    @Test
    void extractFunctionCode_returnsNullForProse() {
        assertNull(ResponseParser.extractFunctionCode("This function reads a file and returns its size."));
    }

    // ----- extractExplanation -----

    @Test
    void extractExplanation_readsJsonExplanationField() {
        String json = "{\"explanation\": \"Validates the license key.\"}";
        assertEquals("Validates the license key.", ResponseParser.extractExplanation(json));
    }

    @Test
    void extractExplanation_readsTextBeforeCodeBlock() {
        String response = "This renames the loop counter.\n```java\nint i;\n```";
        assertEquals("This renames the loop counter.", ResponseParser.extractExplanation(response));
    }

    @Test
    void extractExplanation_returnsDefaultWhenNothingUseful() {
        assertEquals("Function rewritten by model analysis",
                ResponseParser.extractExplanation("plain text with no code block"));
    }

    @Test
    void extractExplanation_returnsEmptyForNull() {
        assertEquals("", ResponseParser.extractExplanation(null));
    }

    // ----- isSuccessfulResponse -----

    @Test
    void isSuccessfulResponse_trueForCodeLikeResponse() {
        assertTrue(ResponseParser.isSuccessfulResponse("Here is the rewritten function."));
    }

    @Test
    void isSuccessfulResponse_falseWhenErrorWordPresent() {
        assertFalse(ResponseParser.isSuccessfulResponse("An error occurred while parsing the function."));
        assertFalse(ResponseParser.isSuccessfulResponse("The model was unable to produce code."));
    }

    @Test
    void isSuccessfulResponse_falseForNull() {
        assertFalse(ResponseParser.isSuccessfulResponse(null));
    }
}
