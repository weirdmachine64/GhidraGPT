package ghidragpt.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Utility class for parsing model responses and extracting code
 */
public class ResponseParser {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final Pattern CODE_BLOCK_PATTERN = Pattern.compile(
        "```(?:java|c\\+\\+|c|python)?\\s*\\n(.*?)\\n```",
        Pattern.DOTALL | Pattern.CASE_INSENSITIVE
    );

    private static final Pattern FUNCTION_PATTERN = Pattern.compile(
        "(?:public|private|protected|static|final)?\\s*" +
        "(?:[\\w<>]+\\s+)*" +
        "\\w+\\s*\\([^)]*\\)\\s*\\{[^}]*\\}",
        Pattern.DOTALL
    );

    /**
     * Parses a model response and extracts the rewritten function code
     */
    public static String extractFunctionCode(String response) {
        if (response == null || response.trim().isEmpty()) {
            return null;
        }

        // Try to parse as JSON first
        try {
            JsonNode jsonNode = objectMapper.readTree(response);
            if (jsonNode.has("code")) {
                return jsonNode.get("code").asText();
            }
            if (jsonNode.has("function")) {
                return jsonNode.get("function").asText();
            }
            if (jsonNode.has("rewritten_code")) {
                return jsonNode.get("rewritten_code").asText();
            }
        } catch (Exception e) {
            // Not JSON, continue with text parsing
        }

        // Extract from code blocks
        Matcher codeMatcher = CODE_BLOCK_PATTERN.matcher(response);
        if (codeMatcher.find()) {
            String code = codeMatcher.group(1).trim();
            if (isValidFunctionCode(code)) {
                return code;
            }
        }

        // Look for function-like patterns in the response
        Matcher functionMatcher = FUNCTION_PATTERN.matcher(response);
        if (functionMatcher.find()) {
            return functionMatcher.group().trim();
        }

        // Fallback: return the entire response if it looks like code
        String trimmed = response.trim();
        if (isValidFunctionCode(trimmed)) {
            return trimmed;
        }

        return null;
    }

    /**
     * Validates if the extracted text looks like valid function code
     */
    private static boolean isValidFunctionCode(String code) {
        if (code == null || code.length() < 10) {
            return false;
        }

        // Check for basic function structure
        return code.contains("(") &&
               code.contains(")") &&
               code.contains("{") &&
               code.contains("}") &&
               (code.contains("public") || code.contains("private") ||
                code.contains("protected") || code.contains("static"));
    }

    /**
     * Extracts explanation from model response
     */
    public static String extractExplanation(String response) {
        if (response == null) {
            return "";
        }

        try {
            JsonNode jsonNode = objectMapper.readTree(response);
            if (jsonNode.has("explanation")) {
                return jsonNode.get("explanation").asText();
            }
            if (jsonNode.has("reasoning")) {
                return jsonNode.get("reasoning").asText();
            }
        } catch (Exception e) {
            // Not JSON, extract from text
        }

        // Look for explanation before code blocks
        int codeBlockIndex = response.indexOf("```");
        if (codeBlockIndex > 0) {
            String explanation = response.substring(0, codeBlockIndex).trim();
            if (!explanation.isEmpty()) {
                return explanation;
            }
        }

        return "Function rewritten by model analysis";
    }

    /**
     * Checks if the response indicates success
     */
    public static boolean isSuccessfulResponse(String response) {
        if (response == null) {
            return false;
        }

        String lowerResponse = response.toLowerCase();
        return !lowerResponse.contains("error") &&
               !lowerResponse.contains("failed") &&
               !lowerResponse.contains("unable") &&
               (lowerResponse.contains("function") ||
                lowerResponse.contains("code") ||
                lowerResponse.contains("```"));
    }
}