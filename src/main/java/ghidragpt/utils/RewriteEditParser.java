package ghidragpt.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Parses a model's rewrite response into a set of edits.
 *
 * <p>The preferred format is <b>JSON Lines</b>: one self-contained JSON edit per
 * line, e.g.
 * <pre>
 * {"op":"func_name","name":"parse_header"}
 * {"op":"rename","old":"iVar1","new":"retry_count"}
 * {"op":"retype","name":"pcVar2","type":"char *"}
 * {"op":"prototype","signature":"int parse_header(char *buf, size_t len)"}
 * {"op":"comment","address":"0x401080","text":"bounds check"}
 * </pre>
 *
 * <p>Parsing each line independently makes the result <b>truncation-resilient</b>:
 * if the response is cut off (e.g. token limit), every complete line is still
 * applied and only the final partial line is lost — instead of the whole
 * response being discarded.
 *
 * <p>For backward compatibility, if no JSONL edits are found the parser falls
 * back to the older single JSON object format
 * ({@code {"function_name":..., "variable_renames":{...}, ...}}).
 *
 * <p>This class is deliberately free of any Ghidra dependency so it can be unit
 * tested in isolation.
 */
public final class RewriteEditParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private RewriteEditParser() {
    }

    /** Aggregated edits parsed from a model response. Insertion order is preserved. */
    public static final class RewriteEdits {
        public String functionName;
        public String functionPrototype;
        public final Map<String, String> variableRenames = new LinkedHashMap<>();
        public final Map<String, String> variableTypes = new LinkedHashMap<>();
        public final Map<String, String> comments = new LinkedHashMap<>();

        public boolean isEmpty() {
            return functionName == null
                && functionPrototype == null
                && variableRenames.isEmpty()
                && variableTypes.isEmpty()
                && comments.isEmpty();
        }
    }

    public static RewriteEdits parse(String response) {
        RewriteEdits edits = new RewriteEdits();
        if (response == null || response.isEmpty()) {
            return edits;
        }

        // Primary path: JSON Lines. Parse each line on its own so a malformed or
        // truncated final line never discards the edits that preceded it.
        for (String rawLine : response.split("\\r?\\n")) {
            String line = rawLine.trim();
            int brace = line.indexOf('{');
            if (brace < 0) {
                continue; // prose, markdown fences, blank lines, etc.
            }
            if (brace > 0) {
                line = line.substring(brace); // tolerate a leading "- " or similar
            }
            JsonNode node;
            try {
                node = MAPPER.readTree(line);
            } catch (Exception e) {
                continue; // skip malformed / truncated line
            }
            if (node == null || !node.isObject() || !node.hasNonNull("op")) {
                continue;
            }
            applyEdit(node, edits);
        }

        if (!edits.isEmpty()) {
            return edits;
        }

        // Fallback: single JSON object (the older response format).
        return parseBlob(response, edits);
    }

    private static void applyEdit(JsonNode node, RewriteEdits edits) {
        String op = text(node, "op");
        if (op == null) {
            return;
        }
        switch (op) {
            case "func_name": {
                String name = text(node, "name");
                if (name != null && !name.isEmpty()) {
                    edits.functionName = name;
                }
                break;
            }
            case "rename": {
                String from = text(node, "old");
                String to = text(node, "new");
                if (from != null && to != null && !from.isEmpty() && !to.isEmpty()) {
                    edits.variableRenames.put(from, to);
                }
                break;
            }
            case "retype": {
                String name = text(node, "name");
                String type = text(node, "type");
                if (name != null && type != null && !name.isEmpty() && !type.isEmpty()) {
                    edits.variableTypes.put(name, type);
                }
                break;
            }
            case "prototype": {
                String sig = text(node, "signature");
                if (sig != null && !sig.trim().isEmpty()) {
                    edits.functionPrototype = sig;
                }
                break;
            }
            case "comment": {
                String address = text(node, "address");
                String content = text(node, "text");
                if (address != null && content != null && !address.isEmpty() && !content.isEmpty()) {
                    edits.comments.put(address, content);
                }
                break;
            }
            default:
                // Unknown op: ignore rather than fail the whole stream.
                break;
        }
    }

    private static RewriteEdits parseBlob(String response, RewriteEdits edits) {
        int start = response.indexOf('{');
        int end = response.lastIndexOf('}');
        if (start < 0 || end <= start) {
            return edits;
        }
        try {
            JsonNode root = MAPPER.readTree(response.substring(start, end + 1));
            if (root == null || !root.isObject()) {
                return edits;
            }
            if (root.hasNonNull("function_name")) {
                edits.functionName = root.get("function_name").asText();
            }
            if (root.hasNonNull("function_prototype")) {
                edits.functionPrototype = root.get("function_prototype").asText();
            }
            copyObject(root.get("variable_renames"), edits.variableRenames);
            copyObject(root.get("variable_types"), edits.variableTypes);
            copyObject(root.get("comments"), edits.comments);
        } catch (Exception e) {
            // Give up quietly; caller treats an empty result as "no changes".
        }
        return edits;
    }

    private static void copyObject(JsonNode node, Map<String, String> target) {
        if (node == null || !node.isObject()) {
            return;
        }
        node.fields().forEachRemaining(f -> target.put(f.getKey(), f.getValue().asText()));
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }
}
