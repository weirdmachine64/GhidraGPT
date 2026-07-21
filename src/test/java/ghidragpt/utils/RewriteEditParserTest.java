package ghidragpt.utils;

import ghidragpt.utils.RewriteEditParser.RewriteEdits;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RewriteEditParserTest {

    @Test
    void parsesJsonLinesEdits() {
        String resp = String.join("\n",
            "{\"op\":\"func_name\",\"name\":\"parse_header\"}",
            "{\"op\":\"rename\",\"old\":\"iVar1\",\"new\":\"retry_count\"}",
            "{\"op\":\"retype\",\"name\":\"pcVar2\",\"type\":\"char *\"}",
            "{\"op\":\"prototype\",\"signature\":\"int parse_header(char *buf)\"}",
            "{\"op\":\"comment\",\"address\":\"0x401080\",\"text\":\"bounds check\"}");
        RewriteEdits e = RewriteEditParser.parse(resp);

        assertEquals("parse_header", e.functionName);
        assertEquals("retry_count", e.variableRenames.get("iVar1"));
        assertEquals("char *", e.variableTypes.get("pcVar2"));
        assertEquals("int parse_header(char *buf)", e.functionPrototype);
        assertEquals("bounds check", e.comments.get("0x401080"));
    }

    @Test
    void truncatedFinalLineDoesNotDiscardEarlierEdits() {
        // Simulate a response cut off mid-way through the last line (token limit).
        String resp = String.join("\n",
            "{\"op\":\"func_name\",\"name\":\"decrypt_blob\"}",
            "{\"op\":\"rename\",\"old\":\"uVar1\",\"new\":\"key_len\"}",
            "{\"op\":\"rename\",\"old\":\"pcVar3\",\"new\":\"cipher"); // <- truncated, no closing
        RewriteEdits e = RewriteEditParser.parse(resp);

        assertEquals("decrypt_blob", e.functionName);
        assertEquals("key_len", e.variableRenames.get("uVar1"));
        // the incomplete final edit is dropped, not fatal
        assertFalse(e.variableRenames.containsKey("pcVar3"));
        assertEquals(1, e.variableRenames.size());
    }

    @Test
    void ignoresProseFencesAndBlankLines() {
        String resp = String.join("\n",
            "Here are the edits:",
            "```jsonl",
            "",
            "{\"op\":\"rename\",\"old\":\"iVar1\",\"new\":\"count\"}",
            "```",
            "Done.");
        RewriteEdits e = RewriteEditParser.parse(resp);
        assertEquals("count", e.variableRenames.get("iVar1"));
        assertEquals(1, e.variableRenames.size());
    }

    @Test
    void unknownOpsAndMissingFieldsAreSkipped() {
        String resp = String.join("\n",
            "{\"op\":\"delete_everything\",\"name\":\"x\"}",   // unknown op
            "{\"op\":\"rename\",\"old\":\"iVar1\"}",             // missing "new"
            "{\"op\":\"rename\",\"old\":\"iVar2\",\"new\":\"ok\"}");
        RewriteEdits e = RewriteEditParser.parse(resp);
        assertEquals(1, e.variableRenames.size());
        assertEquals("ok", e.variableRenames.get("iVar2"));
    }

    @Test
    void fallsBackToLegacyBlobFormat() {
        String resp =
            "Sure!\n{\n" +
            "  \"function_name\": \"init_state\",\n" +
            "  \"variable_renames\": { \"local_10\": \"buffer\" },\n" +
            "  \"variable_types\": { \"buffer\": \"char *\" },\n" +
            "  \"comments\": { \"0x1000\": \"entry\" }\n" +
            "}\nHope this helps.";
        RewriteEdits e = RewriteEditParser.parse(resp);
        assertEquals("init_state", e.functionName);
        assertEquals("buffer", e.variableRenames.get("local_10"));
        assertEquals("char *", e.variableTypes.get("buffer"));
        assertEquals("entry", e.comments.get("0x1000"));
    }

    @Test
    void emptyAndNullYieldNoEdits() {
        assertTrue(RewriteEditParser.parse(null).isEmpty());
        assertTrue(RewriteEditParser.parse("").isEmpty());
        assertTrue(RewriteEditParser.parse("no json here at all").isEmpty());
    }
}
