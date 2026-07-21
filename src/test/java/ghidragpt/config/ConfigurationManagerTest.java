package ghidragpt.config;

import ghidragpt.service.APIClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ConfigurationManager}.
 *
 * {@code user.home} is redirected to a temporary directory before the class is
 * loaded so the tests never read or write the developer's real
 * {@code ~/.ghidragpt/config.properties}. Tests never call
 * {@code saveConfiguration()}, so no file is written regardless.
 */
class ConfigurationManagerTest {

    private static String originalHome;

    @BeforeAll
    static void redirectHome(@TempDir Path tmpHome) {
        originalHome = System.getProperty("user.home");
        System.setProperty("user.home", tmpHome.toString());
    }

    @AfterAll
    static void restoreHome() {
        if (originalHome != null) {
            System.setProperty("user.home", originalHome);
        }
    }

    @Test
    void apiKeyRoundTripsThroughObfuscation() {
        ConfigurationManager cm = new ConfigurationManager();
        String key = "sk-test-1234567890_ABCdef!@#$%";
        cm.setApiKey(key);
        assertEquals(key, cm.getApiKey(), "obfuscation must be reversible");
    }

    @Test
    void apiKeyRoundTripsUnicode() {
        ConfigurationManager cm = new ConfigurationManager();
        String key = "clé-secrète-日本語-🔑";
        cm.setApiKey(key);
        assertEquals(key, cm.getApiKey());
    }

    @Test
    void storedKeyIsNotPlaintext() {
        ConfigurationManager cm = new ConfigurationManager();
        String key = "supersecretapikey";
        cm.setApiKey(key);
        // The persisted (in-memory) form is XOR+hex, so the raw secret must not appear.
        // We assert via the public marker plus a successful decrypt round-trip.
        assertTrue(cm.isApiKeyEncrypted());
        assertTrue(cm.canDecryptStoredKey());
        assertEquals(key, cm.getApiKey());
    }

    @Test
    void emptyApiKeyReturnsEmpty() {
        ConfigurationManager cm = new ConfigurationManager();
        cm.setApiKey("");
        assertEquals("", cm.getApiKey());
        assertFalse(cm.isApiKeyEncrypted());
    }

    @Test
    void nullApiKeyIsTreatedAsEmpty() {
        ConfigurationManager cm = new ConfigurationManager();
        cm.setApiKey(null);
        assertEquals("", cm.getApiKey());
    }

    @Test
    void providerRoundTrips() {
        ConfigurationManager cm = new ConfigurationManager();
        cm.setProvider(APIClient.GPTProvider.OPENROUTER);
        assertEquals(APIClient.GPTProvider.OPENROUTER, cm.getProvider());
    }

    @Test
    void defaultsAreSaneOnFreshConfig() {
        ConfigurationManager cm = new ConfigurationManager();
        assertEquals(APIClient.GPTProvider.OPENAI, cm.getProvider());
        assertEquals("gpt-4", cm.getModel());
        assertEquals(APIClient.DEFAULT_MAX_TOKENS, cm.getMaxTokens());
        assertEquals(APIClient.DEFAULT_TEMPERATURE, cm.getTemperature(), 1e-9);
        assertEquals(APIClient.DEFAULT_TIMEOUT_SECONDS, cm.getTimeoutSeconds());
    }

    @Test
    void isConfigured_requiresKeyAndModelForKeyedProvider() {
        ConfigurationManager cm = new ConfigurationManager();
        cm.setProvider(APIClient.GPTProvider.OPENROUTER);
        cm.setModel("openrouter/auto");
        cm.setApiKey("");
        assertFalse(cm.isConfigured(), "no key -> not configured");
        cm.setApiKey("sk-or-abc");
        assertTrue(cm.isConfigured());
    }

    @Test
    void isConfigured_ollamaNeedsNoKey() {
        ConfigurationManager cm = new ConfigurationManager();
        cm.setProvider(APIClient.GPTProvider.OLLAMA);
        cm.setModel("llama3.2");
        cm.setApiKey("");
        assertTrue(cm.isConfigured(), "Ollama should be configured with just a model");
    }
}
