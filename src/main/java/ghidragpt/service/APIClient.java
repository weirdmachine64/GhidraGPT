package ghidragpt.service;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import ghidra.util.Msg;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Service class for interacting with various GPT APIs (OpenAI, Anthropic Claude, etc.)
 */
public class APIClient {
    
    private static final String OPENAI_API_URL = "https://api.openai.com/v1/chat/completions";
    private static final String ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
    private static final String GEMINI_API_URL_LEGACY = "https://generativelanguage.googleapis.com/v1beta/models/";
    private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
    private static final String COHERE_API_URL = "https://api.cohere.ai/v1/chat";
    private static final String MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions";
    private static final String DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions";
    private static final String GROK_API_URL = "https://api.x.ai/v1/chat/completions";
    private static final String OLLAMA_API_URL = "http://localhost:11434/api/chat";
    
    // Default configuration constants
    public static final int DEFAULT_TIMEOUT_SECONDS = 30;
    public static final int DEFAULT_MAX_TOKENS = 4000;
    public static final double DEFAULT_TEMPERATURE = 0.1;
    
    private OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private String apiKey;
    private GPTProvider provider = GPTProvider.GROK;
    private String model = "grok-3"; // Default model
    private String customApiUrl = ""; // For OPENAI_COMPATIBLE provider
    
    // Configurable parameters
    private int maxTokens = DEFAULT_MAX_TOKENS;
    private double temperature = DEFAULT_TEMPERATURE;
    private int timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
    
    public enum GPTProvider {
        OPENAI, ANTHROPIC, GEMINI, COHERE, MISTRAL, DEEPSEEK, GROK, OLLAMA, OPENAI_COMPATIBLE
    }
    
    public APIClient() {
        this(DEFAULT_TIMEOUT_SECONDS);
    }
    
    public APIClient(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .build();
        this.objectMapper = new ObjectMapper();
    }
    
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    public void setProvider(GPTProvider provider) {
        this.provider = provider;
    }
    
    public void setModel(String model) {
        this.model = model;
    }
    
    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }
    
    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }
    
    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        // Rebuild HTTP client with new timeout
        rebuildHttpClient();
    }
    
    public void setCustomApiUrl(String customApiUrl) {
        this.customApiUrl = customApiUrl != null ? customApiUrl : "";
    }
    
    private void rebuildHttpClient() {
        // Create new HTTP client with updated timeout
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .build();
    }
    
    // Getter methods for debugging and configuration checking
    public String getApiKey() {
        return apiKey;
    }
    
    public GPTProvider getProvider() {
        return provider;
    }
    
    public String getModel() {
        return model;
    }
    
    public int getMaxTokens() {
        return maxTokens;
    }
    
    public double getTemperature() {
        return temperature;
    }
    
    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }
    
    public String getCustomApiUrl() {
        return customApiUrl;
    }
    
    /**
     * Send a request to the configured GPT API (with streaming enabled by default)
     */
    public String sendRequest(String prompt) throws IOException {
        // Create a default callback that ignores streaming events
        return sendRequest(prompt, new StreamCallback() {
            @Override
            public void onPartialResponse(String partialContent) {
                // Default implementation does nothing
            }
            
            @Override
            public void onComplete(String fullContent) {
                // Default implementation does nothing
            }
            
            @Override
            public void onError(Exception error) {
                // Default implementation does nothing
            }
        });
    }
    
    /**
     * Send a streaming request to the configured GPT API with callback for partial responses
     */
    public String sendRequest(String prompt, StreamCallback callback) throws IOException {
        // Ollama doesn't require API key, all others do
        if (provider != GPTProvider.OLLAMA && (apiKey == null || apiKey.trim().isEmpty())) {
            throw new IllegalStateException("API key not configured");
        }
        
        // OpenAI Compatible requires custom URL
        if (provider == GPTProvider.OPENAI_COMPATIBLE && (customApiUrl == null || customApiUrl.trim().isEmpty())) {
            throw new IllegalStateException("Custom API URL not configured for OpenAI Compatible provider");
        }
        
        // All providers now support native streaming
        switch (provider) {
            case OPENAI:
                return sendOpenAIStreamingRequest(prompt, callback);
            case ANTHROPIC:
                return sendAnthropicStreamingRequest(prompt, callback);
            case GEMINI:
                return sendGeminiStreamingRequest(prompt, callback);
            case COHERE:
                return sendCohereStreamingRequest(prompt, callback);
            case MISTRAL:
                return sendMistralStreamingRequest(prompt, callback);
            case DEEPSEEK:
                return sendDeepSeekStreamingRequest(prompt, callback);
            case GROK:
                return sendGrokStreamingRequest(prompt, callback);
            case OLLAMA:
                return sendOllamaStreamingRequest(prompt, callback);
            case OPENAI_COMPATIBLE:
                return sendOpenAICompatibleStreamingRequest(prompt, callback);
            default:
                throw new IllegalStateException("Unsupported provider: " + provider);
        }
    }
    
    /**
     * Callback interface for streaming responses
     */
    public interface StreamCallback {
        void onPartialResponse(String partialContent);
        void onComplete(String fullContent);
        void onError(Exception error);
    }

    /**
     * Centralized streaming utilities to avoid code duplication
     */
    private static class StreamingUtils {
        
        /**
         * Create a streaming HTTP request with common headers
         */
        public static Request buildStreamingRequest(String url, String jsonBody, String authHeader, String authValue) {
            RequestBody body = RequestBody.create(
                jsonBody, MediaType.get("application/json; charset=utf-8"));
            
            Request.Builder builder = new Request.Builder()
                    .url(url)
                    .header("Content-Type", "application/json")
                    .header("Accept", "text/event-stream")
                    .post(body);
            
            if (authHeader != null && authValue != null && !authValue.trim().isEmpty()) {
                builder.header(authHeader, authValue);
            }
            
            return builder.build();
        }
        
        /**
         * Simulate streaming for providers without native streaming support
         */
        public static void simulateStreaming(String fullResponse, StreamCallback callback) {
            String[] words = fullResponse.split("\\s+");
            StringBuilder currentChunk = new StringBuilder();
            
            try {
                for (int i = 0; i < words.length; i++) {
                    currentChunk.append(words[i]);
                    if (i < words.length - 1) {
                        currentChunk.append(" ");
                    }
                    
                    // Send chunk every few words or at sentence boundaries
                    if (i % 3 == 0 || words[i].endsWith(".") || words[i].endsWith("!") || words[i].endsWith("?")) {
                        callback.onPartialResponse(currentChunk.toString());
                        currentChunk.setLength(0);
                        
                        // Small delay to simulate streaming
                        Thread.sleep(50);
                    }
                }
                
                // Send any remaining content
                if (currentChunk.length() > 0) {
                    callback.onPartialResponse(currentChunk.toString());
                }
                
                callback.onComplete(fullResponse);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                callback.onError(e);
            }
        }
    }
    
    private String sendOpenAIRequest(String prompt) throws IOException {
        OpenAIRequest request = new OpenAIRequest();
        request.model = model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(OPENAI_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("OpenAI API request failed: " + response.code() + " " + response.message() + 
                    "\nResponse body: " + (response.body() != null ? response.body().string() : "empty"));
            }
            
            String responseBody = response.body().string();
            if (responseBody == null || responseBody.trim().isEmpty()) {
                throw new IOException("Empty response body from OpenAI API");
            }
            
            try {
                OpenAIResponse apiResponse = objectMapper.readValue(responseBody, OpenAIResponse.class);
                
                if (apiResponse.choices != null && !apiResponse.choices.isEmpty()) {
                    String content = apiResponse.choices.get(0).message.content;
                    if (content != null && !content.trim().isEmpty()) {
                        return content;
                    } else {
                        throw new IOException("OpenAI API returned empty content. Response: " + responseBody);
                    }
                } else {
                    throw new IOException("OpenAI API returned no choices. Response: " + responseBody);
                }
            } catch (Exception e) {
                throw new IOException("Failed to parse OpenAI API response: " + e.getMessage() + 
                    "\nResponse body: " + responseBody);
            }
        }
    }
    
    private String sendOpenAIStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        OpenAIRequest request = new OpenAIRequest();
        request.model = model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            OPENAI_API_URL, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendAnthropicRequest(String prompt) throws IOException {
        AnthropicRequest request = new AnthropicRequest();
        request.model = model.isEmpty() ? "claude-3-sonnet-20240229" : model;
        request.messages = List.of(new AnthropicMessage("user", prompt));
        request.maxTokens = maxTokens;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(ANTHROPIC_API_URL)
                .header("x-api-key", apiKey)
                .header("Content-Type", "application/json")
                .header("anthropic-version", "2023-06-01")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("API request failed: " + response.code() + " " + response.message());
            }
            
            String responseBody = response.body().string();
            AnthropicResponse apiResponse = objectMapper.readValue(responseBody, AnthropicResponse.class);
            
            if (apiResponse.content != null && !apiResponse.content.isEmpty()) {
                return apiResponse.content.get(0).text;
            }
            
            return "No response generated";
        }
    }
    
    private String sendGeminiRequest(String prompt) throws IOException {
        // Google Gemini API request using OpenAI-compatible endpoint
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "gemini-2.5-flash" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = false;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(GEMINI_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Gemini API request failed: " + response.code() + " " + response.message());
            }
            
            String responseBody = response.body().string();
            OpenAIResponse apiResponse = objectMapper.readValue(responseBody, OpenAIResponse.class);
            
            if (apiResponse.choices != null && !apiResponse.choices.isEmpty() &&
                apiResponse.choices.get(0).message != null &&
                apiResponse.choices.get(0).message.content != null) {
                return apiResponse.choices.get(0).message.content;
            }
            
            return "No response generated";
        }
    }
    
    private String sendCohereRequest(String prompt) throws IOException {
        // Cohere API request
        CohereRequest request = new CohereRequest();
        request.model = model.isEmpty() ? "command" : model;
        request.messages = List.of(new CohereMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(COHERE_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Cohere API request failed: " + response.code() + " " + response.message());
            }
            
            String responseBody = response.body().string();
            CohereResponse apiResponse = objectMapper.readValue(responseBody, CohereResponse.class);
            
            if (apiResponse.text != null && !apiResponse.text.trim().isEmpty()) {
                return apiResponse.text;
            }
            
            return "No response generated";
        }
    }
    
    private String sendMistralRequest(String prompt) throws IOException {
        // Mistral AI API request (OpenAI-compatible format)
        MistralRequest request = new MistralRequest();
        request.model = model.isEmpty() ? "mistral-large-latest" : model;
        request.messages = List.of(new MistralMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(MISTRAL_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Mistral API request failed: " + response.code() + " " + response.message());
            }
            
            String responseBody = response.body().string();
            MistralResponse apiResponse = objectMapper.readValue(responseBody, MistralResponse.class);
            
            if (apiResponse.choices != null && !apiResponse.choices.isEmpty()) {
                return apiResponse.choices.get(0).message.content;
            }
            
            return "No response generated";
        }
    }
    
    private String sendDeepSeekRequest(String prompt) throws IOException {
        // DeepSeek API request (OpenAI-compatible format)
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "deepseek-chat" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = false;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(DEEPSEEK_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("DeepSeek API request failed: " + response.code() + " " + response.message());
            }
            
            String responseBody = response.body().string();
            OpenAIResponse apiResponse = objectMapper.readValue(responseBody, OpenAIResponse.class);
            
            if (apiResponse.choices != null && !apiResponse.choices.isEmpty() &&
                apiResponse.choices.get(0).message != null &&
                apiResponse.choices.get(0).message.content != null) {
                return apiResponse.choices.get(0).message.content;
            }
            
            return "No response generated";
        }
    }
    
    private String sendGrokRequest(String prompt) throws IOException {
        // Grok API request (OpenAI-compatible format)
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "grok-3" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(GROK_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Grok API request failed: " + response.code() + " " + response.message() + 
                    "\nResponse body: " + (response.body() != null ? response.body().string() : "empty"));
            }
            
            String responseBody = response.body().string();
            OpenAIResponse apiResponse = objectMapper.readValue(responseBody, OpenAIResponse.class);
            
            if (apiResponse.choices != null && !apiResponse.choices.isEmpty()) {
                return apiResponse.choices.get(0).message.content;
            }
            
            return "No response generated";
        }
    }
    
    private String sendGrokStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Grok streaming API request (OpenAI-compatible format)
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "grok-beta" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            GROK_API_URL, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendMistralStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Mistral uses OpenAI-compatible streaming format
        MistralRequest request = new MistralRequest();
        request.model = model.isEmpty() ? "mistral-large-latest" : model;
        request.messages = List.of(new MistralMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            MISTRAL_API_URL, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendDeepSeekStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // DeepSeek uses OpenAI-compatible streaming format
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "deepseek-chat" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            DEEPSEEK_API_URL, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendOpenAICompatibleStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // OpenAI Compatible API request - uses custom URL with OpenAI-compatible format
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "gpt-4" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        // Ensure the URL ends with /chat/completions if not already present
        String apiUrl = customApiUrl;
        if (!apiUrl.endsWith("/chat/completions")) {
            if (!apiUrl.endsWith("/")) {
                apiUrl += "/";
            }
            apiUrl += "chat/completions";
        }
        
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            apiUrl, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendOllamaStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Ollama native streaming API request with separate system prompt
        OllamaRequest request = new OllamaRequest();
        request.model = model.isEmpty() ? "llama3.2" : model;
        request.messages = List.of(
            new OllamaMessage("system", "You are a security expert. /no_think"),
            new OllamaMessage("user", prompt)
        );
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(OLLAMA_API_URL)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        
        return processOllamaStream(httpRequest, callback);
    }
    
    private String processOllamaStream(Request httpRequest, StreamCallback callback) throws IOException {
        StringBuilder fullResponse = new StringBuilder();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Ollama streaming request failed: " + response.code() + " " + response.message());
            }
            
            // Ollama sends JSON objects line by line (JSONL format)
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.body().byteStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        try {
                            // Debug: Log the raw line to understand Ollama's response format
                            Msg.info(this, "Ollama response line: " + line);
                            
                            OllamaStreamResponse streamResponse = objectMapper.readValue(line, OllamaStreamResponse.class);
                            if (streamResponse.message != null && streamResponse.message.content != null) {
                                String content = streamResponse.message.content;
                                fullResponse.append(content);
                                Msg.info(this, "Ollama content: '" + content + "'");
                                callback.onPartialResponse(content);
                            }
                            
                            // Check if this is the final message
                            if (streamResponse.done != null && streamResponse.done) {
                                break;
                            }
                        } catch (Exception e) {
                            // Log parsing errors to help debug
                            Msg.error(this, "Error parsing Ollama response: " + e.getMessage() + " | Line: " + line);
                        }
                    }
                }
            }
        } catch (Exception e) {
            callback.onError(e);
            throw e;
        }
        
        String result = fullResponse.toString();
        callback.onComplete(result);
        return result;
    }
    
    private String processAnthropicStream(Request httpRequest, StreamCallback callback) throws IOException {
        StringBuilder fullResponse = new StringBuilder();
        StringBuilder lineBuffer = new StringBuilder();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Anthropic API streaming request failed: " + response.code() + " " + response.message());
            }

            try (java.io.InputStream inputStream = response.body().byteStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    String chunk = new String(buffer, 0, bytesRead, java.nio.charset.StandardCharsets.UTF_8);
                    
                    // Process character by character to handle partial lines
                    for (char c : chunk.toCharArray()) {
                        if (c == '\n') {
                            String line = lineBuffer.toString().trim();
                            lineBuffer.setLength(0); // Clear buffer
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6);
                                if (!data.isEmpty()) {
                                    try {
                                        AnthropicStreamResponse streamResponse = objectMapper.readValue(data, AnthropicStreamResponse.class);
                                        
                                        // Handle content_block_delta events with text_delta
                                        if ("content_block_delta".equals(streamResponse.type) && 
                                            streamResponse.delta != null && 
                                            "text_delta".equals(streamResponse.delta.type) &&
                                            streamResponse.delta.text != null) {
                                            
                                            String content = streamResponse.delta.text;
                                            fullResponse.append(content);
                                            callback.onPartialResponse(content);
                                        }
                                    } catch (Exception e) {
                                        // Skip malformed chunks - don't log to avoid spam
                                    }
                                }
                            }
                        } else {
                            lineBuffer.append(c);
                        }
                    }
                }
            }
        } catch (Exception e) {
            callback.onError(e);
            throw e;
        }
        
        String result = fullResponse.toString();
        callback.onComplete(result);
        return result;
    }

    private String processCohereStream(Request httpRequest, StreamCallback callback) throws IOException {
        StringBuilder fullResponse = new StringBuilder();
        StringBuilder lineBuffer = new StringBuilder();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Cohere streaming request failed: " + response.code() + " " + response.message());
            }
            
            // Use byte-by-byte reading for true streaming performance
            try (java.io.InputStream inputStream = response.body().byteStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    String chunk = new String(buffer, 0, bytesRead, java.nio.charset.StandardCharsets.UTF_8);
                    
                    // Process character by character to handle partial lines
                    for (char c : chunk.toCharArray()) {
                        if (c == '\n') {
                            String line = lineBuffer.toString().trim();
                            lineBuffer.setLength(0); // Clear buffer
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6);
                                if ("[DONE]".equals(data)) {
                                    String result = fullResponse.toString();
                                    callback.onComplete(result);
                                    return result;
                                }
                                
                                try {
                                    CohereStreamResponse streamResponse = objectMapper.readValue(data, CohereStreamResponse.class);
                                    if ("content-delta".equals(streamResponse.type) && 
                                        streamResponse.delta != null && 
                                        streamResponse.delta.message != null && 
                                        streamResponse.delta.message.content != null && 
                                        streamResponse.delta.message.content.text != null) {
                                        String content = streamResponse.delta.message.content.text;
                                        fullResponse.append(content);
                                        callback.onPartialResponse(content);
                                    }
                                } catch (Exception e) {
                                    // Skip malformed chunks - don't log to avoid spam
                                }
                            }
                        } else {
                            lineBuffer.append(c);
                        }
                    }
                }
            }
        } catch (Exception e) {
            callback.onError(e);
            throw e;
        }
        
        String result = fullResponse.toString();
        callback.onComplete(result);
        return result;
    }

    // Helper method for OpenAI-compatible streaming (used by OpenAI, Grok, Mistral, DeepSeek, Gemini)
    private String processOpenAICompatibleStream(Request httpRequest, StreamCallback callback) throws IOException {
        StringBuilder fullResponse = new StringBuilder();
        StringBuilder lineBuffer = new StringBuilder();
        
        try (Response response = httpClient.newCall(httpRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Streaming request failed: " + response.code() + " " + response.message());
            }
            
            // Use byte-by-byte reading for true streaming performance
            try (java.io.InputStream inputStream = response.body().byteStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    String chunk = new String(buffer, 0, bytesRead, java.nio.charset.StandardCharsets.UTF_8);
                    
                    // Process character by character to handle partial lines
                    for (char c : chunk.toCharArray()) {
                        if (c == '\n') {
                            String line = lineBuffer.toString().trim();
                            lineBuffer.setLength(0); // Clear buffer
                            
                            if (line.startsWith("data: ")) {
                                String data = line.substring(6);
                                if ("[DONE]".equals(data)) {
                                    String result = fullResponse.toString();
                                    callback.onComplete(result);
                                    return result;
                                }
                                
                                try {
                                    OpenAIStreamResponse streamResponse = objectMapper.readValue(data, OpenAIStreamResponse.class);
                                    if (streamResponse.choices != null && !streamResponse.choices.isEmpty()) {
                                        String content = streamResponse.choices.get(0).delta.content;
                                        if (content != null) {
                                            fullResponse.append(content);
                                            callback.onPartialResponse(content);
                                        }
                                    }
                                } catch (Exception e) {
                                    // Skip malformed chunks - don't log to avoid spam
                                }
                            }
                        } else {
                            lineBuffer.append(c);
                        }
                    }
                }
            }
        } catch (Exception e) {
            callback.onError(e);
            throw e;
        }
        
        String result = fullResponse.toString();
        callback.onComplete(result);
        return result;
    }
    
    // Add stub methods for providers without streaming support yet
    private String sendAnthropicStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Anthropic native streaming API request
        AnthropicRequest request = new AnthropicRequest();
        request.model = model.isEmpty() ? "claude-3-5-sonnet-20241022" : model;
        request.messages = List.of(new AnthropicMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(ANTHROPIC_API_URL)
                .header("x-api-key", apiKey)
                .header("Content-Type", "application/json")
                .header("anthropic-version", "2023-06-01")
                .header("Accept", "text/event-stream")
                .post(body)
                .build();
        
        return processAnthropicStream(httpRequest, callback);
    }
    
    private String sendGeminiStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Gemini now supports OpenAI-compatible streaming
        OpenAIRequest request = new OpenAIRequest();
        request.model = model.isEmpty() ? "gemini-2.5-flash" : model;
        request.messages = List.of(new OpenAIMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        Request httpRequest = StreamingUtils.buildStreamingRequest(
            GEMINI_API_URL, jsonRequest, "Authorization", "Bearer " + apiKey);
        
        return processOpenAICompatibleStream(httpRequest, callback);
    }
    
    private String sendCohereStreamingRequest(String prompt, StreamCallback callback) throws IOException {
        // Cohere native streaming API request
        CohereRequest request = new CohereRequest();
        request.model = model.isEmpty() ? "command" : model;
        request.messages = List.of(new CohereMessage("user", prompt));
        request.maxTokens = maxTokens;
        request.temperature = temperature;
        request.stream = true;
        
        String jsonRequest = objectMapper.writeValueAsString(request);
        
        RequestBody body = RequestBody.create(
            jsonRequest, MediaType.get("application/json; charset=utf-8"));
        
        Request httpRequest = new Request.Builder()
                .url(COHERE_API_URL)
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
                .post(body)
                .build();
        
        return processCohereStream(httpRequest, callback);
    }
    
    /**
     * Fetches available models from the API provider
     * @return List of model IDs, or empty list if not supported/failed
     */
    public List<String> fetchAvailableModels() {
        try {
            switch (provider) {
                case OPENAI:
                    return fetchOpenAIModels();
                case OLLAMA:
                    return fetchOllamaModels();
                case OPENAI_COMPATIBLE:
                    return fetchOpenAICompatibleModels();
                case MISTRAL:
                    return fetchMistralModels();
                case DEEPSEEK:
                    return fetchDeepSeekModels();
                case GEMINI:
                    return fetchGeminiModels();
                default:
                    // Providers without models API: return empty list
                    return List.of();
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to fetch models: " + e.getMessage());
            return List.of();
        }
    }
    
    private List<String> fetchOpenAIModels() throws IOException {
        Request request = new Request.Builder()
                .url("https://api.openai.com/v1/models")
                .header("Authorization", "Bearer " + apiKey)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch models: " + response.code());
            }
            
            String responseBody = response.body().string();
            ModelsListResponse modelsResponse = objectMapper.readValue(responseBody, ModelsListResponse.class);
            
            return modelsResponse.data.stream()
                    .map(model -> model.id)
                    .filter(id -> id.startsWith("gpt-"))
                    .sorted()
                    .toList();
        }
    }
    
    private List<String> fetchOllamaModels() throws IOException {
        Request request = new Request.Builder()
                .url("http://localhost:11434/api/tags")
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch Ollama models: " + response.code());
            }
            
            String responseBody = response.body().string();
            OllamaModelsResponse modelsResponse = objectMapper.readValue(responseBody, OllamaModelsResponse.class);
            
            return modelsResponse.models.stream()
                    .map(model -> model.name)
                    .sorted()
                    .toList();
        }
    }
    
    private List<String> fetchOpenAICompatibleModels() throws IOException {
        String baseUrl = customApiUrl;
        if (baseUrl.endsWith("/chat/completions")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - "/chat/completions".length());
        }
        if (!baseUrl.endsWith("/")) {
            baseUrl += "/";
        }
        
        Request request = new Request.Builder()
                .url(baseUrl + "models")
                .header("Authorization", "Bearer " + apiKey)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch models: " + response.code());
            }
            
            String responseBody = response.body().string();
            ModelsListResponse modelsResponse = objectMapper.readValue(responseBody, ModelsListResponse.class);
            
            return modelsResponse.data.stream()
                    .map(model -> model.id)
                    .sorted()
                    .toList();
        }
    }
    
    private List<String> fetchMistralModels() throws IOException {
        Request request = new Request.Builder()
                .url("https://api.mistral.ai/v1/models")
                .header("Authorization", "Bearer " + apiKey)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch Mistral models: " + response.code());
            }
            
            String responseBody = response.body().string();
            ModelsListResponse modelsResponse = objectMapper.readValue(responseBody, ModelsListResponse.class);
            
            return modelsResponse.data.stream()
                    .map(model -> model.id)
                    .sorted()
                    .toList();
        }
    }
    
    private List<String> fetchDeepSeekModels() throws IOException {
        Request request = new Request.Builder()
                .url("https://api.deepseek.com/v1/models")
                .header("Authorization", "Bearer " + apiKey)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch DeepSeek models: " + response.code());
            }
            
            String responseBody = response.body().string();
            ModelsListResponse modelsResponse = objectMapper.readValue(responseBody, ModelsListResponse.class);
            
            return modelsResponse.data.stream()
                    .map(model -> model.id)
                    .sorted()
                    .toList();
        }
    }
    
    private List<String> fetchGeminiModels() throws IOException {
        Request request = new Request.Builder()
                .url("https://generativelanguage.googleapis.com/v1beta/models?key=" + apiKey)
                .get()
                .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to fetch Gemini models: " + response.code());
            }
            
            String responseBody = response.body().string();
            GeminiModelsResponse modelsResponse = objectMapper.readValue(responseBody, GeminiModelsResponse.class);
            
            return modelsResponse.models.stream()
                    .map(model -> model.name.replaceFirst("models/", ""))
                    .filter(name -> name.startsWith("gemini-"))
                    .sorted()
                    .toList();
        }
    }
    
    // OpenAI API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIRequest {
        public String model;
        public List<OpenAIMessage> messages;
        @JsonProperty("max_tokens")
        public int maxTokens;
        public double temperature;
        public boolean stream = false;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GrokStreamResponse {
        public List<GrokStreamChoice> choices;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GrokStreamChoice {
        public OpenAIStreamDelta delta;
    }

    // Anthropic Streaming API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicStreamResponse {
        public String type;
        public AnthropicDelta delta;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicDelta {
        public String type;
        public String text;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIMessage {
        public String role;
        public String content;
        
        public OpenAIMessage() {}
        
        public OpenAIMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIResponse {
        public List<OpenAIChoice> choices;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIChoice {
        public OpenAIMessage message;
    }
    
    // Streaming response DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIStreamResponse {
        public List<OpenAIStreamChoice> choices;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIStreamChoice {
        public OpenAIStreamDelta delta;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OpenAIStreamDelta {
        public String content;
    }
    
    // Anthropic API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicRequest {
        public String model;
        public List<AnthropicMessage> messages;
        @JsonProperty("max_tokens")
        public int maxTokens;
        public boolean stream;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicMessage {
        public String role;
        public String content;
        
        public AnthropicMessage() {}
        
        public AnthropicMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicResponse {
        public List<AnthropicContent> content;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AnthropicContent {
        public String text;
    }
    
    // Google Gemini API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiRequest {
        public List<GeminiContent> contents;
        public GeminiGenerationConfig generationConfig;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiContent {
        public List<GeminiPart> parts;
        
        public GeminiContent() {}
        
        public GeminiContent(List<GeminiPart> parts) {
            this.parts = parts;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiPart {
        public String text;
        
        public GeminiPart() {}
        
        public GeminiPart(String text) {
            this.text = text;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiGenerationConfig {
        public int maxOutputTokens;
        public double temperature;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiResponse {
        public List<GeminiCandidate> candidates;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiCandidate {
        public GeminiContent content;
    }
    
    // Cohere API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereRequest {
        public String model;
        public List<CohereMessage> messages;
        @JsonProperty("max_tokens")
        public int maxTokens;
        public double temperature;
        public boolean stream = false;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereMessage {
        public String role;
        public String content;
        
        public CohereMessage() {}
        
        public CohereMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereResponse {
        public String text;
    }
    
    // Cohere Streaming API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereStreamResponse {
        public String type;
        public CohereStreamDelta delta;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereStreamDelta {
        public CohereStreamMessage message;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereStreamMessage {
        public CohereStreamContent content;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CohereStreamContent {
        public String text;
    }
    
    // Mistral AI API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MistralRequest {
        public String model;
        public List<MistralMessage> messages;
        @JsonProperty("max_tokens")
        public int maxTokens;
        public double temperature;
        public boolean stream = false;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MistralMessage {
        public String role;
        public String content;
        
        public MistralMessage() {}
        
        public MistralMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MistralResponse {
        public List<MistralChoice> choices;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MistralChoice {
        public MistralMessage message;
    }
    
    // Ollama API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OllamaRequest {
        public String model;
        public List<OllamaMessage> messages;
        public boolean stream = false;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OllamaMessage {
        public String role;
        public String content;
        
        public OllamaMessage() {}
        
        public OllamaMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OllamaStreamResponse {
        public String model;
        public OllamaMessage message;
        public Boolean done;
    }
    
    // Models List API DTOs
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ModelsListResponse {
        public List<ModelInfo> data;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ModelInfo {
        public String id;
        public String name;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OllamaModelsResponse {
        public List<OllamaModelInfo> models;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OllamaModelInfo {
        public String name;
        public String model;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiModelsResponse {
        public List<GeminiModelInfo> models;
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GeminiModelInfo {
        public String name;
    }
    
}
