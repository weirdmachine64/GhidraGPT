package ghidragpt.ui;

import ghidragpt.service.APIClient;
import ghidragpt.config.ConfigurationManager;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * Configuration panel for API settings
 */
public class ConfigurationPanel extends JPanel {
    
    private final APIClient apiClient;
    private final ConfigurationManager configManager;
    private final JTextField apiKeyField;
    private final JComboBox<APIClient.GPTProvider> providerCombo;
    private final JComboBox<String> modelCombo;
    private final JButton fetchModelsButton;
    private final JTextField customApiUrlField;
    private final JLabel customApiUrlLabel;
    private final JSpinner maxTokensSpinner;
    private final JSpinner temperatureSpinner;
    private final JSpinner timeoutSpinner;
    private final JButton testButton;
    private final JLabel statusLabel;
    
    public ConfigurationPanel(APIClient apiClient) {
        this.apiClient = apiClient;
        this.configManager = new ConfigurationManager();
        
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // API Provider
        gbc.gridx = 0; gbc.gridy = 0;
        add(new JLabel("API Provider:"), gbc);
        
        providerCombo = new JComboBox<>(APIClient.GPTProvider.values());
        providerCombo.addActionListener(e -> updateModelField());
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(providerCombo, gbc);
        
        // API Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("API Key:"), gbc);
        
        apiKeyField = new JPasswordField(30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(apiKeyField, gbc);
        
        // Model
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Model:"), gbc);
        
        // Create a panel to hold model combo and fetch button
        JPanel modelPanel = new JPanel(new BorderLayout(5, 0));
        modelCombo = new JComboBox<>();
        modelCombo.setEditable(true);
        modelCombo.setPreferredSize(new Dimension(200, 25));
        modelPanel.add(modelCombo, BorderLayout.CENTER);
        
        fetchModelsButton = new JButton("Fetch");
        fetchModelsButton.setPreferredSize(new Dimension(70, 25));
        fetchModelsButton.addActionListener(e -> fetchModels());
        modelPanel.add(fetchModelsButton, BorderLayout.EAST);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(modelPanel, gbc);
        
        // Custom API URL (for OpenAI Compatible provider)
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE;
        customApiUrlLabel = new JLabel("Custom API URL:");
        add(customApiUrlLabel, gbc);
        
        customApiUrlField = new JTextField("http://localhost:8000/v1", 30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(customApiUrlField, gbc);
        
        // Hide by default (only show for OPENAI_COMPATIBLE provider)
        customApiUrlLabel.setVisible(false);
        customApiUrlField.setVisible(false);
        
        // Max Tokens
        gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Max Tokens:"), gbc);
        
        maxTokensSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_MAX_TOKENS, 100, 32000, 100));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(maxTokensSpinner, gbc);
        
        // Temperature
        gbc.gridx = 0; gbc.gridy = 5; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Temperature:"), gbc);
        
        temperatureSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_TEMPERATURE, 0.0, 2.0, 0.1));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(temperatureSpinner, gbc);
        
        // Timeout
        gbc.gridx = 0; gbc.gridy = 6; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Timeout (seconds):"), gbc);
        
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(APIClient.DEFAULT_TIMEOUT_SECONDS, 5, 300, 5));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(timeoutSpinner, gbc);
        
        // Create button panel to center buttons horizontally
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        
        testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> testConnection());
        testButton.setPreferredSize(new Dimension(150, 30));
        buttonPanel.add(testButton);
        
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> saveConfiguration());
        saveButton.setPreferredSize(new Dimension(150, 30));
        buttonPanel.add(saveButton);
        
        // Add centered button panel
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(10, 5, 5, 5);
        gbc.weighty = 0.0;
        add(buttonPanel, gbc);
        
        // Status label
        statusLabel = new JLabel("Not configured");
        statusLabel.setForeground(Color.RED);
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(5, 5, 10, 5);
        gbc.weighty = 0.0;
        add(statusLabel, gbc);
        
        // Vertical spacer to push everything to the top when panel height increases
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        gbc.gridx = 0; gbc.gridy = 9; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0; // Take up all extra vertical space
        gbc.weightx = 1.0; // Take up all extra horizontal space
        add(spacer, gbc);
        
        updateModelField();
        
        // Load configuration from file
        loadConfiguration();
    }
    
    /**
     * Loads configuration from the configuration manager and updates UI
     */
    private void loadConfiguration() {
        // Load saved values
        providerCombo.setSelectedItem(configManager.getProvider());
        apiKeyField.setText(configManager.getApiKey());
        modelCombo.setSelectedItem(configManager.getModel());
        customApiUrlField.setText(configManager.getCustomApiUrl());
        maxTokensSpinner.setValue(configManager.getMaxTokens());
        temperatureSpinner.setValue(configManager.getTemperature());
        timeoutSpinner.setValue(configManager.getTimeoutSeconds());
        
        // Update visibility of custom URL field
        APIClient.GPTProvider provider = configManager.getProvider();
        boolean isOpenAICompatible = (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE);
        customApiUrlLabel.setVisible(isOpenAICompatible);
        customApiUrlField.setVisible(isOpenAICompatible);
        
        // Update status
        if (configManager.isConfigured()) {
            statusLabel.setText("Configuration loaded");
            statusLabel.setForeground(Color.BLUE);
            
            // Apply to GPT service
            apiClient.setApiKey(configManager.getApiKey());
            apiClient.setProvider(configManager.getProvider());
            apiClient.setModel(configManager.getModel());
            apiClient.setCustomApiUrl(configManager.getCustomApiUrl());
            apiClient.setMaxTokens(configManager.getMaxTokens());
            apiClient.setTemperature(configManager.getTemperature());
            apiClient.setTimeoutSeconds(configManager.getTimeoutSeconds());
        } else {
            statusLabel.setText("Configuration incomplete");
            statusLabel.setForeground(Color.ORANGE);
        }
    }
    
    private void updateModelField() {
        APIClient.GPTProvider provider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        
        // Reset all configuration fields when provider changes
        resetConfigurationFields();
        
        // Show/hide custom API URL field based on provider
        boolean isOpenAICompatible = (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE);
        customApiUrlLabel.setVisible(isOpenAICompatible);
        customApiUrlField.setVisible(isOpenAICompatible);
        
        // Clear and set placeholder
        modelCombo.removeAllItems();
        modelCombo.addItem("<model>");
        modelCombo.setSelectedItem("<model>");
        
        // Set provider-specific defaults
        if (provider == APIClient.GPTProvider.OLLAMA) {
            apiKeyField.setEnabled(false);  // Ollama doesn't require API key
            apiKeyField.setText("Not required for Ollama (local)");
        } else if (provider == APIClient.GPTProvider.OPENAI_COMPATIBLE) {
            apiKeyField.setEnabled(true);
            if (apiKeyField.getText().equals("Not required for Ollama (local)")) {
                apiKeyField.setText("");
            }
            customApiUrlField.setText("http://localhost:8000/v1");
        } else {
            // For all other providers, enable API key field and clear placeholder
            apiKeyField.setEnabled(true);
            if (apiKeyField.getText().equals("Not required for Ollama (local)")) {
                apiKeyField.setText("");
            }
        }
        
        // Reset status to unconfigured state
        statusLabel.setText("Configuration updated - please test connection");
        statusLabel.setForeground(Color.ORANGE);
    }
    
    private void resetConfigurationFields() {
        // Clear API key field
        apiKeyField.setText("");
        
        // Reset status
        statusLabel.setText("Not configured");
        statusLabel.setForeground(Color.RED);
        
        // Enable API key field by default
        apiKeyField.setEnabled(true);
    }    private void saveConfiguration() {
        String apiKey = apiKeyField.getText().trim();
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // All providers require API key except Ollama
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // OpenAI Compatible requires custom URL
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // For Ollama, clear any placeholder text from API key field
        if (selectedProvider == APIClient.GPTProvider.OLLAMA) {
            apiKey = "";  // Don't save placeholder text
        }
        
        // Save to configuration manager
        configManager.setApiKey(apiKey);
        configManager.setProvider(selectedProvider);
        configManager.setModel(getSelectedModel());
        configManager.setCustomApiUrl(customApiUrl);
        configManager.setMaxTokens((Integer) maxTokensSpinner.getValue());
        configManager.setTemperature((Double) temperatureSpinner.getValue());
        configManager.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        configManager.saveConfiguration();
        
        // Apply to GPT service
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setModel(getSelectedModel());
        apiClient.setCustomApiUrl(customApiUrl);
        apiClient.setMaxTokens((Integer) maxTokensSpinner.getValue());
        apiClient.setTemperature((Double) temperatureSpinner.getValue());
        apiClient.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        
        statusLabel.setText("Configuration saved");
        statusLabel.setForeground(Color.BLUE);
        
        JOptionPane.showMessageDialog(this, 
            "Configuration saved successfully!\nSaved to: " + configManager.getConfigurationPath(), 
            "Success", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void testConnection() {
        // First update the GPTService with current UI values
        String apiKey = apiKeyField.getText().trim();
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String model = getSelectedModel();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // Validate inputs before testing
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (model.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a model name", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Apply current UI values to GPTService for testing
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setModel(model);
        apiClient.setCustomApiUrl(customApiUrl);

        testButton.setEnabled(false);
        testButton.setText("Testing...");
        
        // Test in background thread
        SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return apiClient.sendRequest("Hello, this is a test message. Please respond with 'Connection successful'.");
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    if (response.toLowerCase().contains("successful") || response.toLowerCase().contains("hello")) {
                        statusLabel.setText("Connection successful");
                        statusLabel.setForeground(Color.GREEN);
                        
                        // Show success message and prompt to save
                        int result = JOptionPane.showConfirmDialog(ConfigurationPanel.this, 
                            "Connection test successful!\n\nWould you like to save this configuration?", 
                            "Success", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
                        
                        if (result == JOptionPane.YES_OPTION) {
                            saveConfiguration();
                        }
                    } else {
                        statusLabel.setText("Connection test completed");
                        statusLabel.setForeground(Color.BLUE);
                        JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                            "Connection established but unexpected response:\n" + response, 
                            "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception e) {
                    statusLabel.setText("Connection failed");
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                        "Connection test failed:\n" + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    testButton.setEnabled(true);
                    testButton.setText("Test Connection");
                }
            }
        };
        
        worker.execute();
    }
    
    private void fetchModels() {
        fetchModelsButton.setEnabled(false);
        fetchModelsButton.setText("Fetching...");
        
        // Get current provider settings
        APIClient.GPTProvider selectedProvider = (APIClient.GPTProvider) providerCombo.getSelectedItem();
        String apiKey = apiKeyField.getText().trim();
        String customApiUrl = customApiUrlField.getText().trim();
        
        // Validate inputs before fetching
        if (selectedProvider != APIClient.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key first", "Error", JOptionPane.ERROR_MESSAGE);
            fetchModelsButton.setEnabled(true);
            fetchModelsButton.setText("Fetch");
            return;
        }
        
        if (selectedProvider == APIClient.GPTProvider.OPENAI_COMPATIBLE && customApiUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a custom API URL first", "Error", JOptionPane.ERROR_MESSAGE);
            fetchModelsButton.setEnabled(true);
            fetchModelsButton.setText("Fetch");
            return;
        }
        
        // Apply current settings to GPT service for fetching
        apiClient.setApiKey(apiKey);
        apiClient.setProvider(selectedProvider);
        apiClient.setCustomApiUrl(customApiUrl);
        
        // Fetch in background thread
        SwingWorker<List<String>, Void> worker = new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() throws Exception {
                return apiClient.fetchAvailableModels();
            }
            
            @Override
            protected void done() {
                try {
                    List<String> models = get();
                    if (models.isEmpty()) {
                        JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                            "No models available or provider doesn't support model listing", 
                            "Info", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // Save current selection
                        String currentModel = getSelectedModel();
                        
                        // Update combo box with fetched models
                        modelCombo.removeAllItems();
                        for (String model : models) {
                            modelCombo.addItem(model);
                        }
                        
                        // Try to restore previous selection if it exists in the list
                        if (currentModel != null && !currentModel.isEmpty()) {
                            modelCombo.setSelectedItem(currentModel);
                        } else if (!models.isEmpty()) {
                            modelCombo.setSelectedIndex(0);
                        }
                        
                        statusLabel.setText("Fetched " + models.size() + " models");
                        statusLabel.setForeground(Color.BLUE);
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                        "Failed to fetch models:\n" + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    fetchModelsButton.setEnabled(true);
                    fetchModelsButton.setText("Fetch");
                }
            }
        };
        
        worker.execute();
    }
    
    private String getSelectedModel() {
        Object selected = modelCombo.getSelectedItem();
        return selected != null ? selected.toString().trim() : "";
    }
    
    public boolean isConfigured() {
        return configManager.isConfigured();
    }
    
    /**
     * Returns the configuration manager for external access
     */
    public ConfigurationManager getConfigurationManager() {
        return configManager;
    }
    

}
