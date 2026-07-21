# GhidraGPT

<div align="center">
  
![GhidraGPT Logo](https://github.com/user-attachments/assets/9adcbb5f-2b5d-4bac-a60a-ffca9c5e9592)

**Author**: Mohamed Benchikh

[![GitHub Stars](https://img.shields.io/github/stars/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/network)
[![GitHub Issues](https://img.shields.io/github/issues/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/issues)
[![License](https://img.shields.io/github/license/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/blob/main/LICENSE)

</div>

A powerful Ghidra plugin that integrates Large Language Models (LLMs) directly into Ghidra to enhance reverse engineering workflows with code analysis and enhancement capabilities.

## 🎥 Demo

![Demo](https://github.com/user-attachments/assets/9ba9a950-ea9e-4dfa-8648-2f241850769d)

## 🚀 Features

### Core Functionality
- **Function Rewrite**: Improve code readability through function renaming, variable renaming, type inference, function prototype updating, and adding contextual comments to make decompiled code more human-readable
- **Code Explanation**: Detailed explanations of function logic and behavior
- **Code Analysis**: Vulnerability detection and security analysis

### Integration Features
- **Context Menu Integration**: Right-click functions for instant model analysis
- **Console Interface**: Dedicated console for viewing model responses and results
- **Flexible Configuration**: Easy setup through configuration panel
- **Stream Processing**: Real-time model response streaming for better user experience

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ZeroDaysBroker/GhidraGPT.git
   cd GhidraGPT
   ```

2. **Build the Plugin**:
   ```bash
   GHIDRA_INSTALL_DIR=/path/to/ghidra mvn clean package
   ```
   The built extension will be at `target/GhidraGPT-x.y.z.zip`

3. **Install in Ghidra**:
   - Open Ghidra
   - Go to `File → Install Extensions`
   - Click the `+` button and select `target/GhidraGPT-x.y.z.zip`
   - Restart Ghidra
   - Enable the plugin via `File → Configure → Analysis → GhidraGPTPlugin`

4. **Configure API Keys**:
   - Open Ghidra and navigate to the GhidraGPT configuration panel
   - Enter your preferred model service API key
   - API keys are automatically encrypted and stored securely

## 📋 Supported AI Providers
- **OpenAI**: GPT models
- **Anthropic**: Claude models
- **Google Gemini**: Gemini models
- **Cohere**: Command models
- **Mistral AI**: Mistral models
- **DeepSeek**: DeepSeek models
- **Grok (xAI)**: Grok models
- **OpenRouter**: Unified access to models from many providers with a single key
- **Ollama**: Bring your own model
- **OpenAI Compatible**: Bring your own compatible OpenAI compatible API 

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🔗 Dependencies

- **Ghidra**: Compatible with Ghidra 10.0+
- **Java**: Java 11+
- **Maven**: Build system

---

**GhidraGPT** - Enhancing reverse engineering with the power of AI
