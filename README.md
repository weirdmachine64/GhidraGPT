# GhidraGPT

<div align="center">
  
![GhidraGPT Logo](assets/logo.png)

**Author**: Mohamed Benchikh

[![GitHub Stars](https://img.shields.io/github/stars/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/network)
[![GitHub Issues](https://img.shields.io/github/issues/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/issues)
[![License](https://img.shields.io/github/license/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/blob/main/LICENSE)

</div>

A powerful Ghidra plugin that integrates Large Language Models (LLMs) directly into Ghidra to enhance reverse engineering workflows with code analysis and enhancement capabilities.

## 🎥 Demo

![Demo](assets/demo.gif)

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
   ./build.sh
   ```

3. **Install in Ghidra**:
   ```bash
   ./install.sh
   ```

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
- **Ollama**: Bring your own model
- **OpenAI Compatible**: Bring your own compatible OpenAI compatible API 

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🔗 Dependencies

- **Ghidra**: Compatible with Ghidra 10.0+
- **Java**: Tested with Java 17
- **Gradle**: Build system (included wrapper)

---

**GhidraGPT** - Enhancing reverse engineering with the power of AI
