# GhidraGPT

<div align="center">
  
![GhidraGPT Logo](assets/logo.png)

**Author**: Mohamed Benchikh

[![GitHub Stars](https://img.shields.io/github/stars/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/network)
[![GitHub Issues](https://img.shields.io/github/issues/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/issues)
[![License](https://img.shields.io/github/license/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/blob/main/LICENSE)

</div>

A powerful Ghidra plugin that integrates Large Language Models (LLMs) to enhance reverse engineering workflows with model-powered code analysis and enhancement capabilities.

## 🎥 Demo

![Demo](assets/demo.gif)


## ⚡ Real-Time Performance

For optimal real-time performance, it is recommended to use smaller and faster models such as **grok-3** or **deepseek-chat**. These models deliver quicker responses, making them ideal for interactive and latency-sensitive reverse engineering workflows. Using larger reasoning models may result in slower response times.

## 🚀 Features

### Core Functionality
- **Function Rewrite**: Model-powered function and variable renaming for improved code readability
- **Code Explanation**: Detailed explanations of function logic and behavior
- **Code Analysis**: Vulnerability detection and security analysis
- **Multi-LLM Support**: Compatible with 8+ AI providers including OpenAI, Anthropic, Google Gemini, Cohere, Mistral AI, DeepSeek, Grok (xAI), and Ollama

### Configuration
- **Flexible Configuration**: Easy setup through configuration panel
- **Stream Processing**: Real-time model response streaming for better user experience

### Integration Features
- **Context Menu Integration**: Right-click functions for instant model analysis
- **Console Interface**: Dedicated console for viewing model responses and results
- **Automatic Analysis**: Integration with Ghidra's analysis pipeline
- **Theme Support**: Custom theming for enhanced UI experience

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

## 📋 Usage

### Available Actions
Access these features through the right-click context menu on any function:

- **GhidraGPT → Rewrite Function**: Improve function and variable names using AI analysis
- **GhidraGPT → Explain Code**: Get detailed explanations of function behavior
- **GhidraGPT → Analyze Code**: Detect potential security vulnerabilities

### Supported AI Providers
- **OpenAI**: GPT models
- **Anthropic**: Claude models
- **Google Gemini**: Gemini models
- **Cohere**: Command models
- **Mistral AI**: Mistral models
- **DeepSeek**: DeepSeek models
- **Grok (xAI)**: Grok models
- **Ollama**: Local models - No API key required

## 🏗️ Architecture

### Service Layer
- **`CodeEnhancementService`**: Handles AI-powered function and variable renaming
- **`CodeAnalysisService`**: Manages comprehensive code analysis and vulnerability detection
- **`GPTService`**: Core AI communication layer with multi-provider support
- **`ConfigurationManager`**: Configuration and API key management

### UI Components
- **`GhidraGPTProvider`**: Main plugin provider with context menu integration
- **`GhidraGPTConsole`**: Dedicated console for AI responses
- **`ConfigurationPanel`**: User-friendly configuration interface

## ⚠️ Pending Work

### Code Retyping & Analysis Enhancement
- **Variable retyping**: Implement automated variable retyping
- **Cross-Reference Analysis**: Improve analysis of function calls and data flow

### Performance Optimizations
- **Batch Processing**: Implement batch analysis for multiple functions
- **Caching System**: Add intelligent caching for AI responses

### Additional Features
- **Custom Prompts**: Allow users to define custom AI prompts for specific analysis needs
- **Export Functionality**: Add ability to export analysis results

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

**Repository**: [https://github.com/ZeroDaysBroker/GhidraGPT](https://github.com/ZeroDaysBroker/GhidraGPT)

- 🐛 **Report Issues**: [Submit bug reports and feature requests](https://github.com/ZeroDaysBroker/GhidraGPT/issues)
- 🔧 **Pull Requests**: [Contribute code improvements](https://github.com/ZeroDaysBroker/GhidraGPT/pulls)
- 📖 **Documentation**: Help improve documentation and examples
- 🧪 **Testing**: Test with different AI providers and report compatibility

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🔗 Dependencies

- **Ghidra**: Compatible with Ghidra 10.0+
- **Java**: Tested with Java 17
- **Gradle**: Build system (included wrapper)

## 📝 Notes

- Ensure you have valid API keys for your chosen AI provider
- The plugin requires an active internet connection for AI API calls (except for Ollama)
- Analysis results may vary depending on the complexity of the code and chosen AI model

---

**GhidraGPT** - Enhancing reverse engineering with the power of AI
