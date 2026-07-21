# GhidraGPT

<div align="center">
  
![GhidraGPT Logo](https://github.com/user-attachments/assets/9adcbb5f-2b5d-4bac-a60a-ffca9c5e9592)

**Author**: Mohamed Benchikh

[![GitHub Stars](https://img.shields.io/github/stars/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/ZeroDaysBroker/GhidraGPT?style=social)](https://github.com/ZeroDaysBroker/GhidraGPT/network)
[![GitHub Issues](https://img.shields.io/github/issues/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/issues)
[![License](https://img.shields.io/github/license/ZeroDaysBroker/GhidraGPT)](https://github.com/ZeroDaysBroker/GhidraGPT/blob/main/LICENSE)

</div>

GhidraGPT is a Ghidra extension that brings large language models into the decompiler workflow. You right-click a function; the plugin sends that function's decompiled C to an LLM provider of your choice and streams the response back into a dedicated console. Depending on the action, it explains the function, recovers meaningful names/types/comments and writes them back into the program, or reviews the code for likely security issues.

All actions operate on a **single function at a time**, using its current decompiler output as the only context; there is no interprocedural or whole-program analysis.

## 🎥 Demo

![Demo](https://github.com/user-attachments/assets/9ba9a950-ea9e-4dfa-8648-2f241850769d)

## 🚀 Features

### Actions (right-click a function ▸ GhidraGPT)

- **Explain**: generates a natural-language summary of what the selected function does, derived from its decompiled code.
- **Rewrite**: recovers a descriptive function name, renames local variables and parameters, infers their types, updates the function prototype, and adds inline comments, then applies that markup back into the Ghidra database.
- **Audit**: reviews the selected function's decompiled code for likely security issues (e.g. unbounded copies, integer overflows, unchecked returns). This is a best-effort, single-function review by the model, not sound static analysis: it has no cross-function dataflow or call-graph context, so treat findings as leads to verify, not proof.

### Integration

- **Decompiler & Listing integration**: actions are available from the right-click `GhidraGPT` submenu in both the Decompiler and Listing views.
- **Streaming console**: responses stream token-by-token into a dedicated GhidraGPT console panel.
- **Pluggable providers**: switch provider and model from the configuration panel; for most providers the available models can be fetched live.
- **Configurable requests**: model, temperature, max tokens, and request timeout are all adjustable.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ZeroDaysBroker/GhidraGPT.git
   cd GhidraGPT
   ```

2. **Build the extension**:
   ```bash
   GHIDRA_INSTALL_DIR=/path/to/ghidra mvn clean package
   ```
   The packaged extension is written to `target/GhidraGPT-<version>.zip`.

3. **Install in Ghidra**:
   - `File → Install Extensions`
   - Click `+`, select `target/GhidraGPT-<version>.zip`, and restart Ghidra.
   - Enable the plugin when prompted, or via `File → Configure → GhidraGPT → GhidraGPTPlugin`.

4. **Configure a provider**:
   - Open the GhidraGPT configuration panel, pick a provider and model, and enter an API key (not required for Ollama).
   - **Note on key storage**: the key is saved locally in `~/.ghidragpt/config.properties`, lightly obfuscated with XOR, which is *not* encryption and should not be treated as secure at-rest storage. Prefer a scoped, rotatable key and protect the file accordingly.

## 📋 Supported providers

| Provider | Notes |
| --- | --- |
| OpenAI | GPT models |
| Anthropic | Claude models |
| Google Gemini | Gemini models (OpenAI-compatible endpoint) |
| Cohere | Command models |
| Mistral AI | Mistral models |
| DeepSeek | DeepSeek models |
| Grok (xAI) | Grok models |
| OpenRouter | Single key, routed access to many providers' models |
| Ollama | Local models; no API key required |
| OpenAI-compatible | Any endpoint implementing the OpenAI chat-completions API (custom base URL) |

## 🤝 Contributing

Issues, feature requests, and pull requests are welcome.

## 📄 License

Licensed under the terms in the [LICENSE](LICENSE) file.

## 🔗 Requirements

- **Ghidra**: 12.1.x (the extension declares compatibility with the Ghidra version it is built against)
- **JDK**: 21+ (required to run Ghidra 12.x)
- **Maven**: build system
- **Network access** to the configured provider's API (except Ollama, which runs locally)

---

**GhidraGPT**: LLM-assisted reverse engineering, inside Ghidra.
