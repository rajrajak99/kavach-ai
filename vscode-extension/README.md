# 🛡️ Kavach AI — Official VS Code Extension

> **Sub-16ms In-Editor AST Security Gate, Vulnerability Highlighter & 1-Click Surgical Patcher**

The **Kavach AI VS Code Extension** brings autonomous pre-merge code auditing and instant self-healing directly into your editor. Catch CWE vulnerabilities, credential leaks, and fatal crashes **before you commit or open a PR**.

---

## ⚡ Core Capabilities

1. **Inline Zero-Noise Diagnostics:**  
   Underlines critical security hazards with discrete red/amber squigglies and exact CWE identifiers (CWE-89 SQLi, CWE-798 Secrets, CWE-78 Command Injections, CWE-120 Buffer Overflows).
2. **1-Click Quick-Fix (`Cmd+.` / `Ctrl+.`):**  
   Click the yellow lightbulb 💡 or press `Ctrl+.` on any vulnerable line to view and apply the compile-ready surgical replacement instantly.
3. **Multi-Language Support:**  
   Supports Python, JavaScript, TypeScript, C, and C++ with sub-16ms AST precision and zero false alarms.
4. **Autonomous Self-Heal Command:**  
   Right-click in the editor or open the Command Palette (`Ctrl+Shift+P`) and run:  
   `Kavach AI: Self-Heal File` to resolve all detected issues in 1 click!

---

## 🛠️ How to Test & Install Locally

### Option A: Run directly in VS Code (Development Mode)
1. Open this `vscode-extension` directory in VS Code.
2. Press **`F5`** (or select **Run > Start Debugging**).
3. A new **Extension Development Host** window will open with Kavach AI active!
4. Open any Python, JavaScript, or C++ file to see real-time security warnings and quick-fixes.

### Option B: Package into `.vsix` for 1-Click Installation
1. Install the official VS Code packaging tool:
   ```bash
   npm install -g @vscode/vsce
   ```
2. Build the package:
   ```bash
   vsce package
   ```
3. Install into your local VS Code:
   ```bash
   code --install-extension kavach-ai-1.0.0.vsix
   ```
