# 🛡️ Kavach AI (कवच)

> **Autonomous High-Precision Code Armor & 1-Click Surgical Patcher**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Security Policy: OWASP 2026](https://img.shields.io/badge/Security-OWASP%202026-green.svg)](https://owasp.org)
[![Engine: Zero--Noise](https://img.shields.io/badge/Engine-Zero--Noise%20Surgical-orange.svg)]()
[![GitHub Actions: Ready](https://img.shields.io/badge/CI%2FCD-GitHub%20Action-purple.svg)](action.yml)

Kavach AI (कवच) is an autonomous, high-speed static security inspector and surgical code repair engine. Operating like an impenetrable armor across your **GitHub Pull Requests (CI/CD)**, local CLI, VS Code editor, and Web Console, it eliminates critical security hazards (CWE-89 SQLi, CWE-798 Secret Leaks, CWE-120 Buffer Overflows) and generates **1-click ready-to-merge patches** with zero-regression self-healing verification.

---

## ⚡ Core Philosophy: Zero-Noise Precision

Most static code scanners overwhelm developers with hundreds of stylistic warnings (missing docstrings, trailing whitespace). Developers end up ignoring them.

AutoPatch operates on a **strict zero-noise policy**:
1. **Ignores Noise:** Lockfiles (`package-lock.json`, `poetry.lock`), minified bundles, images, and formatting diffs are discarded automatically.
2. **Flags Real Hazards Only:**
   - 🛡️ **Hardcoded Credentials & Tokens (CWE-798):** AWS keys, GitHub PATs, OpenAI/Stripe secret keys in Python and JavaScript.
   - 🛡️ **Raw SQL Injections (CWE-89):** Raw string interpolation inside queries.
   - 🛡️ **Arbitrary OS Command Injection (CWE-78):** Untrusted shell inputs via `os.system` / `child_process.exec`.
   - 🔴 **Fatal Runtime Exceptions (CWE-369, CWE-95):** ZeroDivisionError crashes, dynamic `eval()` execution.
   - ⚡ **Resource Descriptors Leaks (CWE-775):** Unmanaged `open()` handles missing `with` context managers.
3. **Generates Instant Patches:** AutoPatch outputs native GitHub markdown ` ```suggestion ` blocks that team leads can merge in 1 click right inside the GitHub UI.

---

## 🤖 GitHub Action Setup (Automated PR Reviews)

Add AutoPatch to any GitHub repository in **30 seconds** by creating `.github/workflows/autopatch.yml`:

```yaml
name: AutoPatch Security Review

on:
  pull_request:
    branches: [ main, master, dev ]
  push:
    branches: [ main, master ]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  autopatch-ci:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: AutoPatch PR Reviewer
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python ci_bot.py --fail-on CRITICAL
```

### What Happens When a PR is Opened:
1. **Inspects Changeset in < 0.05s** without external network latency.
2. **Posts an Official PR Review Comment** with exact line numbers and 1-click GitHub commit suggestions.
3. **Populates the GitHub Step Summary** with executive metrics and CWE classifications.
4. **Fails the CI status check** to block merging if Critical vulnerabilities are detected.

---

## 🏗️ System Architecture

```
                  ┌───────────────────────────────┐
                  │   Incoming Git Pull Request   │
                  │   (git diff main...feature)   │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │    DiffParser (Zero-Noise)    │
                  │   - Filters lockfiles/assets  │
                  │   - Extracts modified hunks   │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │       Surgical Analyzer       │
                  │   - Python & JS/TS Parsers    │
                  │   - CWE-798 Credential Leaks  │
                  │   - CWE-89 SQL Injections     │
                  │   - CWE-78 Command Injections │
                  │   - CWE-775 Descriptor Leaks  │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │     1-Click Patch Engine      │
                  │   - GitHub suggestion blocks  │
                  │   - PR Commenter Bot (CI/CD)  │
                  │   - Standalone .patch export  │
                  └───────────────────────────────┘
```

---

## 🚀 Quickstart & Usage

### 1. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/rajrajak99/autopatch-ai.git
cd autopatch-ai
pip install -r requirements.txt
```

### 2. Standalone Terminal CLI (Scan 10,000+ Files Locally)
```bash
# Scan a directory and generate unified .patch
python cli.py ./my-project --patch autopatch.patch

# Apply patch directly via git
git apply autopatch.patch
```

### 3. Launch Local Review Workstation (Raycast / Linear Dark UI)
```bash
streamlit run app.py
```
Open `http://localhost:8502` in your browser.

### 4. Run Automated Unit Tests
```bash
pytest -o pythonpath=. tests/
```

---

## 📂 Project Structure

```
autopatch-ai/
├── action.yml                  # GitHub Action specification (Composite)
├── ci_bot.py                   # Automated CI/CD PR Reviewer & Commenter
├── cli.py                      # Standalone high-speed Terminal CLI scanner
├── app.py                      # Luxury Raycast/Linear Dark review workstation
├── core/
│   ├── __init__.py
│   ├── diff_parser.py          # Unified Git diff & hunk pre-filtering
│   ├── surgical_analyzer.py    # Zero-noise CWE & bug detection engine
│   └── patch_validator.py      # Syntax and indentation patch validator
├── samples/
│   ├── __init__.py
│   └── vulnerable_samples.py   # Multi-language test scenarios (Python + Node.js)
├── tests/
│   ├── __init__.py
│   └── test_autopatch.py       # Comprehensive pytest test suite (4/4 passing)
├── .github/
│   └── workflows/
│       └── autopatch.yml       # Production CI workflow configuration
├── .streamlit/
│   └── config.toml             # Raycast/Linear Obsidian theme configuration
├── requirements.txt            # Minimal production dependencies
├── LICENSE                     # MIT License
└── README.md                   # Technical documentation
```

---

## 🛡️ Supported CWE Vulnerability Matrix

| CWE ID | Vulnerability Class | Language | Severity | AutoPatch Remediation |
|---|---|---|---|---|
| **CWE-798** | Hardcoded Credentials & Tokens | Python / JS | Critical | Moves secrets to environment variables |
| **CWE-89** | SQL Injection (Raw formatting) | Python / JS | Critical | Converts to parameterized queries |
| **CWE-78** | OS Command Injection | Python / JS | High | Converts string interpolation to discrete arrays |
| **CWE-95** | Arbitrary Code Execution (`eval`) | JavaScript | Critical | Replaces with strict JSON parser |
| **CWE-775** | Unmanaged Resource Descriptor | Python | Medium | Enforces `with open(...)` context manager |
| **CWE-369** | Unchecked Zero Division | Python | High | Inserts defensive conditional guard |

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

Developed by **[rajrajak99](https://github.com/rajrajak99)**.
