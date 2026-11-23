# Contributing to Kavach AI 🛡️

Thank you for your interest in contributing to **Kavach AI**! We are building the world's fastest, zero-noise autonomous code security gate and 1-click self-healing engine.

## Code of Conduct
We are committed to providing a welcoming, productive, and harassment-free experience for everyone. Be respectful, constructive, and open-minded in code reviews and discussions.

---

## Quick Development Setup

1. **Fork and Clone the Repository:**
   ```bash
   git clone https://github.com/rajrajak99/kavach-ai.git
   cd kavach-ai
   ```

2. **Create a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   pip install -r requirements.txt
   pip install pytest pytest-cov
   ```

3. **Run the Full Test Suite:**
   ```bash
   pytest -o pythonpath=. tests/
   ```
   *All 128 tests must pass before opening a PR.*

---

## How to Add a New AST Security Rule in 5 Minutes

Kavach AI uses deterministic Python Abstract Syntax Tree (AST) pattern matching with 0% false positives.

To add a new rule:
1. Open `core/surgical_analyzer.py`.
2. Locate the `_analyze_python_ast` method.
3. Add a dedicated AST visitor or node check (e.g. detecting insecure yaml deserialization `yaml.load(..., Loader=yaml.Loader)`):
   ```python
   # Example: Detecting Insecure YAML Deserialization (CWE-502)
   if isinstance(node, ast.Call):
       if getattr(node.func, 'attr', '') == 'load':
           # Flag CWE-502 and construct surgical suggestion
   ```
4. Define the 1-click surgical replacement (e.g., `yaml.safe_load(...)`).
5. Add a test scenario in `tests/test_autopatch.py` confirming both detection and clean patch generation.
6. Verify with `pytest`.

---

## Submitting Pull Requests

1. Create a feature branch: `git checkout -b feat/cwe-502-yaml-deserialization`.
2. Commit your changes with conventional commit messages: `feat: add CWE-502 AST detector and safe_load patch`.
3. Push to your branch and open a PR on GitHub.
4. Kavach AI's automated CI bot will review your PR and verify zero regressions!
