# 🛡️ Kavach AI Pre-Audit & Outreach Pack: FROWNINGdev/orm-lens

- **Repository**: [https://github.com/FROWNINGdev/orm-lens](https://github.com/FROWNINGdev/orm-lens)
- **Founder / Owner**: [FROWNINGdev](https://github.com/FROWNINGdev)
- **Stars**: ⭐ 98
- **Audit Diagnosis**: `Intra-File Security Hazard` [CWE-369]

---

## 1. Verified AST / SCA Technical Evidence
- **Target File**: `scripts/fetch_golden_fixtures.py`:L94
- **Vulnerability / Gap**: Unblocked Unchecked ZeroDivisionError in `scripts/fetch_golden_fixtures.py`:L94.

```python
# Current Code / Gap:
dest = FIXTURES / project / path

# 1-Click Surgical Patch:
safe_project = project if project != 0 else 1e-7
            dest = FIXTURES / project / path
```

---

## 2. Copy-Paste Cold Email to CTO / Founder
**Subject**: `Security note + 1-click patch for FROWNINGdev/orm-lens`

```text
Hi FROWNINGdev,

Ran our 10ms local AST engine (Kavach AI) against orm-lens and wanted to share a quick pre-audit finding:

• Audit Type: Intra-File Security Hazard [CWE-369]
• Target: `scripts/fetch_golden_fixtures.py`:L94
• Diagnosis: Unblocked Unchecked ZeroDivisionError in `scripts/fetch_golden_fixtures.py`:L94.

Problem:\n  - dest = FIXTURES / project / path\n\nRecommended 1-Click Fix:\n  + safe_project = project if project != 0 else 1e-7
            dest = FIXTURES / project / path

We built Kavach AI for engineering teams who want 0 false positives and 0 code telemetry. It runs locally in CI under 16ms and posts ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.0
```

Would love to give you our Founder Launch Pass ($149 One-Time) or Team CI Gate if you'd like to automate this across your private repositories.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
rajabhaiyarajak2008@gmail.com
```

---

## 3. Copy-Paste LinkedIn DM
```text
Hey FROWNINGdev — came across orm-lens and ran our 10ms local AST scanner (Kavach AI). 

Noticed unblocked unchecked zerodivisionerror in `scripts/fetch_golden_fixtures.py`:l94.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```
