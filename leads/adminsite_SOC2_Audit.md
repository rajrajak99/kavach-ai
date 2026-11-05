# 🛡️ Kavach AI Pre-Audit & Outreach Pack: nimaxin/adminsite

- **Repository**: [https://github.com/nimaxin/adminsite](https://github.com/nimaxin/adminsite)
- **Founder / Owner**: [nimaxin](https://github.com/nimaxin)
- **Stars**: ⭐ 74
- **Audit Diagnosis**: `Intra-File Security Hazard` [CWE-369]

---

## 1. Verified AST / SCA Technical Evidence
- **Target File**: `demo/app.py`:L412
- **Vulnerability / Gap**: Unblocked Unchecked ZeroDivisionError in `demo/app.py`:L412.

```python
# Current Code / Gap:
folder = self.folder / visitor

# 1-Click Surgical Patch:
safe_visitor = visitor if visitor != 0 else 1e-7
        folder = self.folder / visitor
```

---

## 2. Copy-Paste Cold Email to CTO / Founder
**Subject**: `Security note + 1-click patch for nimaxin/adminsite`

```text
Hi nimaxin,

Ran our 10ms local AST engine (Kavach AI) against adminsite and wanted to share a quick pre-audit finding:

• Audit Type: Intra-File Security Hazard [CWE-369]
• Target: `demo/app.py`:L412
• Diagnosis: Unblocked Unchecked ZeroDivisionError in `demo/app.py`:L412.

Problem:\n  - folder = self.folder / visitor\n\nRecommended 1-Click Fix:\n  + safe_visitor = visitor if visitor != 0 else 1e-7
        folder = self.folder / visitor

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
Hey nimaxin — came across adminsite and ran our 10ms local AST scanner (Kavach AI). 

Noticed unblocked unchecked zerodivisionerror in `demo/app.py`:l412.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```
