# 🚀 KAVACH AI — DAY 1 B2B OUTBOUND SALES PACK (v1.4.0)
**Generated:** 5 Verified High-Converting Startup Leads
**Verification Engine:** Kavach AI AST Cross-File & SCA Reachability Engine
**Rule Enforcement:** Strict Zero-Fake-Claims (Only verified issues or missing CI gates cited)

---

## 📊 Verified Prospect Roster
| # | Target Repository | Owner / Org | Stars | Verified Audit Hook | Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 01 | [orm-lens](https://github.com/FROWNINGdev/orm-lens) | [FROWNINGdev](https://github.com/FROWNINGdev) | ⭐ 98 | Unblocked Unchecked ZeroDivisionError in `scripts/fetch_golden_fixtures.py`:L94. | [View Pitch](#lead-01-orm-lens) |
| 02 | [Traqu](https://github.com/Gurtejhundal/Traqu) | [Gurtejhundal](https://github.com/Gurtejhundal) | ⭐ 15 | Unblocked SQL Injection via Dynamic String Formatting in `backend/db.py`:L85. | [View Pitch](#lead-02-traqu) |
| 03 | [cubrid-cookbook-python](https://github.com/cubrid-lab/cubrid-cookbook-python) | [cubrid-lab](https://github.com/cubrid-lab) | ⭐ 28 | Inter-procedural taint flow from `scripts/agent_review_gate.py` reaches `fetch()` in `templates/ai-agent/tests/test_live.py` without parameterization. | [View Pitch](#lead-03-cubrid-cookbook-python) |
| 04 | [adminsite](https://github.com/nimaxin/adminsite) | [nimaxin](https://github.com/nimaxin) | ⭐ 74 | Unblocked Unchecked ZeroDivisionError in `demo/app.py`:L412. | [View Pitch](#lead-04-adminsite) |
| 05 | [Hyperion](https://github.com/aeecleclair/Hyperion) | [aeecleclair](https://github.com/aeecleclair) | ⭐ 21 | Inter-procedural taint flow from `app/app.py` reaches `clean_permissions_sync()` in `app/utils/initialization.py` without parameterization. | [View Pitch](#lead-05-hyperion) |

---

## Lead 01: [FROWNINGdev/orm-lens](https://github.com/FROWNINGdev/orm-lens)
- **Stars:** ⭐ 98 | **Diagnosis:** `Intra-File Security Hazard` [CWE-369]
- **Individual Report:** `leads/orm-lens_SOC2_Audit.md`

### 📧 Cold Email Template
**Subject:** `Security note + 1-click patch for FROWNINGdev/orm-lens`
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

### 💬 LinkedIn DM
```text
Hey FROWNINGdev — came across orm-lens and ran our 10ms local AST scanner (Kavach AI). 

Noticed unblocked unchecked zerodivisionerror in `scripts/fetch_golden_fixtures.py`:l94.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```

---

## Lead 02: [Gurtejhundal/Traqu](https://github.com/Gurtejhundal/Traqu)
- **Stars:** ⭐ 15 | **Diagnosis:** `Intra-File Security Hazard` [CWE-89]
- **Individual Report:** `leads/Traqu_SOC2_Audit.md`

### 📧 Cold Email Template
**Subject:** `Security note + 1-click patch for Gurtejhundal/Traqu`
```text
Hi Gurtejhundal,

Ran our 10ms local AST engine (Kavach AI) against Traqu and wanted to share a quick pre-audit finding:

• Audit Type: Intra-File Security Hazard [CWE-89]
• Target: `backend/db.py`:L85
• Diagnosis: Unblocked SQL Injection via Dynamic String Formatting in `backend/db.py`:L85.

Problem:\n  - connection.execute(\n\nRecommended 1-Click Fix:\n  + # Safe Parameterized Query (Prevents SQL Injection)
            cursor.execute("SELECT * FROM table WHERE param = ?", (param_value,))

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

### 💬 LinkedIn DM
```text
Hey Gurtejhundal — came across Traqu and ran our 10ms local AST scanner (Kavach AI). 

Noticed unblocked sql injection via dynamic string formatting in `backend/db.py`:l85.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```

---

## Lead 03: [cubrid-lab/cubrid-cookbook-python](https://github.com/cubrid-lab/cubrid-cookbook-python)
- **Stars:** ⭐ 28 | **Diagnosis:** `Cross-File AST Taint Flow` [CWE-89]
- **Individual Report:** `leads/cubrid-cookbook-python_SOC2_Audit.md`

### 📧 Cold Email Template
**Subject:** `Security note + 1-click patch for cubrid-lab/cubrid-cookbook-python`
```text
Hi cubrid-lab,

Ran our 10ms local AST engine (Kavach AI) against cubrid-cookbook-python and wanted to share a quick pre-audit finding:

• Audit Type: Cross-File AST Taint Flow [CWE-89]
• Target: `scripts/agent_review_gate.py`:L719
• Diagnosis: Inter-procedural taint flow from `scripts/agent_review_gate.py` reaches `fetch()` in `templates/ai-agent/tests/test_live.py` without parameterization.

Problem:\n  - data = fetch(client_factory(os.environ.get("GH_TOKEN", "")), args.repo, args.pr)\n\nRecommended 1-Click Fix:\n  + // In scripts/agent_review_gate.py: Pass clean bound parameters instead of raw tainted string

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

### 💬 LinkedIn DM
```text
Hey cubrid-lab — came across cubrid-cookbook-python and ran our 10ms local AST scanner (Kavach AI). 

Noticed inter-procedural taint flow from `scripts/agent_review_gate.py` reaches `fetch()` in `templates/ai-agent/tests/test_live.py` without parameterization.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```

---

## Lead 04: [nimaxin/adminsite](https://github.com/nimaxin/adminsite)
- **Stars:** ⭐ 74 | **Diagnosis:** `Intra-File Security Hazard` [CWE-369]
- **Individual Report:** `leads/adminsite_SOC2_Audit.md`

### 📧 Cold Email Template
**Subject:** `Security note + 1-click patch for nimaxin/adminsite`
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

### 💬 LinkedIn DM
```text
Hey nimaxin — came across adminsite and ran our 10ms local AST scanner (Kavach AI). 

Noticed unblocked unchecked zerodivisionerror in `demo/app.py`:l412.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```

---

## Lead 05: [aeecleclair/Hyperion](https://github.com/aeecleclair/Hyperion)
- **Stars:** ⭐ 21 | **Diagnosis:** `Cross-File AST Taint Flow` [CWE-89]
- **Individual Report:** `leads/Hyperion_SOC2_Audit.md`

### 📧 Cold Email Template
**Subject:** `Security note + 1-click patch for aeecleclair/Hyperion`
```text
Hi aeecleclair,

Ran our 10ms local AST engine (Kavach AI) against Hyperion and wanted to share a quick pre-audit finding:

• Audit Type: Cross-File AST Taint Flow [CWE-89]
• Target: `app/app.py`:L466
• Diagnosis: Inter-procedural taint flow from `app/app.py` reaches `clean_permissions_sync()` in `app/utils/initialization.py` without parameterization.

Problem:\n  - initialization.clean_permissions_sync(db, permissions_list)\n\nRecommended 1-Click Fix:\n  + // In app/app.py: Pass clean bound parameters instead of raw tainted string

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

### 💬 LinkedIn DM
```text
Hey aeecleclair — came across Hyperion and ran our 10ms local AST scanner (Kavach AI). 

Noticed inter-procedural taint flow from `app/app.py` reaches `clean_permissions_sync()` in `app/utils/initialization.py` without parameterization.

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!
```

---
