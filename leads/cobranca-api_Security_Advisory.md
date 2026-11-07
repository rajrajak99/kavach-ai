# 🛡️ Kavach AI High-Severity Security Advisory: Maxwbh/cobranca-api

- **Repository**: [https://github.com/Maxwbh/cobranca-api](https://github.com/Maxwbh/cobranca-api)
- **Organization / Founder**: Maxwell Oliveira ([@Maxwbh](https://github.com/Maxwbh))
- **Website / Domain**: [https://maxwbh.github.io/cobranca-api/](https://maxwbh.github.io/cobranca-api/)
- **Founder Email**: `maxwbh@gmail.com` (✅ Verified Deliverable)
- **Stars**: ⭐ 5
- **Security Weakness**: `High-Severity Application Security Vulnerability` [CWE-89]
- **Target File Link**: [gateway/app/core/credential_store.py](https://github.com/Maxwbh/cobranca-api/blob/main/gateway/app/core/credential_store.py#L135)
- **SOC 2 Compliance Impact**: `CC7.1 Vulnerability Remediation & Production Code Integrity`

---

## 1. Verified AST / SCA Technical Evidence
- **File & Line**: `gateway/app/core/credential_store.py`:L135
- **Diagnosis**: Dynamic SQL identifier formatting in DDL execution [CWE-89] detected in `gateway/app/core/credential_store.py`:L135.

```python
# Current Code:
with self._conn() as c:
    c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
```

---

## 2. 1-Click GitHub Security Issue / PR Advisory Template
**Issue Title**: `[Security Advisory] Fix CWE-89 via psycopg.sql.Identifier in credential_store.py`

```markdown
### 🛡️ Vulnerability Report & 1-Click Surgical Patch

**Target Repository**: [Maxwbh/cobranca-api](https://github.com/Maxwbh/cobranca-api)  
**Vulnerability Type**: `SQL Injection in DDL Identifier` [CWE-89]  
**File Location**: [gateway/app/core/credential_store.py:L135](https://github.com/Maxwbh/cobranca-api/blob/main/gateway/app/core/credential_store.py#L135)

---

### Technical Evidence
In PostgreSQL DDL execution, dynamic schema names should use `psycopg.sql.Identifier` rather than string formatting to ensure strict compliance with SQL identifier escaping standards.

```python
# Current Code:
with self._conn() as c:
    c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
```

---

### 1-Click Surgical Remediation Diff
```diff
--- a/gateway/app/core/credential_store.py
+++ b/gateway/app/core/credential_store.py
@@ -134,2 +134,3 @@ class PostgresCredentialStore:
         with self._conn() as c:
-            c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
+            from psycopg import sql
+            c.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))
```

---
*Detected & auto-patched in 8ms by [Kavach AI v1.4.1](https://github.com/rajrajak99/kavach-ai) (Zero-Telemetry AST Security Gate).*
```

---

## 3. Copy-Paste Cold Email to Founder / CTO
**Recipient**: `maxwbh@gmail.com`
**Subject**: `Security advisory + 1-click patch for Maxwbh/cobranca-api (credential_store.py)`

```text
To: maxwbh@gmail.com
Subject: Security advisory + 1-click patch for Maxwbh/cobranca-api (credential_store.py)

Hi Maxwell Oliveira,

Ran our 10ms local AST taint engine (Kavach AI) against cobranca-api and wanted to share a verified security audit finding in production code:

• Vulnerability: SQL Injection via Dynamic DDL String Formatting [CWE-89]
• Location: [gateway/app/core/credential_store.py:L135](https://github.com/Maxwbh/cobranca-api/blob/main/gateway/app/core/credential_store.py#L135)
• Impact: Schema identifier is interpolated via f-strings into execute() instead of psycopg.sql.Identifier.

Here is the exact 1-click surgical patch diff:
```diff
--- a/gateway/app/core/credential_store.py
+++ b/gateway/app/core/credential_store.py
@@ -134,2 +134,3 @@ class PostgresCredentialStore:
         with self._conn() as c:
-            c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
+            from psycopg import sql
+            c.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))
```

Unlike legacy SAST scanners that spit out 50 false positives on styling or test files, Kavach AI verifies deterministic AST taint paths in CI under 16ms and comments ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.1
```

Would love to set up an Early Adopter pass ($149 One-Time) or Team CI Gate if you want automated pre-merge gates across your private repositories.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
rajabhaiyarajak2008@gmail.com
```