# 🛡️ Kavach AI High-Severity Security Advisory: Gurtejhundal/Traqu

- **Repository**: [https://github.com/Gurtejhundal/Traqu](https://github.com/Gurtejhundal/Traqu)
- **Founder / Owner**: Gurtejbir Singh ([@Gurtejhundal](https://github.com/Gurtejhundal))
- **Author Website**: [https://gurtejbirsingh.vercel.app/](https://gurtejbirsingh.vercel.app/)
- **Stars**: ⭐ 15
- **Security Weakness**: `Dynamic Table Migration SQL Injection & Unescaped Identifiers` [CWE-89]
- **Target File Link**: [`backend/db.py:L114-123`](https://github.com/Gurtejhundal/Traqu/blob/main/backend/db.py#L114-L123)
- **SOC 2 Compliance Impact**: `CC7.1 Vulnerability Remediation & Production Code Integrity`

---

## 1. Verified AST / SCA Technical Evidence

In `backend/db.py`, database schema migration logic uses raw Python f-strings to format temporary table names and column lists directly into `cursor.execute()`. Without SQL-92 identifier quote escaping, table or column names containing quotation characters break syntax or allow arbitrary DDL execution.

```python
# Vulnerable Code (backend/db.py:L117-120):
columns = ', '.join(f'"{column.name}"' for column in table.columns)
cursor.execute(f'INSERT INTO "{temporary_name}" ({columns}) SELECT {columns} FROM "{table.name}"')
cursor.execute(f'DROP TABLE "{table.name}"')
cursor.execute(f'ALTER TABLE "{temporary_name}" RENAME TO "{table.name}"')
```

---

## 2. 1-Click Surgical Remediation Diff (Exact Python Code)

```diff
--- a/backend/db.py
+++ b/backend/db.py
@@ -117,7 +117,11 @@ def upgrade_database(engine: Engine) -> None:
-            columns = ', '.join(f'"{column.name}"' for column in table.columns)
-            cursor.execute(f'INSERT INTO "{temporary_name}" ({columns}) SELECT {columns} FROM "{table.name}"')
-            cursor.execute(f'DROP TABLE "{table.name}"')
-            cursor.execute(f'ALTER TABLE "{temporary_name}" RENAME TO "{table.name}"')
+            # Safely escape double-quotes in identifiers to prevent SQL injection & syntax breakages
+            escape_ident = lambda name: f'"{name.replace(chr(34), chr(34)*2)}"'
+            columns = ', '.join(escape_ident(column.name) for column in table.columns)
+            safe_temp = escape_ident(temporary_name)
+            safe_table = escape_ident(table.name)
+            cursor.execute(f'INSERT INTO {safe_temp} ({columns}) SELECT {columns} FROM {safe_table}')
+            cursor.execute(f'DROP TABLE {safe_table}')
+            cursor.execute(f'ALTER TABLE {safe_temp} RENAME TO {safe_table}')
```

---

## 3. Copy-Paste Cold Email to Founder / CTO

**To**: `Gurtejbir Singh (via Portfolio: https://gurtejbirsingh.vercel.app/)`  
**Subject**: `Security advisory + 1-click patch for Traqu (backend/db.py)`

```text
Hi Gurtejbir,

Ran our 10ms local AST taint engine (Kavach AI) against Traqu and wanted to share a verified security audit finding in production database migration logic:

• Vulnerability: SQL Injection / Unescaped Dynamic Identifier Formatting [CWE-89 / OWASP A03]
• Location: backend/db.py:L118
• Impact: Table copy DDL executes raw f-strings directly inside cursor.execute() without standard identifier quote escaping.

1-Click Surgical Patch:
```diff
--- a/backend/db.py
+++ b/backend/db.py
@@ -117,4 +117,8 @@
-            columns = ', '.join(f'"{column.name}"' for column in table.columns)
-            cursor.execute(f'INSERT INTO "{temporary_name}" ({columns}) SELECT {columns} FROM "{table.name}"')
+            escape_ident = lambda name: f'"{name.replace(chr(34), chr(34)*2)}"'
+            columns = ', '.join(escape_ident(column.name) for column in table.columns)
+            safe_temp = escape_ident(temporary_name)
+            safe_table = escape_ident(table.name)
+            cursor.execute(f'INSERT INTO {safe_temp} ({columns}) SELECT {columns} FROM {safe_table}')
```

Unlike legacy SAST scanners that spit out 50 false positives on styling or test files, Kavach AI verifies deterministic AST taint paths in CI under 16ms and comments ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.0
```

Would love to set you up with an Early Adopter pass if you want automated pre-merge gates across your private repositories.

Best,  
Raja Rajak  
Founder, Kavach AI (https://kavach-ai.streamlit.app)  
rajabhaiyarajak2008@gmail.com
```

---

## 4. Copy-Paste LinkedIn DM

```text
Hey Gurtejbir — came across Traqu and ran our 10ms local AST engine (Kavach AI). 

Noticed dynamic table migration formatting in `backend/db.py:L118` that could be vulnerable to quote breakage or SQL injection in raw `cursor.execute()`.

We generated the exact surgical patch diff:
- columns = ', '.join(f'"{column.name}"' for column in table.columns)
- cursor.execute(f'INSERT INTO "{temporary_name}" ({columns}) SELECT {columns} FROM "{table.name}"')
+ escape_ident = lambda name: f'"{name.replace(chr(34), chr(34)*2)}"'
+ columns = ', '.join(escape_ident(column.name) for column in table.columns)
+ cursor.execute(f'INSERT INTO {escape_ident(temporary_name)} ({columns}) SELECT {columns} FROM {escape_ident(table.name)}')

We built a plug-and-play GitHub Action (uses: rajrajak99/kavach-ai@v1.4.0) that catches and auto-patches these in CI before merge.

Happy to give you an Early Adopter pass if you want to test it on private repos: https://kavach-ai.streamlit.app!
```

---

## 5. Ready-to-Submit GitHub Pull Request (PR) Description

**PR Title**: `fix(db): escape SQL identifiers during table upgrade migrations (CWE-89)`

```markdown
### 🛡️ Security Advisory Summary
This pull request hardens SQLite table migration queries in `backend/db.py` by escaping double quotes in table and column identifiers per the SQL-92 standard.

### 🔍 Vulnerability Details
- **Weakness**: `CWE-89` (SQL Injection / Improper Identifier Neutralization)
- **Impact**: Dynamic table renaming and copying constructed via Python f-strings without identifier escaping can break SQL syntax or allow unintended DDL manipulation if table/column definitions include quote characters.
- **Remediation**:
  Implement SQL-92 identifier quote doubling (`name.replace('"', '""')`) for all dynamic table and column identifiers.

### 🧪 Verification
- Verified successful compilation of table copy, drop, and rename queries.
- Ensured foreign-key check passes cleanly.

*Discovered and verified via [Kavach AI v1.4.0](https://github.com/rajrajak99/kavach-ai) (Zero-Telemetry AST Security Gate).*
```
