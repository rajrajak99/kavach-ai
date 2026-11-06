#!/usr/bin/env python3
"""
[KAVACH AI] 1-CLICK OUTREACH & SECURITY WORKSPACE LAUNCHER
Launches browser tabs for PyPI token revocation/rotation and target lead repositories,
and formats copy-paste cold email, LinkedIn DM, and PR templates directly in terminal.
"""
import webbrowser
import time
import sys
import io

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

URLS = [
    # 1. PyPI Token Management (Sanitization Verification)
    ("PyPI Token Management", "https://pypi.org/manage/account/token/"),
    # 2. Target Repositories
    ("Target 1: Sanoy24/fastapi-ecommerce", "https://github.com/Sanoy24/fastapi-ecommerce"),
    ("Target 2: Gurtejhundal/Traqu", "https://github.com/Gurtejhundal/Traqu"),
    ("Target 3: nimaxin/adminsite", "https://github.com/nimaxin/adminsite"),
    # 3. Direct Founder Outreach Mailto Links
    ("Mailto: Yonas Mekonnen (fastapi-ecommerce)", "mailto:myonas886@gmail.com?subject=Security%20Advisory%3A%20fastapi-ecommerce%20input%20validation%20(CWE-20)"),
    ("Mailto: nimaxin (adminsite)", "mailto:nimaxin2@gmail.com?subject=Security%20Advisory%3A%20adminsite%20DDL%20identifier%20validation%20(CWE-89)"),
]

def launch_workspace():
    print("=" * 80)
    print("🛡️  KAVACH AI — 1-CLICK OUTREACH & SECURITY WORKSPACE LAUNCHER")
    print("=" * 80)
    print("\n[+] Launching security management and target lead tabs in your default browser...")
    
    for label, url in URLS:
        print(f"  -> Opening: {label} ({url})")
        try:
            webbrowser.open_new_tab(url)
            time.sleep(0.4)
        except Exception as e:
            print(f"     [!] Could not open URL: {e}")

    print("\n" + "=" * 80)
    print("📋 READY-TO-SEND OUTREACH TEMPLATES (TOP 3 COMMERCIAL TARGETS)")
    print("=" * 80)

    print("""
--------------------------------------------------------------------------------
TARGET 1: Sanoy24/fastapi-ecommerce
Founder: Yonas Mekonnen | Email: myonas886@gmail.com | Stars: ⭐ 22
Weakness: CWE-20 (Improper Input Validation / Unbounded Query Parameter)
File: app/api/v1/routes/cart.py:L121 & app/services/cart_service.py:L208
--------------------------------------------------------------------------------

[COLD EMAIL]
To: myonas886@gmail.com
Subject: Security advisory + 1-click patch for fastapi-ecommerce (cart.py)

Hi Yonas,

Ran our 10ms local AST taint engine (Kavach AI) against fastapi-ecommerce and wanted to share a verified security audit finding in your production cart flow:

• Vulnerability: Improper Input Validation & Unbounded Query Parameter [CWE-20 / OWASP A03]
• Location: app/api/v1/routes/cart.py:L121 & app/services/cart_service.py:L208
• Impact: Raw, unbounded coupon query string reaches database query without regex constraints or length bounds.

1-Click Surgical Patch:
--- a/app/api/v1/routes/cart.py
+++ b/app/api/v1/routes/cart.py
@@ -121,3 +121,3 @@
-    code: str,
+    code: str = Query(..., min_length=2, max_length=50, pattern=r"^[A-Za-z0-9_-]+$"),

Unlike legacy SAST scanners that spit out 50 noisy false positives on test scripts, Kavach AI deterministically verifies AST taint paths in CI under 16ms and comments ready-to-merge patches directly on PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.1
```

Would love to give you an Early Adopter pass if you want automated pre-merge gates across your private repositories.

Best,  
Raja Rajak  
Founder, Kavach AI (https://kavach-ai.streamlit.app)  
rajabhaiyarajak2008@gmail.com

[LINKEDIN / TWITTER DM]
Hey Yonas — came across fastapi-ecommerce and ran our 10ms local AST engine (Kavach AI). 

Noticed untrusted coupon strings propagate directly into database filters without regex bounding or length constraints in `app/api/v1/routes/cart.py:L121`. 

We generated the exact 1-line surgical patch:
- code: str,
+ code: str = Query(..., min_length=2, max_length=50, pattern=r"^[A-Za-z0-9_-]+$"),

We built a plug-and-play GitHub Action (uses: rajrajak99/kavach-ai@v1.4.1) that catches and auto-patches these in CI before merge.

Happy to set you up with an Early Adopter pass if you want to test it on private repos: https://kavach-ai.streamlit.app!

--------------------------------------------------------------------------------
TARGET 2: Gurtejhundal/Traqu
Founder: Gurtejbir Singh | Website: https://gurtejbirsingh.vercel.app/ | Stars: ⭐ 15
Weakness: CWE-89 (Dynamic Table Migration SQL Injection & Unescaped Identifiers)
File: backend/db.py:L118
--------------------------------------------------------------------------------

[COLD EMAIL / CONTACT FORM]
To: Gurtejbir Singh (via Portfolio: https://gurtejbirsingh.vercel.app/)
Subject: Security advisory + 1-click patch for Traqu (backend/db.py)

Hi Gurtejbir,

Ran our 10ms local AST taint engine (Kavach AI) against Traqu and wanted to share a verified security audit finding in production database migration logic:

• Vulnerability: SQL Injection / Unescaped Dynamic Identifier Formatting [CWE-89 / OWASP A03]
• Location: backend/db.py:L118
• Impact: Table copy DDL executes raw f-strings directly inside cursor.execute() without standard identifier quote escaping.

1-Click Surgical Patch:
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

Unlike legacy SAST scanners that spit out 50 false positives on styling or test files, Kavach AI verifies deterministic AST taint paths in CI under 16ms and comments ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.1
```

Would love to set you up with an Early Adopter pass if you want automated pre-merge gates across your private repositories.

Best,  
Raja Rajak  
Founder, Kavach AI (https://kavach-ai.streamlit.app)  
rajabhaiyarajak2008@gmail.com

[LINKEDIN DM]
Hey Gurtejbir — came across Traqu and ran our 10ms local AST engine (Kavach AI). 

Noticed dynamic table migration formatting in `backend/db.py:L118` that could be vulnerable to quote breakage or SQL injection in raw `cursor.execute()`.

We generated the exact surgical patch diff:
- columns = ', '.join(f'"{column.name}"' for column in table.columns)
- cursor.execute(f'INSERT INTO "{temporary_name}" ({columns}) SELECT {columns} FROM "{table.name}"')
+ escape_ident = lambda name: f'"{name.replace(chr(34), chr(34)*2)}"'
+ columns = ', '.join(escape_ident(column.name) for column in table.columns)
+ cursor.execute(f'INSERT INTO {escape_ident(temporary_name)} ({columns}) SELECT {columns} FROM {escape_ident(table.name)}')

We built a plug-and-play GitHub Action (uses: rajrajak99/kavach-ai@v1.4.1) that catches and auto-patches these in CI before merge.

Happy to give you an Early Adopter pass if you want to test it on private repos: https://kavach-ai.streamlit.app!

--------------------------------------------------------------------------------
TARGET 3: nimaxin/adminsite
Founder: nimaxin | Email: nimaxin2@gmail.com | Stars: ⭐ 74
Weakness: CWE-89 (Dynamic DDL Identifier Validation in ALTER TABLE)
File: src/adminsite/_storage.py:L84
--------------------------------------------------------------------------------

[COLD EMAIL]
To: nimaxin2@gmail.com
Subject: Security advisory + 1-click patch for nimaxin/adminsite (_storage.py)

Hi nimaxin,

Ran our 10ms local AST taint engine (Kavach AI) against adminsite and wanted to share a verified security audit finding in your schema synchronization helper:

• Vulnerability: Dynamic DDL Identifier Validation [CWE-89 / OWASP A03]
• Location: src/adminsite/_storage.py:L84
• Impact: Dynamic ALTER TABLE DDL executes without strict identifier whitelist regex validation, triggering SAST injection warnings.

1-Click Surgical Patch:
--- a/src/adminsite/_storage.py
+++ b/src/adminsite/_storage.py
@@ -82,3 +82,6 @@
         if column.name not in present:
+            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(column.name)):
+                raise ValueError(f"Invalid column identifier: {column.name}")
             spec = CreateColumn(column).compile(dialect=connection.dialect)

Unlike legacy SAST scanners that spit out 50 false positives on test scripts, Kavach AI deterministically verifies AST taint paths in CI under 16ms and comments ready-to-merge patches directly on PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.1
```

Would love to give you an Early Adopter pass if you want automated pre-merge gates across your private repositories.

Best,  
Raja Rajak  
Founder, Kavach AI (https://kavach-ai.streamlit.app)  
rajabhaiyarajak2008@gmail.com

[LINKEDIN DM]
Hey nimaxin — came across adminsite and ran our 10ms local AST engine (Kavach AI). 

Noticed dynamic column additions in `src/adminsite/_storage.py:L84` execute ALTER TABLE without strict identifier syntax validation.

We generated the exact surgical patch diff:
+ if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(column.name)):
+     raise ValueError(f"Invalid column identifier: {column.name}")
  spec = CreateColumn(column).compile(dialect=connection.dialect)

We built a plug-and-play GitHub Action (uses: rajrajak99/kavach-ai@v1.4.1) that catches and auto-patches these in CI before merge.

Happy to set you up with an Early Adopter pass if you want to test it on private repos: https://kavach-ai.streamlit.app!
""")
    print("=" * 80)
    print("✅ Workspace launched successfully! Check your browser and copy messages above.")
    print("=" * 80)

if __name__ == "__main__":
    launch_workspace()
