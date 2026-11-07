"""
Launch Priority B2B Outreach Workspace (Lead #4 & Lead #5):
1. Maxwbh/cobranca-api (maxwbh@gmail.com) -> DDL SQLi PR on GitHub & Email
2. LovePelmeni/Payment-Service (kirklimushin@gmail.com) -> Private Email for CWE-798 Hardcoded Secret
"""
import webbrowser
import urllib.parse
import time
import sys

TARGETS = [
    {
        "repo": "Maxwbh/cobranca-api",
        "founder": "Maxwell Oliveira",
        "email": "maxwbh@gmail.com",
        "file_url": "https://github.com/Maxwbh/cobranca-api/blob/main/gateway/app/core/credential_store.py#L135",
        "subject": "Security advisory + 1-click patch for Maxwbh/cobranca-api (credential_store.py)",
        "body": """Hi Maxwell,

Ran our 10ms local AST taint engine (Kavach AI v1.4.1) against cobranca-api and wanted to share a verified security audit finding in production code:

• Vulnerability: DDL SQL Injection via Dynamic String Formatting [CWE-89]
• Location: gateway/app/core/credential_store.py:L135
• Impact: c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"') constructs dynamic schema identifiers directly from input variables.

Here is the exact 1-click surgical patch diff using psycopg's native identifier escaper:

--- a/gateway/app/core/credential_store.py
+++ b/gateway/app/core/credential_store.py
@@ -134,2 +134,3 @@ class PostgresCredentialStore:
         with self._conn() as c:
-            c.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
+            from psycopg import sql
+            c.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))

We built a sub-16ms zero-telemetry GitHub Action (uses: rajrajak99/kavach-ai@v1.4.1) that blocks dynamic SQLi flows before merge.

Happy to set you up with an Early Adopter pass if you'd like to run automated pre-merge gates across your private repositories: https://kavach-ai.streamlit.app

Best,
Raja Rajak
Founder, Kavach AI
rajabhaiyarajak2008@gmail.com"""
    },
    {
        "repo": "LovePelmeni/Payment-Service",
        "founder": "Kirill Klimushin",
        "email": "kirklimushin@gmail.com",
        "file_url": "https://github.com/LovePelmeni/Payment-Service/blob/main/API/settings.py#L47",
        "subject": "Security advisory + 1-line fix for Payment-Service (API/settings.py)",
        "body": """Hi Kirill,

Ran our local AST security engine (Kavach AI v1.4.1) against Payment-Service and wanted to privately flag a hardcoded credential finding in your configuration:

- Finding: Hardcoded Stripe API Secret [CWE-798]
- Location: API/settings.py:L47
- Remediation Patch:
--- a/API/settings.py
+++ b/API/settings.py
@@ -46,2 +46,3 @@
-STRIPE_API_SECRET = 'sk_test_...'
+import os
+STRIPE_API_SECRET = os.environ.get("STRIPE_API_SECRET", "")

We built a sub-16ms zero-telemetry GitHub Action (uses: rajrajak99/kavach-ai@v1.4.1) that blocks hardcoded secrets and SQLi taint flows before merge.

Happy to set you up with an Early Adopter pass if you'd like to run it across your private repositories: https://kavach-ai.streamlit.app

Best,
Raja Rajak
Founder, Kavach AI
rajabhaiyarajak2008@gmail.com"""
    }
]

def main():
    open_browser = "--open-browser" in sys.argv
    print("=" * 80)
    print("KAVACH AI - PRIORITY OUTREACH WORKSPACE (LEADS #4 & #5)")
    print("=" * 80)
    
    for idx, t in enumerate(TARGETS, 1):
        print(f"\n[{idx}/2] Target: {t['repo']} ({t['founder']})")
        print(f"Email: {t['email']}")
        print(f"File URL: {t['file_url']}")
        print(f"Subject: {t['subject']}")
        print("-" * 60)
        
        gmail_url = (
            f"https://mail.google.com/mail/?view=cm&fs=1"
            f"&to={urllib.parse.quote(t['email'])}"
            f"&su={urllib.parse.quote(t['subject'])}"
            f"&body={urllib.parse.quote(t['body'])}"
        )
        print(f"Direct Gmail Web Compose Link:\n{gmail_url}\n")
        
        if open_browser:
            print(f"Opening Browser Tab for {t['email']}...")
            webbrowser.open(gmail_url)
            time.sleep(1)
            print(f"Opening GitHub File: {t['file_url']}...")
            webbrowser.open(t['file_url'])
            time.sleep(1)

    print("\n" + "=" * 80)
    print("Priority outreach workspace prepared.")
    print("=" * 80)

if __name__ == "__main__":
    main()
