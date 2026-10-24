"""
Curated real-world buggy Pull Request samples for instant testing (Python, JavaScript, & C++).
"""

SAMPLE_NODE_JS_EXPRESS = """diff --git a/routes/orderController.js b/routes/orderController.js
--- a/routes/orderController.js
+++ b/routes/orderController.js
@@ -10,12 +10,25 @@ const express = require('express');
 const router = express.Router();
 
+// 1. Leaked Payment Gateway Secret
+const stripeSecretKey = "sk-live-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4";
+
+router.post('/checkout', async (req, res) => {
+    const { userId, orderCmd, dynamicScript } = req.body;
+
+    // 2. Node.js SQL Injection via Template Literal
+    const query = `SELECT * FROM orders WHERE user_id = ${userId}`;
+    const result = await db.query(query);
+
+    // 3. Node.js Remote Command Injection
+    child_process.exec(`sync_orders.sh --id=${orderCmd}`);
+
+    // 4. Critical Arbitrary Code Execution (eval)
+    eval(dynamicScript);
+
+    res.json({ success: true });
+});
+"""

SAMPLE_PYTHON_MULTI = """diff --git a/app/security_demo.py b/app/security_demo.py
--- a/app/security_demo.py
+++ b/app/security_demo.py
@@ -1,5 +1,15 @@
+import os
+
+# 1. Leaked GitHub Token
+github_token = "ghp_AbCdEf1234567890XyZ1234567890AbCdEf"
+
+# 2. Command Injection Vulnerability
+filename = input("Enter filename: ")
+os.system(f"cat {filename}")
+
+# 3. Unmanaged File Leak
+log_file = open("audit.log", "w")
+log_file.write("User accessed system")
+"""

SAMPLE_SQLI_AND_NONE = """diff --git a/backend/routes/user.py b/backend/routes/user.py
--- a/backend/routes/user.py
+++ b/backend/routes/user.py
@@ -20,6 +20,10 @@ def get_user_profile(user_id):
+    # Query user profile from database
+    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
+    cursor.execute(query)
+    user_record = cursor.fetchone()
+    return {"status": "ok", "profile": user_record}
+"""

SAMPLE_CPP_MEMORY_AND_SECURITY = """diff --git a/src/network_handler.cpp b/src/network_handler.cpp
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/src/network_handler.cpp
@@ -0,0 +1,24 @@
+#include <iostream>
+#include <cstring>
+#include <cstdlib>
+
+void process_client_request(const char* user_input, const char* filename) {
+    // 1. Hardcoded production API token
+    const char* api_key = "ghp_ProductionSecretKey998877665544332211";
+    
+    // 2. Dangerous unbounded buffer copy (Buffer Overflow)
+    char buffer[64];
+    strcpy(buffer, user_input);
+    
+    // 3. Format string vulnerability
+    printf(buffer);
+    
+    // 4. Arbitrary command injection
+    std::string cmd = "ping -c 1 " + std::string(filename);
+    system(cmd.c_str());
+}
+"""

ALL_SAMPLES = {
    "🌐 Node.js / Express Backend (JS/TS Security Pack)": SAMPLE_NODE_JS_EXPRESS,
    "🐍 Python Multi-Threat (Token + Command Injection + File Leak)": SAMPLE_PYTHON_MULTI,
    "🚨 SQL Injection & Unsafe Query (Python)": SAMPLE_SQLI_AND_NONE,
    "⚡ C++ Memory Safety & Injection (Buffer Overflow + system + Token)": SAMPLE_CPP_MEMORY_AND_SECURITY
}
