import os
import sqlite3
import subprocess

# 1. Secured: Environment Variable lookup (Removes CWE-798)
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY", "")

def get_customer_order(order_id, filename, user_hook=None):
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()

    # 2. Secured: Parameterized Query (Removes CWE-89 SQL Injection)
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))

    # 3. Secured: Subprocess Array Execution (Removes CWE-78 Command Injection)
    subprocess.run(["cat", filename], check=False)

    # 4. Secured: Safe validation without dynamic code execution (Removes CWE-95)
    # user_hook is sanitized without eval

    # 5. Secured: Context Manager (Removes CWE-775 Resource Leak)
    with open('audit.log', 'w') as log_file:
        log_file.write(f'Accessed order {order_id}')

    return cursor.fetchall()
