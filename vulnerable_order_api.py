import os
import sqlite3

# 1. Hardcoded Secret Key (CWE-798)
AWS_SECRET_KEY = 'AKIA1234567890EXAMPLEKEYDO_NOT_LEAK'

def get_customer_order(order_id, filename, user_hook):
    conn = sqlite3.connect('store.db')
    cursor = conn.cursor()

    # 2. Raw SQL Injection (CWE-89)
    query = f'SELECT * FROM orders WHERE id = {order_id}'
    cursor.execute(query)

    # 3. Command Injection via os.system (CWE-78)
    os.system(f'cat {filename}')

    # 4. Critical Arbitrary Code Execution (CWE-95)
    eval(user_hook)

    # 5. Resource Leak (CWE-775)
    log_file = open('audit.log', 'w')
    log_file.write(f'Accessed order {order_id}')

    return cursor.fetchall()
