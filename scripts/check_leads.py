"""
Kavach AI — Quick Leads and Trial Signups Inspector
Run: python scripts/check_leads.py
"""

import sys
import json
import sqlite3
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def main():
    print('==================================================')
    print('[*] KAVACH AI - LIVE CUSTOMER & TRIAL LEADS')
    print('==================================================\n')
    
    # 1. Check TRIAL_SIGNUPS.json
    leads_file = Path('leads/TRIAL_SIGNUPS.json')
    if leads_file.exists():
        try:
            with open(leads_file, 'r', encoding='utf-8') as f:
                signups = json.load(f)
            print(f'[+] VIP 14-Day Trial Signups ({len(signups)} leads):')
            for s in signups:
                print(f'  • Email: {s.get("email")}')
                print(f'    Plan:  {s.get("tier")}')
                print(f'    Key:   {s.get("license_key")}')
                print(f'    Date:  {s.get("issued_at")}')
                print('--------------------------------------------------')
        except Exception as e:
            print('Error reading TRIAL_SIGNUPS.json:', e)
    else:
        print('[+] VIP 14-Day Trial Signups: 0 leads recorded yet.')
        print('    (File: leads/TRIAL_SIGNUPS.json)\n')

    # 2. Check Database Accounts
    db_file = Path('data/kavach_accounts.db')
    if db_file.exists():
        try:
            conn = sqlite3.connect(str(db_file))
            c = conn.cursor()
            c.execute('SELECT email, tier, license_key, created_at FROM kavach_accounts ORDER BY created_at DESC')
            rows = c.fetchall()
            conn.close()
            print(f'\n[+] Registered Accounts Database ({len(rows)} accounts):')
            for r in rows:
                print(f'  • Email: {r[0]} | Plan: {r[1]}')
                print(f'    Key:   {r[2]}')
                print(f'    Date:  {r[3]}')
                print('--------------------------------------------------')
        except Exception as e:
            print('Error reading database:', e)

if __name__ == '__main__':
    main()
