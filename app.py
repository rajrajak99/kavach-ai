import streamlit as st
import pandas as pd
import html
import os
from pathlib import Path

from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer
from core.ai_reasoner import AIReasoner
from core.license_manager import LicenseManager, PlanTier
from samples.vulnerable_samples import SAMPLE_PYTHON_MULTI

# ----------------- PAGE CONFIG -----------------
st.set_page_config(
    page_title="Kavach AI | Code Security Inspector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ----------------- STATE -----------------
if "is_pro_user" not in st.session_state:
    st.session_state.is_pro_user = False
if "license_tier" not in st.session_state:
    st.session_state.license_tier = PlanTier.FREE.value
if "license_key" not in st.session_state:
    st.session_state.license_key = ""
if "user_code" not in st.session_state:
    st.session_state.user_code = ""

def verify_license_key(key: str):
    return LicenseManager.get_tier_for_key(key)

# ----------------- CLEAN MINIMAL THEME (CSS) -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif !important;
        color: #f4f4f5 !important;
        background-color: #090a0f !important;
    }

    .stApp {
        background-color: #090a0f !important;
    }

    /* Clean Header */
    .brand-title {
        font-size: 1.5rem;
        font-weight: 800;
        color: #ffffff;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .brand-sub {
        font-size: 12.5px;
        color: #8b949e;
        margin-top: 2px;
    }

    /* Badges */
    .plan-badge {
        font-size: 12px;
        font-weight: 700;
        padding: 5px 14px;
        border-radius: 20px;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-free {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .badge-pro {
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.35);
    }
    .badge-team {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.35);
    }

    /* Simple Clean Tabs */
    .stTabs [data-baseweb="tab-list"] {
        border-bottom: 1px solid #1f2430 !important;
        gap: 20px !important;
        background: transparent !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e !important;
        font-weight: 600 !important;
        font-size: 14.5px !important;
        padding: 10px 18px !important;
        border: none !important;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        border-bottom: 2px solid #38bdf8 !important;
    }

    /* Clean Pricing Card */
    .pricing-box {
        background: #11131a;
        border: 1px solid #1f2430;
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 280px;
    }
    .pricing-box-pro {
        border: 2px solid #38bdf8;
        background: #0f1622;
    }
    .pricing-box-team {
        border: 2px solid #f59e0b;
        background: #1b1610;
    }
    .price-title {
        font-size: 14px;
        font-weight: 800;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .price-amt {
        font-size: 2.2rem;
        font-weight: 900;
        color: #ffffff;
        font-family: 'JetBrains Mono', monospace;
        margin: 10px 0;
    }
    .price-features {
        font-size: 12.5px;
        color: #c9d1d9;
        line-height: 1.8;
        text-align: left;
        margin: 16px 0;
    }

    /* Inputs */
    .stTextArea textarea {
        background: #0b0c10 !important;
        border: 1px solid #1f2430 !important;
        color: #ffffff !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important;
        border-radius: 8px !important;
    }
    .stButton > button[kind="primary"] {
        background-color: #38bdf8 !important;
        color: #000000 !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 20px !important;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- HEADER -----------------
head_col1, head_col2 = st.columns([2, 1])
with head_col1:
    st.markdown("""
    <div>
        <div class="brand-title">🛡️ Kavach AI <span style="font-size:12px; font-weight:600; color:#38bdf8; background:#111c2a; padding:2px 8px; border-radius:12px; border:1px solid #1e3a5f;">v1.2.1 Secure</span></div>
        <div class="brand-sub">Autonomous Zero-Noise Code Security Inspector & 1-Click Surgical Patcher</div>
    </div>
    """, unsafe_allow_html=True)

with head_col2:
    if st.session_state.license_tier == PlanTier.TEAM_ENTERPRISE.value:
        badge_html = '<span class="plan-badge badge-team">👑 Team Plan ($99/mo) Active</span>'
    elif st.session_state.is_pro_user:
        badge_html = '<span class="plan-badge badge-pro">⚡ Developer Pro ($1/mo) Active</span>'
    else:
        badge_html = '<span class="plan-badge badge-free">🆓 Community Free Active</span>'

    st.markdown(f"""
    <div style="display:flex; justify-content:flex-end; align-items:center; gap:8px; padding-top:6px;">
        <span style="font-size:12px; color:#8b949e;">Status:</span>
        {badge_html}
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='border-bottom: 1px solid #1f2430; margin: 8px 0 16px 0;'></div>", unsafe_allow_html=True)

# ----------------- ONLY 3 CLEAN TABS -----------------
tab_scan, tab_pricing, tab_setup = st.tabs([
    "🔍 Scan Code (कोड स्कैन करें)",
    "💎 Pricing Plans (सब्सक्रिप्शन प्लान्स - $0 / $1 / $99)",
    "🔌 GitHub Setup (गिटहब इंटीग्रेशन)"
])

# ================= TAB 1: CLEAN CODE SCANNER =================
with tab_scan:
    # Quick Test Buttons
    st.markdown("<div style='font-size:12px; font-weight:600; color:#8b949e; margin-bottom:6px;'>Quick Test Examples (Optional):</div>", unsafe_allow_html=True)
    c_btn1, c_btn2, c_btn3, c_btn4 = st.columns([1.2, 1.2, 1, 3])
    with c_btn1:
        if st.button("🔑 Load Secret Leak Sample", use_container_width=True):
            st.session_state.user_code = SAMPLE_PYTHON_MULTI
            st.rerun()
    with c_btn2:
        if st.button("💉 Load SQL Injection Sample", use_container_width=True):
            st.session_state.user_code = '''import sqlite3

def find_user(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
'''
            st.rerun()
    with c_btn3:
        if st.button("🧹 Clear Box", use_container_width=True):
            st.session_state.user_code = ""
            st.rerun()

    col_editor, col_result = st.columns([1.1, 1.2], gap="large")

    with col_editor:
        code_input = st.text_area(
            "Paste your Python, JavaScript, or C++ code here:",
            value=st.session_state.user_code,
            height=340,
            placeholder="Code box is empty. Paste your code here to inspect for vulnerabilities (SQL injection, leaked keys, command injection...)"
        )
        inspect_btn = st.button("⚡ Inspect Code Now", type="primary", use_container_width=True)

    # Run Analysis
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()

    code_to_check = code_input.strip() if code_input else ""
    if code_to_check:
        if "diff --git" in code_to_check or "\n@@ " in code_to_check or code_to_check.startswith("@@ "):
            diffs = parser.parse_git_diff(code_to_check)
        else:
            sn_name = "snippet.py"
            if "const " in code_to_check or "function" in code_to_check:
                sn_name = "snippet.js"
            elif "#include" in code_to_check:
                sn_name = "snippet.cpp"
            diffs = [parser.parse_raw_snippet(sn_name, code_to_check)]
        analysis = analyzer.generate_pull_request_review(diffs)
        findings = analysis['findings']
        metrics = analysis['metrics']
    else:
        findings = []
        metrics = {'critical': 0, 'security': 0, 'performance': 0}

    with col_result:
        st.markdown("<div style='font-size:13px; font-weight:700; color:#ffffff; margin-bottom:6px;'>Inspection Result</div>", unsafe_allow_html=True)
        if not code_to_check:
            st.info("👈 Code box is clean and empty. Paste any code on the left and click **Inspect Code Now**.")
        elif not findings:
            st.success("🟢 **CLEAN - READY TO MERGE**\n\nZero security vulnerabilities or resource leaks detected in this code.")
        else:
            if metrics['critical'] > 0:
                st.error(f"🔴 **MERGE BLOCKED**: Found {metrics['critical']} Critical Security Exploit(s)")
            else:
                st.warning(f"🟠 **WARNING**: Found {metrics['security']} Security Vulnerability / Leak(s)")

            for i, f in enumerate(findings, 1):
                cat_safe = html.escape(f.category)
                exp_safe = html.escape(f.explanation)
                cwe_safe = html.escape(f.cwe_id or "CWE-General")
                
                with st.expander(f"Issue #{i}: {cat_safe} ({f.severity})", expanded=True):
                    st.write(exp_safe)
                    c1, c2 = st.columns(2)
                    with c1:
                        st.caption("❌ Vulnerable Code:")
                        st.code(f.problem_code, language=f.language)
                    with c2:
                        st.caption("✅ 1-Click Surgical Patch:")
                        st.code(f.fixed_code, language=f.language)

# ================= TAB 2: PROMINENT SIMPLE PRICING =================
with tab_pricing:
    st.markdown("### 💎 Choose Your Kavach AI Plan")
    st.caption("100% Zero-Loss Model. Runs locally on your machine — zero server bills.")

    p1, p2, p3 = st.columns(3)

    # 1. Free Plan
    with p1:
        st.markdown("""
        <div class="pricing-box">
            <div>
                <div class="price-title" style="color:#34d399;">🆓 Community Plan</div>
                <div class="price-amt">$0</div>
                <div style="font-size:11px; color:#8b949e; margin-bottom:12px;">Forever Free</div>
                <div class="price-features">
                    ✓ <b>Unlimited Public Repositories</b><br>
                    ✓ High-Speed Offline AST Scanner<br>
                    ✓ Local CLI (`kavach .`)<br>
                    ✓ Free for Students & Open Source<br>
                    ✓ Zero Data Retention
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
        if st.button("🆓 Use Free Plan ($0)", key="btn_activate_free", use_container_width=True):
            st.session_state.is_pro_user = False
            st.session_state.license_tier = PlanTier.FREE.value
            st.session_state.license_key = ""
            st.success("Active Plan: Community Free ($0)")
            st.rerun()

    # 2. Developer Pro Plan
    with p2:
        st.markdown("""
        <div class="pricing-box pricing-box-pro">
            <div>
                <div class="price-title" style="color:#38bdf8;">⚡ Developer Pro</div>
                <div class="price-amt">$1<span style="font-size:14px; color:#8b949e;">/mo</span></div>
                <div style="font-size:11px; color:#38bdf8; font-weight:700; margin-bottom:12px;">$12 Billed Annually</div>
                <div class="price-features">
                    ✓ <b>Up to 5 Personal Private Repos</b><br>
                    ✓ 1-Click Code Remediations<br>
                    ✓ Local Git Pre-Commit Hooks<br>
                    ✓ Personal GitHub Account Support<br>
                    ✓ Priority Email Updates
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
        if st.button("⚡ Select Developer Pro ($1)", key="btn_activate_pro", use_container_width=True):
            st.session_state.is_pro_user = True
            st.session_state.license_tier = PlanTier.DEVELOPER_PRO.value
            st.session_state.license_key = "BUILDER-DEV-1"
            st.balloons()
            st.success("Active Plan: Developer Pro ($1/mo)")
            st.rerun()

    # 3. Team Enterprise Plan
    with p3:
        st.markdown("""
        <div class="pricing-box pricing-box-team">
            <div>
                <div class="price-title" style="color:#fbbf24;">🏢 Team Enterprise</div>
                <div class="price-amt">$99<span style="font-size:14px; color:#8b949e;">/mo</span></div>
                <div style="font-size:11px; color:#fbbf24; font-weight:700; margin-bottom:12px;">For Startups & Companies</div>
                <div class="price-features">
                    ✓ <b>GitHub Organizations</b><br>
                    ✓ <b>Unlimited Team Repositories</b><br>
                    ✓ Autonomous PR Review Bot & Blocker<br>
                    ✓ Pytest Self-Healing Engine<br>
                    ✓ SLA Support
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
        if st.button("🏢 Select Team Enterprise ($99)", key="btn_activate_team", use_container_width=True):
            st.session_state.is_pro_user = True
            st.session_state.license_tier = PlanTier.TEAM_ENTERPRISE.value
            st.session_state.license_key = "KV-TEAM-ORG-99"
            st.balloons()
            st.success("Active Plan: Team Enterprise ($99/mo)")
            st.rerun()

    st.markdown("---")
    st.markdown("#### 🔑 Have a License Key?")
    k_col1, k_col2 = st.columns([2, 1])
    with k_col1:
        custom_key_input = st.text_input("Enter License Key:", placeholder="e.g. BUILDER-DEV-1 or KV-TEAM-ORG-99")
    with k_col2:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        if st.button("⚡ Activate License Key", use_container_width=True):
            tier = verify_license_key(custom_key_input)
            if tier:
                st.session_state.is_pro_user = True
                st.session_state.license_tier = tier.value
                st.session_state.license_key = custom_key_input.strip().upper()
                st.balloons()
                st.rerun()
            else:
                st.error("Invalid Key! Demo keys: BUILDER-DEV-1 (Pro) or KV-TEAM-ORG-99 (Team)")

# ================= TAB 3: GITHUB SETUP =================
with tab_setup:
    st.markdown("### 🔌 1-Minute GitHub Actions Setup")
    st.caption("Protect your GitHub repository from bad code and vulnerabilities automatically.")

    st.markdown("Create file `.github/workflows/kavach.yml` in your repo:")
    st.code('''name: 🛡️ Kavach AI Security Gate

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]

permissions:
  contents: read
  pull-requests: write

jobs:
  kavach-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run Kavach AI
        uses: rajrajak99/kavach-ai@v1.2.1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: 'CRITICAL'
''', language="yaml")

    st.markdown("#### 📦 Run Locally via Terminal:")
    st.code("pip install --upgrade kavach-ai\nkavach .", language="bash")
