import streamlit as st
import pandas as pd
import requests
import html
import base64
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

# ----------------- LOGO LOADER -----------------
@st.cache_data
def get_logo_base64():
    logo_path = Path("assets/logo.png")
    if logo_path.exists():
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""

# ----------------- CACHED ENGINES & HELPERS -----------------
@st.cache_resource
def get_parser():
    return DiffParser()

@st.cache_resource
def get_analyzer():
    return SurgicalAnalyzer()

@st.cache_data(show_spinner=False)
def analyze_code_cached(code_str: str):
    if not code_str:
        return {'findings': [], 'metrics': {'critical': 0, 'security': 0, 'performance': 0}}
    parser = get_parser()
    analyzer = get_analyzer()
    if "diff --git" in code_str or "\n@@ " in code_str or code_str.startswith("@@ "):
        diffs = parser.parse_git_diff(code_str)
    else:
        sn_name = "snippet.py"
        if "const " in code_str or "function" in code_str:
            sn_name = "snippet.js"
        elif "#include" in code_str:
            sn_name = "snippet.cpp"
        diffs = [parser.parse_raw_snippet(sn_name, code_str)]
    return analyzer.generate_pull_request_review(diffs)

# ----------------- STATE INITIALIZATION -----------------
if "is_pro_user" not in st.session_state:
    st.session_state.is_pro_user = False
if "license_tier" not in st.session_state:
    st.session_state.license_tier = PlanTier.FREE.value
if "license_key" not in st.session_state:
    st.session_state.license_key = ""
if "user_code" not in st.session_state:
    st.session_state.user_code = ""
if "toast_msg" not in st.session_state:
    st.session_state.toast_msg = None
if "key_feedback" not in st.session_state:
    st.session_state.key_feedback = None
if "github_user" not in st.session_state:
    st.session_state.github_user = None
if "auth_error" not in st.session_state:
    st.session_state.auth_error = None

# ----------------- GITHUB AUTH HELPER -----------------
@st.cache_data(ttl=3600)
def fetch_github_profile(username: str, token: str = ""):
    if not username:
        return {"success": False, "error": "Username cannot be empty."}
    headers = {"User-Agent": "Kavach-AI-Scanner"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        res = requests.get(f"https://api.github.com/users/{username.strip()}", headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return {
                "success": True,
                "login": data.get("login"),
                "name": data.get("name") or data.get("login"),
                "avatar_url": data.get("avatar_url"),
                "public_repos": data.get("public_repos", 0),
                "html_url": data.get("html_url"),
                "bio": data.get("bio", ""),
            }
        elif res.status_code == 404:
            return {"success": False, "error": f"GitHub user '@{username}' not found."}
        else:
            return {"success": False, "error": f"GitHub API error (status {res.status_code})"}
    except Exception as e:
        return {"success": False, "error": f"Network error: {str(e)}"}

def login_github():
    username = st.session_state.get("input_gh_user", "").strip()
    token = st.session_state.get("input_gh_pat", "").strip()
    if not username:
        st.session_state.auth_error = "Please enter your GitHub username."
        return
    profile = fetch_github_profile(username, token)
    if profile.get("success"):
        st.session_state.github_user = profile
        st.session_state.auth_error = None
        st.session_state.toast_msg = f"👋 Connected as @{profile['login']}!"
    else:
        st.session_state.auth_error = profile.get("error", "GitHub user not found.")

def demo_login_github():
    profile = fetch_github_profile("rajrajak99")
    if profile.get("success"):
        st.session_state.github_user = profile
        st.session_state.auth_error = None
        st.session_state.toast_msg = "👋 Signed in as Founder @rajrajak99!"

def logout_github():
    st.session_state.github_user = None
    st.session_state.auth_error = None
    st.session_state.toast_msg = "Logged out of GitHub."

# ----------------- INSTANT CALLBACKS (0ms LATENCY) -----------------
def select_plan(tier_val: str, key_val: str, is_pro_val: bool, plan_name: str):
    st.session_state.license_tier = tier_val
    st.session_state.license_key = key_val
    st.session_state.is_pro_user = is_pro_val
    st.session_state.toast_msg = f"🎉 {plan_name} Active!"

def activate_custom_key():
    key = st.session_state.get("custom_key_input", "").strip().upper()
    if not key:
        st.session_state.key_feedback = ("error", "Please enter a license key.")
        return
    tier = LicenseManager.get_tier_for_key(key)
    if tier:
        st.session_state.license_tier = tier.value
        st.session_state.license_key = key
        st.session_state.is_pro_user = (tier != PlanTier.FREE)
        st.session_state.key_feedback = ("success", f"✅ Key Verified: {tier.value} Activated!")
        st.session_state.toast_msg = f"✅ Activated: {tier.value}"
    else:
        st.session_state.key_feedback = ("error", "❌ Invalid Key! Demo keys: BUILDER-DEV-1 (Pro) or KV-TEAM-ORG-99 (Team)")

def load_code_sample(code: str):
    st.session_state.user_code = code

def clear_code_box():
    st.session_state.user_code = ""

def apply_patch_to_editor(problem_code: str, fixed_code: str):
    current = st.session_state.get("user_code", "")
    if problem_code in current:
        st.session_state.user_code = current.replace(problem_code, fixed_code)
        st.session_state.toast_msg = "🪄 1-Click Patch Applied! Code is now secure."
    else:
        lines = current.splitlines()
        replaced = False
        new_lines = []
        for line in lines:
            if not replaced and line.strip() == problem_code.strip():
                indent = len(line) - len(line.lstrip())
                indented_fixed = "\n".join([" " * indent + fl.lstrip() for fl in fixed_code.splitlines()])
                new_lines.append(indented_fixed)
                replaced = True
            else:
                new_lines.append(line)
        if replaced:
            st.session_state.user_code = "\n".join(new_lines)
            st.session_state.toast_msg = "🪄 1-Click Patch Applied! Code is now secure."

# Trigger toast notification if pending
if st.session_state.get("toast_msg"):
    st.toast(st.session_state.toast_msg)
    st.session_state.toast_msg = None

# ----------------- LUXURY MIDNIGHT CYBERSECURITY THEME (CSS) -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        color: #f0f6fc !important;
        background-color: #07090e !important;
    }

    .stApp {
        background-color: #07090e !important;
    }

    /* Top Navbar */
    .brand-group {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .brand-logo-img {
        width: 44px;
        height: 44px;
        border-radius: 10px;
        object-fit: cover;
        box-shadow: 0 0 20px rgba(0, 229, 255, 0.4);
        border: 1px solid rgba(0, 229, 255, 0.45);
    }
    .brand-title {
        font-size: 1.4rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.02em;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .brand-badge {
        font-size: 11px;
        font-weight: 700;
        color: #00e5ff;
        background: rgba(0, 229, 255, 0.1);
        border: 1px solid rgba(0, 229, 255, 0.28);
        padding: 2px 8px;
        border-radius: 20px;
        font-family: 'JetBrains Mono', monospace;
    }
    .brand-sub {
        font-size: 12px;
        color: #8b949e;
        margin-top: 1px;
    }

    /* Badges */
    .plan-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        font-family: 'JetBrains Mono', monospace;
    }
    .pill-free {
        background: rgba(16, 185, 129, 0.12);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .pill-pro {
        background: rgba(0, 229, 255, 0.12);
        color: #00e5ff;
        border: 1px solid rgba(0, 229, 255, 0.35);
        box-shadow: 0 0 12px rgba(0, 229, 255, 0.2);
    }
    .pill-team {
        background: rgba(245, 158, 11, 0.12);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }

    /* Hero Section */
    .hero-box {
        margin-bottom: 24px;
    }
    .hero-tag {
        display: inline-block;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #00e5ff;
        background: rgba(0, 229, 255, 0.08);
        border: 1px solid rgba(0, 229, 255, 0.2);
        padding: 4px 10px;
        border-radius: 6px;
        margin-bottom: 8px;
    }
    .hero-title {
        font-size: 1.85rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.03em;
        line-height: 1.25;
        margin-bottom: 6px;
    }
    .hero-desc {
        font-size: 13.5px;
        color: #8b949e;
        line-height: 1.5;
        max-width: 800px;
    }
    .privacy-tag {
        font-size: 11.5px;
        color: #34d399;
        background: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.2);
        padding: 4px 10px;
        border-radius: 6px;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        border-bottom: 1px solid #161b26 !important;
        gap: 16px !important;
        background: transparent !important;
        margin-bottom: 20px !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8b949e !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        padding: 8px 16px !important;
        border: none !important;
        background: transparent !important;
        border-radius: 8px !important;
        transition: all 0.2s ease !important;
    }
    .stTabs [aria-selected="true"] {
        color: #ffffff !important;
        background: #111520 !important;
        border-bottom: 2px solid #00e5ff !important;
    }

    /* Workspace Cards */
    .card-head-title {
        font-size: 15px;
        font-weight: 700;
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .card-head-sub {
        font-size: 12px;
        color: #8b949e;
        margin-top: 2px;
        margin-bottom: 14px;
    }

    /* Empty State in Right Card */
    .empty-state-box {
        background: #090c12;
        border: 1px dashed #1c2638;
        border-radius: 12px;
        padding: 32px 24px;
        text-align: center;
        margin-top: 8px;
    }
    .empty-title {
        font-size: 16px;
        font-weight: 700;
        color: #ffffff;
        margin: 12px 0 6px 0;
    }
    .empty-desc {
        font-size: 12.5px;
        color: #8b949e;
        line-height: 1.6;
        max-width: 380px;
        margin: 0 auto 20px auto;
    }
    .empty-features {
        text-align: left;
        display: inline-block;
        font-size: 12.5px;
        color: #c9d1d9;
        line-height: 2;
        margin-bottom: 20px;
    }
    .empty-tip {
        background: rgba(0, 229, 255, 0.06);
        border: 1px solid rgba(0, 229, 255, 0.18);
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 12px;
        color: #8b949e;
        text-align: left;
    }

    /* Pricing Cards */
    .pricing-card {
        background: #0d1017;
        border: 1px solid #182030;
        border-radius: 14px;
        padding: 26px 22px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 340px;
        position: relative;
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .pricing-card-popular {
        border: 2px solid #00e5ff;
        background: #09121f;
        box-shadow: 0 0 30px rgba(0, 229, 255, 0.2);
    }
    .popular-pill {
        position: absolute;
        top: -12px;
        left: 50%;
        transform: translateX(-50%);
        background: #00e5ff;
        color: #000000;
        font-size: 10.5px;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 3px 12px;
        border-radius: 12px;
        box-shadow: 0 0 12px rgba(0, 229, 255, 0.5);
    }
    .card-tier-title {
        font-size: 13.5px;
        font-weight: 800;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }
    .card-tier-amt {
        font-size: 2.3rem;
        font-weight: 900;
        color: #ffffff;
        font-family: 'JetBrains Mono', monospace;
        margin: 8px 0 2px 0;
    }
    .card-tier-sub {
        font-size: 11.5px;
        color: #8b949e;
        margin-bottom: 16px;
    }
    .card-features-list {
        font-size: 12.5px;
        color: #c9d1d9;
        line-height: 1.85;
        text-align: left;
        margin-bottom: 20px;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 700 !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button[kind="primary"] {
        background-color: #00e5ff !important;
        color: #000000 !important;
        border: none !important;
        box-shadow: 0 0 15px rgba(0, 229, 255, 0.3) !important;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #33ebff !important;
        box-shadow: 0 0 22px rgba(0, 229, 255, 0.5) !important;
        transform: translateY(-1px) !important;
    }
    .stTextArea textarea {
        background: #06080d !important;
        border: 1px solid #182030 !important;
        color: #f0f6fc !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important;
        border-radius: 8px !important;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- TOP NAVBAR -----------------
logo_b64 = get_logo_base64()
if logo_b64:
    logo_tag = f'<img src="data:image/png;base64,{logo_b64}" class="brand-logo-img" alt="Kavach AI Logo" />'
else:
    logo_tag = '<span style="font-size:32px;">🛡️</span>'

if st.session_state.license_tier == PlanTier.TEAM_ENTERPRISE.value:
    badge_html = '<span class="plan-pill pill-team">● 👑 Team Active ($99/mo)</span>'
elif st.session_state.is_pro_user:
    badge_html = '<span class="plan-pill pill-pro">● ⚡ Developer Pro Active ($1/mo)</span>'
else:
    badge_html = '<span class="plan-pill pill-free">● 🆓 Community Free Active</span>'

nav_col1, nav_col2 = st.columns([2.0, 2.0])
with nav_col1:
    st.markdown(f"""
    <div class="brand-group">
        {logo_tag}
        <div>
            <div class="brand-title">Kavach AI <span class="brand-badge">v1.2.1 Secure</span></div>
            <div class="brand-sub">Autonomous Zero-Noise Code Security Inspector & 1-Click Surgical Patcher</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with nav_col2:
    nav_auth_col, nav_badge_col = st.columns([1.15, 0.85])
    with nav_auth_col:
        if st.session_state.github_user:
            u = st.session_state.github_user
            with st.popover(f"👤 @{u['login']}", use_container_width=True):
                st.markdown(f"""
                <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">
                    <img src="{u['avatar_url']}" style="width:44px; height:44px; border-radius:50%; border:2px solid #00e5ff;" />
                    <div>
                        <div style="font-weight:700; color:#fff; font-size:14.5px;">{html.escape(u['name'])}</div>
                        <div style="font-size:12px; color:#8b949e;">@{html.escape(u['login'])} • {u['public_repos']} Repos</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(badge_html, unsafe_allow_html=True)
                st.markdown("<div style='margin-top:12px;'></div>", unsafe_allow_html=True)
                st.button("🚪 Sign Out", key="btn_signout", on_click=logout_github, use_container_width=True)
        else:
            with st.popover("🐙 Sign in with GitHub", use_container_width=True):
                st.markdown("<div style='font-weight:700; font-size:14px; margin-bottom:4px;'>🐙 Connect GitHub Account</div>", unsafe_allow_html=True)
                st.caption("Link your GitHub handle to bind licenses and scan private repos.")
                st.text_input("GitHub Username:", key="input_gh_user", placeholder="e.g. rajrajak99")
                st.text_input("Personal Access Token (Optional):", key="input_gh_pat", type="password", placeholder="ghp_...")
                c_in1, c_in2 = st.columns(2)
                with c_in1:
                    st.button("⚡ Connect", key="btn_do_login", on_click=login_github, use_container_width=True)
                with c_in2:
                    st.button("👤 Demo Login", key="btn_demo_login", on_click=demo_login_github, use_container_width=True)
                if st.session_state.get("auth_error"):
                    st.error(st.session_state.auth_error)
    with nav_badge_col:
        st.markdown(f"""
        <div style="display:flex; justify-content:flex-end; align-items:center; height:100%; padding-top:4px;">
            {badge_html}
        </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='border-bottom: 1px solid #161b26; margin: 12px 0 20px 0;'></div>", unsafe_allow_html=True)

# ----------------- CLEAN 3-TAB SUITE -----------------
tab_scan, tab_pricing, tab_setup = st.tabs([
    "🔍 Scan Code (कोड स्कैन करें)",
    "💎 Plans & Licensing (सब्सक्रिप्शन प्लान्स - $0 / $1 / $99)",
    "🔌 GitHub Setup (गिटहब इंटीग्रेशन)"
])

# ================= TAB 1: CODE INSPECTOR WORKSPACE =================
SQL_SAMPLE = '''import sqlite3

def find_user(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
'''

with tab_scan:
    # Hero Title Bar
    st.markdown("""
    <div class="hero-box">
        <span class="hero-tag">🛡️ Security Workspace</span>
        <div class="hero-title">Inspect code before it reaches production.</div>
        <div class="hero-desc">Paste a snippet or run a committed scan. Search for pre-production patterns, secret leaks, and unsafe blocks with focused remediation.</div>
    </div>
    """, unsafe_allow_html=True)

    col_editor, col_result = st.columns([1.15, 1.15], gap="large")

    # LEFT PANEL: SOURCE TO INSPECT
    with col_editor:
        st.markdown("""
        <div class="card-head-title">
            <span>Sources to inspect</span>
            <span style="font-size:11px; color:#8b949e; font-family:'JetBrains Mono';">demo.py • UTF-8</span>
        </div>
        <div class="card-head-sub">Python, JavaScript, TypeScript, C++, or raw git diff format</div>
        """, unsafe_allow_html=True)

        # Quick Samples Bar
        c1, c2, c3 = st.columns([1.3, 1.3, 0.9])
        with c1:
            st.button("🔑 Secret leak", on_click=load_code_sample, args=(SAMPLE_PYTHON_MULTI,), use_container_width=True)
        with c2:
            st.button("💉 SQL injection", on_click=load_code_sample, args=(SQL_SAMPLE,), use_container_width=True)
        with c3:
            st.button("🧹 Clear", on_click=clear_code_box, use_container_width=True)

        st.markdown("<div style='margin-top:6px;'></div>", unsafe_allow_html=True)

        code_input = st.text_area(
            "Code Input:",
            key="user_code",
            height=330,
            label_visibility="collapsed",
            placeholder="// Paste code here to inspect for SQL injection, leaked keys, command injection, and more..."
        )

        inspect_btn = st.button("⚡ Inspect Code Now", type="primary", use_container_width=True)
        st.markdown("<div style='text-align:center; font-size:11.5px; color:#6e7681; margin-top:6px;'>🔒 No external servers contacted • Runs in local zero-trust sandbox</div>", unsafe_allow_html=True)

    # RUN ANALYSIS (CACHED)
    code_to_check = code_input.strip() if code_input else ""
    if code_to_check:
        analysis = analyze_code_cached(code_to_check)
        findings = analysis['findings']
        metrics = analysis['metrics']
    else:
        findings = []
        metrics = {'critical': 0, 'security': 0, 'performance': 0}

    # RIGHT PANEL: INSPECTION RESULT
    with col_result:
        status_label = "Awaiting scan" if not code_to_check else ("Clean" if not findings else f"{metrics['critical']} Critical / {metrics['security']} Security")
        st.markdown(f"""
        <div class="card-head-title">
            <span>Inspection result</span>
            <span style="font-size:11px; color:#00e5ff; background:rgba(0,229,255,0.1); padding:2px 8px; border-radius:12px; border:1px solid rgba(0,229,255,0.25); font-family:'JetBrains Mono';">{status_label}</span>
        </div>
        <div class="card-head-sub">Interactive findings & 1-click surgical remediation</div>
        """, unsafe_allow_html=True)

        if not code_to_check:
            st.markdown("""
            <div class="empty-state-box">
                <div style="font-size:36px;">🛡️</div>
                <div class="empty-title">Ready when your code is.</div>
                <div class="empty-desc">Paste a snippet on the left or choose a sample to see detected vulnerabilities, severity, and safe patches.</div>
                <div class="empty-features">
                    ✓ <b>Zero-noise signal filtering</b> (Ignores lockfiles & stylistic noise)<br>
                    ✓ <b>Direct-in-patch suggestions</b> (1-click surgical remediation)<br>
                    ✓ <b>Local data privacy</b> (Code never leaves your runner or browser)
                </div>
                <div class="empty-tip">
                    💡 <b>Or start with a sample:</b> Click <code>Secret leak</code> or <code>SQL injection</code> on the left to test a pre-loaded exploit.
                </div>
            </div>
            """, unsafe_allow_html=True)
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
                
                with st.expander(f"Issue #{i}: {cat_safe} ({f.severity}) • {cwe_safe}", expanded=True):
                    st.write(exp_safe)
                    c_sub1, c_sub2 = st.columns(2)
                    with c_sub1:
                        st.caption("❌ Vulnerable Code:")
                        st.code(f.problem_code, language=f.language)
                    with c_sub2:
                        st.caption("✅ 1-Click Surgical Patch:")
                        st.code(f.fixed_code, language=f.language)

                    st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
                    st.button(
                        f"🪄 1-Click Apply Patch to Code Box (कोड ऑटोमैटिक ठीक करें)",
                        key=f"btn_apply_fix_{i}",
                        type="primary",
                        on_click=apply_patch_to_editor,
                        args=(f.problem_code, f.fixed_code),
                        use_container_width=True
                    )

# ================= TAB 2: PRICING & LICENSING =================
with tab_pricing:
    st.markdown("""
    <div class="hero-box" style="text-align:center; max-width:750px; margin: 0 auto 20px auto;">
        <span class="hero-tag">💎 Simple, Transparent Licensing</span>
        <div class="hero-title">Secure every commit with Kavach AI.</div>
        <div class="hero-desc">Start free for public repositories, then unlock private repo remediation and team-wide protection when you need it.</div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.github_user:
        u = st.session_state.github_user
        st.markdown(f"""
        <div style="background: rgba(0, 229, 255, 0.08); border: 1px solid rgba(0, 229, 255, 0.25); border-radius: 10px; padding: 10px 16px; margin: 0 auto 20px auto; max-width: 750px; display:flex; align-items:center; gap:12px;">
            <img src="{u['avatar_url']}" style="width:34px; height:34px; border-radius:50%; border:1px solid #00e5ff;" />
            <div style="font-size:12.5px; color:#f0f6fc;">
                Subscribing as <b>{html.escape(u['name'])}</b> (<code>@{html.escape(u['login'])}</code>). All purchased licenses attach to this GitHub profile.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center; font-size:12px; color:#8b949e; margin: 0 auto 18px auto; max-width: 600px;">
            💡 <i>Tip: Click <b>🐙 Sign in with GitHub</b> in the top right to link your Developer Pro license to your account.</i>
        </div>
        """, unsafe_allow_html=True)

    is_free = (st.session_state.license_tier == PlanTier.FREE.value)
    is_pro = (st.session_state.license_tier == PlanTier.DEVELOPER_PRO.value)
    is_team = (st.session_state.license_tier == PlanTier.TEAM_ENTERPRISE.value)

    p1, p2, p3 = st.columns(3)

    # 1. COMMUNITY ($0)
    with p1:
        st.markdown(f"""
        <div class="pricing-card">
            <div>
                <div class="card-tier-title" style="color:#34d399;">🆓 Community</div>
                <div class="card-tier-amt">$0</div>
                <div class="card-tier-sub">Forever free for public repositories</div>
                <div class="card-features-list">
                    ✓ <b>Unlimited public repositories</b><br>
                    ✓ High-speed offline AST scanning<br>
                    ✓ Local CLI execution (<code>kavach .</code>)<br>
                    ✓ Free for students & open source<br>
                    ✓ Zero data retention
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "✅ Active Plan" if is_free else "🆓 Use Free Plan ($0)",
            key="btn_activate_free",
            disabled=is_free,
            on_click=select_plan,
            args=(PlanTier.FREE.value, "", False, "Community Free ($0)"),
            use_container_width=True
        )

    # 2. DEVELOPER PRO ($1) - MOST POPULAR
    with p2:
        st.markdown(f"""
        <div class="pricing-card pricing-card-popular">
            <div class="popular-pill">🔥 Most Popular</div>
            <div>
                <div class="card-tier-title" style="color:#00e5ff;">⚡ Developer Pro</div>
                <div class="card-tier-amt">$1<span style="font-size:14px; color:#8b949e;">/mo</span></div>
                <div class="card-tier-sub" style="color:#00e5ff; font-weight:700;">$12 Billed Annually • Independent devs</div>
                <div class="card-features-list">
                    ✓ <b>Up to 5 personal private repos</b><br>
                    ✓ 1-click surgical auto-remediations<br>
                    ✓ Local Git pre-commit hooks<br>
                    ✓ Personal GitHub account support<br>
                    ✓ Priority email updates
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "✅ Active Plan" if is_pro else "⚡ Select Developer Pro ($1)",
            key="btn_activate_pro",
            disabled=is_pro,
            type="primary" if not is_pro else "secondary",
            on_click=select_plan,
            args=(PlanTier.DEVELOPER_PRO.value, "BUILDER-DEV-1", True, "Developer Pro ($1/mo)"),
            use_container_width=True
        )

    # 3. TEAM ENTERPRISE ($99)
    with p3:
        st.markdown(f"""
        <div class="pricing-card">
            <div>
                <div class="card-tier-title" style="color:#fbbf24;">🏢 Team Enterprise</div>
                <div class="card-tier-amt">$99<span style="font-size:14px; color:#8b949e;">/mo</span></div>
                <div class="card-tier-sub">For startups & companies</div>
                <div class="card-features-list">
                    ✓ <b>GitHub Organizations support</b><br>
                    ✓ <b>Unlimited team repositories</b><br>
                    ✓ Autonomous PR review bot & blocker<br>
                    ✓ Pytest self-healing engine<br>
                    ✓ SLA support & custom rules
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "✅ Active Plan" if is_team else "🏢 Select Team Enterprise ($99)",
            key="btn_activate_team",
            disabled=is_team,
            on_click=select_plan,
            args=(PlanTier.TEAM_ENTERPRISE.value, "KV-TEAM-ORG-99", True, "Team Enterprise ($99/mo)"),
            use_container_width=True
        )

    # WIDE LICENSE ACTIVATION STRIP
    st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
    lk_col1, lk_col2, lk_col3 = st.columns([2, 1.8, 1])
    with lk_col1:
        st.markdown("""
        <div style="padding-top:6px;">
            <div style="font-size:14px; font-weight:700; color:#ffffff;">🔑 Already have a license key?</div>
            <div style="font-size:12px; color:#8b949e;">Enter your key to unlock developer or team features instantly.</div>
        </div>
        """, unsafe_allow_html=True)
    with lk_col2:
        st.text_input("License Key:", key="custom_key_input", placeholder="e.g. BUILDER-DEV-1 or KV-TEAM-ORG-99", label_visibility="collapsed")
    with lk_col3:
        st.button("⚡ Activate License", key="btn_activate_key", on_click=activate_custom_key, use_container_width=True)

    if st.session_state.get("key_feedback"):
        status, msg = st.session_state.key_feedback
        if status == "success":
            st.success(msg)
        else:
            st.error(msg)

    st.markdown("""
    <div style="text-align:center; font-size:12px; color:#6e7681; margin-top:24px;">
        Need help choosing? Kavach AI runs 100% locally with zero cloud compute cost for Raja Rajak.
    </div>
    """, unsafe_allow_html=True)

# ================= TAB 3: GITHUB SETUP =================
with tab_setup:
    st.markdown("""
    <div class="hero-box">
        <span class="hero-tag">🔌 CI / CD Integration</span>
        <div class="hero-title">1-Minute GitHub Actions Security Gate</div>
        <div class="hero-desc">Protect your GitHub repository from bad code and vulnerabilities automatically before merges.</div>
    </div>
    """, unsafe_allow_html=True)

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
