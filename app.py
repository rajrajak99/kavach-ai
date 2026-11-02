import sys
import os
from pathlib import Path

# Explicitly ensure repository root is at index 0 of sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
import requests
import html
import base64

from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer
from core.ai_reasoner import AIReasoner
from kavach_license import LicenseManager, PlanTier
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
        st.session_state.toast_msg = f"Connected as @{profile['login']}!"
    else:
        st.session_state.auth_error = profile.get("error", "GitHub user not found.")

def demo_login_github():
    profile = fetch_github_profile("rajrajak99")
    if profile.get("success"):
        st.session_state.github_user = profile
        st.session_state.auth_error = None
        st.session_state.toast_msg = "Signed in as Founder @rajrajak99"

def logout_github():
    st.session_state.github_user = None
    st.session_state.auth_error = None
    st.session_state.toast_msg = "Logged out of GitHub."

# ----------------- CALLBACKS -----------------
def select_plan(tier_val: str, plan_name: str):
    user_handle = st.session_state.github_user['login'] if st.session_state.github_user else "local-builder"
    key_val = ""
    if tier_val == PlanTier.DEVELOPER_PRO.value:
        try:
            from scripts.mint_license import mint_license
            key_val = mint_license(tier="pro", subject=user_handle, days=365)
        except Exception:
            key_val = "KV-PRO-INDIE"
        st.session_state.is_pro_user = True
    elif tier_val == PlanTier.TEAM_ENTERPRISE.value:
        try:
            from scripts.mint_license import mint_license
            key_val = mint_license(tier="team", subject=user_handle, days=365)
        except Exception:
            key_val = "KV-TEAM-ORG"
        st.session_state.is_pro_user = True
    else:
        key_val = ""
        st.session_state.is_pro_user = False

    st.session_state.license_tier = tier_val
    st.session_state.license_key = key_val
    st.session_state.toast_msg = f"{plan_name} Active!"

def activate_custom_key():
    key = st.session_state.get("custom_key_input", "").strip()
    if not key:
        st.session_state.key_feedback = ("error", "Please enter a license key.")
        return
    tier = LicenseManager.get_tier_for_key(key)
    if tier:
        st.session_state.license_tier = tier.value
        st.session_state.license_key = key
        st.session_state.is_pro_user = (tier != PlanTier.FREE)
        st.session_state.key_feedback = ("success", f"Verified: {tier.value} Activated!")
        st.session_state.toast_msg = f"Verified: {tier.value}"
    else:
        st.session_state.key_feedback = ("error", "Invalid or expired key! Must be an authentic Ed25519 token or LemonSqueezy key.")

def load_code_sample(code: str):
    st.session_state.user_code = code

def clear_code_box():
    st.session_state.user_code = ""

def apply_patch_to_editor(problem_code: str, fixed_code: str):
    current = st.session_state.get("user_code", "")
    if problem_code in current:
        st.session_state.user_code = current.replace(problem_code, fixed_code)
        st.session_state.toast_msg = "Patch Applied! Code is now secure."
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
            st.session_state.toast_msg = "Patch Applied! Code is now secure."

if st.session_state.get("toast_msg"):
    st.toast(st.session_state.toast_msg)
    st.session_state.toast_msg = None

# ----------------- MONOCHROME ZINC SYSTEM & LINEAR/VERCEL CSS -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* 1. Global Reset & Typography */
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        color: #EDEDED !important;
        background-color: #09090B !important;
    }
    .stApp {
        background-color: #09090B !important;
    }

    /* 2. Hide Streamlit Boilerplate Chrome & Restrict to 100vh */
    #MainMenu { visibility: hidden !important; display: none !important; }
    header[data-testid="stHeader"] { display: none !important; }
    footer { visibility: hidden !important; display: none !important; }

    .block-container {
        padding-top: 1.1rem !important;
        padding-bottom: 0.8rem !important;
        padding-left: 1.25rem !important;
        padding-right: 1.25rem !important;
        max-width: 1380px !important;
    }

    /* 3. Top Navbar (Compact Single-Row Container) */
    .brand-wrap {
        display: flex;
        align-items: center;
        gap: 9px;
    }
    .brand-logo-img {
        width: 24px;
        height: 24px;
        border-radius: 6px;
        object-fit: cover;
        border: 1px solid rgba(255, 255, 255, 0.14);
    }
    .brand-title {
        font-size: 14px;
        font-weight: 600;
        color: #FAFAFA;
        letter-spacing: -0.01em;
        display: flex;
        align-items: center;
        gap: 7px;
    }
    .brand-pill {
        font-size: 10.5px;
        font-weight: 500;
        color: #A1A1AA;
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 1px 6px;
        border-radius: 10px;
        font-family: 'JetBrains Mono', monospace;
    }
    .plan-pill {
        font-size: 11px;
        font-weight: 500;
        padding: 3px 9px;
        border-radius: 12px;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.02em;
        display: inline-flex;
        align-items: center;
        gap: 5px;
    }
    .pill-free {
        color: #A1A1AA;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .pill-pro {
        color: #FAFAFA;
        background: rgba(255, 255, 255, 0.12);
        border: 1px solid rgba(255, 255, 255, 0.22);
    }
    .pill-team {
        color: #FBBF24;
        background: rgba(245, 158, 11, 0.1);
        border: 1px solid rgba(245, 158, 11, 0.22);
    }

    /* 4. Linear Segmented Control Tabs */
    div[data-testid="stSegmentedControl"] {
        background: #121214 !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
        padding: 2px !important;
    }
    div[data-testid="stSegmentedControl"] button {
        background: transparent !important;
        color: #A1A1AA !important;
        font-size: 12.5px !important;
        font-weight: 500 !important;
        border-radius: 6px !important;
        border: none !important;
        padding: 3px 14px !important;
        height: 28px !important;
        min-height: 28px !important;
        transition: all 0.15s ease !important;
    }
    div[data-testid="stSegmentedControl"] button:hover {
        color: #EDEDED !important;
    }
    div[data-testid="stSegmentedControl"] button[aria-checked="true"] {
        background: #27272A !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25) !important;
    }

    /* 5. Linear Crisp High-Contrast White Primary & Secondary Buttons */
    div[data-testid="stButton"] > button[kind="primary"] {
        background: #FAFAFA !important;
        color: #09090B !important;
        font-weight: 600 !important;
        font-size: 12.5px !important;
        height: 36px !important;
        min-height: 36px !important;
        padding: 0 14px !important;
        border-radius: 6px !important;
        border: none !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25) !important;
        transition: all 0.15s ease !important;
    }
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: #E4E4E7 !important;
        color: #09090B !important;
    }
    div[data-testid="stButton"] > button[kind="secondary"] {
        background: #18181B !important;
        color: #D4D4D8 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        font-size: 12px !important;
        height: 36px !important;
        min-height: 36px !important;
        border-radius: 6px !important;
        transition: all 0.15s ease !important;
    }
    div[data-testid="stButton"] > button[kind="secondary"]:hover {
        background: #27272A !important;
        color: #FFFFFF !important;
        border-color: rgba(255, 255, 255, 0.2) !important;
    }

    /* GitHub Popover Button */
    div[data-testid="stPopover"] > button {
        background: #18181B !important;
        color: #D4D4D8 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        font-size: 11.5px !important;
        height: 30px !important;
        min-height: 30px !important;
        border-radius: 6px !important;
        padding: 0 10px !important;
    }
    div[data-testid="stPopover"] > button:hover {
        background: #27272A !important;
        color: #FFFFFF !important;
    }

    /* 6. IDE Code Editor Card */
    .ide-tab-label {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        font-family: 'JetBrains Mono', monospace;
        color: #D4D4D8;
        background: #121214;
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 4px 10px;
        border-radius: 6px;
        height: 36px;
        box-sizing: border-box;
    }
    .ide-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #10B981;
    }
    .ide-meta {
        color: #71717A;
        font-size: 11px;
    }

    div[data-testid="stTextArea"] textarea {
        background: #0C0D0F !important;
        color: #E4E4E7 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 12px !important;
        line-height: 1.55 !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
        padding: 10px 12px !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: rgba(255, 255, 255, 0.22) !important;
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.08) !important;
    }

    /* 7. Diagnostic Container (440px Match) */
    div[data-testid="stVerticalBlock"]:has(> div[data-testid="stContainer"]) {
        gap: 0 !important;
    }
    div[data-testid="stContainer"] {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
        background: #0C0D0F !important;
    }

    /* Minimal Terminal Empty State */
    .terminal-empty-box {
        background: #121214;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 14px 16px;
        font-family: 'JetBrains Mono', monospace;
    }
    .terminal-bar {
        display: flex;
        align-items: center;
        gap: 6px;
        padding-bottom: 10px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        margin-bottom: 10px;
    }
    .term-dot {
        width: 9px;
        height: 9px;
        border-radius: 50%;
    }
    .term-dot.red { background: #EF4444; opacity: 0.8; }
    .term-dot.yellow { background: #F59E0B; opacity: 0.8; }
    .term-dot.green { background: #10B981; opacity: 0.8; }
    .term-title {
        color: #71717A;
        font-size: 11px;
        margin-left: 6px;
    }
    .term-body {
        font-size: 11.5px;
        line-height: 1.65;
    }
    .term-line {
        color: #D4D4D8;
    }
    .term-prompt {
        color: #10B981;
        font-weight: 600;
        margin-right: 6px;
    }
    .term-line.muted {
        color: #71717A;
        font-size: 11px;
    }
    .term-line.success {
        color: #34D399;
        margin-top: 6px;
    }
    .term-line.info {
        color: #60A5FA;
        font-size: 11px;
        margin-top: 4px;
    }

    /* Diagnostics Banners & Expander Cards */
    .diag-banner {
        border-radius: 6px;
        padding: 7px 11px;
        font-size: 12px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .diag-blocked {
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid rgba(239, 68, 68, 0.28);
        color: #F87171;
    }
    .diag-warning {
        background: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.28);
        color: #FBBF24;
    }
    .diag-clean {
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.28);
        color: #34D399;
    }

    div[data-testid="stExpander"] {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 6px !important;
        background: #121214 !important;
        margin-bottom: 7px !important;
    }
    div[data-testid="stExpander"] summary {
        font-size: 12px !important;
        font-weight: 600 !important;
        padding: 5px 8px !important;
    }

    /* 8. Pricing Cards */
    .pricing-card {
        background: #121214;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 20px 18px;
        position: relative;
    }
    .pricing-card-popular {
        border-color: rgba(255, 255, 255, 0.22);
        background: #16161A;
    }
    .popular-pill {
        position: absolute;
        top: 12px;
        right: 14px;
        font-size: 10px;
        font-weight: 600;
        background: #FAFAFA;
        color: #09090B;
        padding: 2px 7px;
        border-radius: 10px;
    }
    .card-tier-title {
        font-size: 14px;
        font-weight: 600;
        color: #FAFAFA;
        margin-bottom: 4px;
    }
    .card-tier-amt {
        font-size: 1.9rem;
        font-weight: 700;
        color: #FFFFFF;
        letter-spacing: -0.02em;
        margin-bottom: 2px;
    }
    .card-tier-sub {
        font-size: 11.5px;
        color: #71717A;
        margin-bottom: 12px;
    }
    .card-features-list {
        font-size: 12px;
        line-height: 1.75;
        color: #D4D4D8;
    }
</style>
""", unsafe_allow_html=True)

# ----------------- COMPACT SINGLE-ROW TOP NAVBAR -----------------
logo_b64 = get_logo_base64()
if logo_b64:
    logo_tag = f'<img src="data:image/png;base64,{logo_b64}" class="brand-logo-img" alt="Logo" />'
else:
    logo_tag = '<span style="font-size:18px;">🛡️</span>'

if st.session_state.license_tier == PlanTier.TEAM_ENTERPRISE.value:
    badge_html = '<span class="plan-pill pill-team">● 👑 Team ($99/mo)</span>'
elif st.session_state.is_pro_user:
    badge_html = '<span class="plan-pill pill-pro">● ⚡ Pro ($1/mo)</span>'
else:
    badge_html = '<span class="plan-pill pill-free">● 🆓 Free</span>'

nav_col1, nav_col2, nav_col3 = st.columns([1.1, 1.25, 1.35], gap="small", vertical_alignment="center")

with nav_col1:
    st.markdown(f"""
    <div class="brand-wrap">
        {logo_tag}
        <span class="brand-title">Kavach AI <span class="brand-pill">v1.3.0</span></span>
    </div>
    """, unsafe_allow_html=True)

with nav_col2:
    active_tab = st.segmented_control(
        "Navigation",
        ["Inspector", "Pricing", "GitHub"],
        default="Inspector",
        label_visibility="collapsed",
        key="main_nav_tab"
    ) or "Inspector"

with nav_col3:
    auth_subcol1, auth_subcol2 = st.columns([1.1, 1.0], gap="small", vertical_alignment="center")
    with auth_subcol1:
        if st.session_state.github_user:
            u = st.session_state.github_user
            with st.popover(f"👤 @{u['login']}", use_container_width=True):
                st.markdown(f"""
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                    <img src="{u['avatar_url']}" style="width:36px; height:36px; border-radius:50%; border:1px solid #FAFAFA;" />
                    <div>
                        <div style="font-weight:600; color:#fff; font-size:13px;">{html.escape(u['name'])}</div>
                        <div style="font-size:11px; color:#A1A1AA;">@{html.escape(u['login'])} • {u['public_repos']} Repos</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(badge_html, unsafe_allow_html=True)
                st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
                st.button("🚪 Sign Out", key="btn_signout", on_click=logout_github, use_container_width=True)
        else:
            with st.popover("🐙 Sign in", use_container_width=True):
                st.markdown("<div style='font-weight:600; font-size:12.5px; margin-bottom:3px;'>GitHub Identity</div>", unsafe_allow_html=True)
                st.caption("Link username to bind licenses.")
                st.text_input("Username:", key="input_gh_user", placeholder="e.g. rajrajak99")
                st.text_input("Token (Optional):", key="input_gh_pat", type="password", placeholder="ghp_...")
                c_in1, c_in2 = st.columns(2)
                with c_in1:
                    st.button("Connect", key="btn_do_login", on_click=login_github, use_container_width=True)
                with c_in2:
                    st.button("Demo", key="btn_demo_login", on_click=demo_login_github, use_container_width=True)
                if st.session_state.get("auth_error"):
                    st.error(st.session_state.auth_error)
    with auth_subcol2:
        st.markdown(f"""
        <div style="display:flex; justify-content:flex-end; align-items:center; height:100%;">
            {badge_html}
        </div>
        """, unsafe_allow_html=True)

st.markdown("<div style='border-bottom: 1px solid rgba(255, 255, 255, 0.08); margin: 6px 0 12px 0;'></div>", unsafe_allow_html=True)

SQL_SAMPLE = '''import sqlite3

def find_user(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()
'''

# ================= TAB 1: GOLDEN RATIO CODE INSPECTOR =================
if active_tab == "Inspector":
    col_editor, col_result = st.columns([1.45, 1.0], gap="medium")

    # RUN ANALYSIS (CACHED)
    current_code = st.session_state.get("user_code", "").strip()
    if current_code:
        analysis = analyze_code_cached(current_code)
        findings = analysis['findings']
        metrics = analysis['metrics']
    else:
        findings = []
        metrics = {'critical': 0, 'security': 0, 'performance': 0}

    # LEFT COLUMN: 60% CODE EDITOR
    with col_editor:
        # IDE Header Bar
        tb_col1, tb_col2, tb_col3 = st.columns([1.0, 1.7, 1.3], gap="small", vertical_alignment="center")
        with tb_col1:
            st.markdown("""
            <div class="ide-tab-label">
                <span class="ide-dot"></span>
                <span>demo.py</span>
                <span class="ide-meta">UTF-8</span>
            </div>
            """, unsafe_allow_html=True)
        with tb_col2:
            q1, q2, q3 = st.columns([1.0, 1.2, 0.8], gap="small")
            with q1:
                st.button("🔑 Secrets", on_click=load_code_sample, args=(SAMPLE_PYTHON_MULTI,), key="btn_sec", use_container_width=True)
            with q2:
                st.button("💉 SQLi", on_click=load_code_sample, args=(SQL_SAMPLE,), key="btn_sqli", use_container_width=True)
            with q3:
                st.button("🧹 Clear", on_click=clear_code_box, key="btn_clr", use_container_width=True)
        with tb_col3:
            st.button("Inspect Code ⌘↵", key="btn_inspect_code", type="primary", use_container_width=True)

        code_input = st.text_area(
            "Code Input:",
            key="user_code",
            height=440,
            label_visibility="collapsed",
            placeholder="// Paste code here or click Secrets / SQLi above to inspect..."
        )

    # RIGHT COLUMN: 40% DIAGNOSTIC INSPECTOR
    with col_result:
        # Diagnostic Header Bar
        r_head1, r_head2 = st.columns([1.2, 1.8], gap="small", vertical_alignment="center")
        with r_head1:
            status_text = "Awaiting Scan" if not current_code else ("Clean" if not findings else f"{len(findings)} Issue(s)")
            st.markdown(f"""
            <div class="ide-tab-label">
                <span>Diagnostics</span>
                <span class="ide-meta">• {status_text}</span>
            </div>
            """, unsafe_allow_html=True)
        with r_head2:
            if findings:
                crit_badge = f'<span style="color:#F87171; font-weight:600;">{metrics["critical"]} Crit</span>'
                sec_badge = f'<span style="color:#FBBF24; font-weight:600;">{metrics["security"]} Sec</span>'
                perf_badge = f'<span style="color:#60A5FA; font-weight:600;">{metrics["performance"]} Perf</span>'
                st.markdown(f"<div style='text-align:right; font-size:11.5px; font-family:\"JetBrains Mono\"; padding-top:6px;'>{crit_badge} • {sec_badge} • {perf_badge}</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='text-align:right; font-size:11.5px; color:#71717A; font-family:\"JetBrains Mono\"; padding-top:6px;'>Zero Noise</div>", unsafe_allow_html=True)

        # 440px Matched Height Container
        with st.container(height=440):
            if not current_code:
                st.markdown("""
                <div class="terminal-empty-box">
                    <div class="terminal-bar">
                        <span class="term-dot red"></span>
                        <span class="term-dot yellow"></span>
                        <span class="term-dot green"></span>
                        <span class="term-title">kavach-engine — ready</span>
                    </div>
                    <div class="term-body">
                        <div class="term-line"><span class="term-prompt">$</span>kavach inspect --mode=zero-noise</div>
                        <div class="term-line muted">AST Parser: initialized (Python 3.14, JS, C++)</div>
                        <div class="term-line muted">Taint Flow: active (Intra-procedural tracking)</div>
                        <div class="term-line muted">Constant Folding: active (CWE-798 resolver)</div>
                        <div class="term-line success">✓ Engine idle. Ready when your code is.</div>
                        <div class="term-line info">ℹ Select 'Secrets' or 'SQLi' above to test.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            elif not findings:
                st.markdown("""
                <div class="diag-banner diag-clean">
                    <span>🟢</span>
                    <div><b>CLEAN - READY TO MERGE</b><br><span style="font-size:11.5px;">Zero security vulnerabilities or resource leaks detected in this code.</span></div>
                </div>
                """, unsafe_allow_html=True)
            else:
                if metrics['critical'] > 0:
                    st.markdown(f"""
                    <div class="diag-banner diag-blocked">
                        <span>🔴</span>
                        <div><b>MERGE BLOCKED</b> • {metrics['critical']} Critical Exploit(s) Detected</div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="diag-banner diag-warning">
                        <span>🟠</span>
                        <div><b>SECURITY WARNING</b> • {metrics['security']} Vulnerability/Leak(s) Detected</div>
                    </div>
                    """, unsafe_allow_html=True)

                for i, f in enumerate(findings, 1):
                    cat_safe = html.escape(f.category)
                    exp_safe = html.escape(f.explanation)
                    cwe_safe = html.escape(f.cwe_id or "CWE-General")

                    with st.expander(f"L{f.line_number} [{f.severity}] {cat_safe} • {cwe_safe}", expanded=(i <= 2)):
                        st.markdown(f"<div style='font-size:12px; color:#A1A1AA; margin-bottom:8px;'>{exp_safe}</div>", unsafe_allow_html=True)
                        c_sub1, c_sub2 = st.columns(2)
                        with c_sub1:
                            st.caption("❌ Current:")
                            st.code(f.problem_code, language=f.language)
                        with c_sub2:
                            st.caption("✅ Patch:")
                            st.code(f.fixed_code, language=f.language)

                        st.button(
                            f"🪄 Apply Patch #{i}",
                            key=f"btn_apply_fix_{i}",
                            type="primary",
                            on_click=apply_patch_to_editor,
                            args=(f.problem_code, f.fixed_code),
                            use_container_width=True
                        )

# ================= TAB 2: PRICING & LICENSING =================
elif active_tab == "Pricing":
    is_free = (st.session_state.license_tier == PlanTier.FREE.value)
    is_pro = (st.session_state.license_tier == PlanTier.DEVELOPER_PRO.value)
    is_team = (st.session_state.license_tier == PlanTier.TEAM_ENTERPRISE.value)

    p1, p2, p3 = st.columns(3)

    # 1. COMMUNITY ($0)
    with p1:
        st.markdown("""
        <div class="pricing-card">
            <div class="card-tier-title" style="color:#34D399;">Community</div>
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
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_free else "Use Free Plan ($0)",
            key="btn_activate_free",
            disabled=is_free,
            on_click=select_plan,
            args=(PlanTier.FREE.value, "Community Free ($0)"),
            use_container_width=True
        )

    # 2. DEVELOPER PRO ($1)
    with p2:
        st.markdown("""
        <div class="pricing-card pricing-card-popular">
            <div class="popular-pill">Most Popular</div>
            <div class="card-tier-title" style="color:#FAFAFA;">Developer Pro</div>
            <div class="card-tier-amt">$1<span style="font-size:14px; color:#71717A;">/mo</span></div>
            <div class="card-tier-sub">$12 billed annually • Independent devs</div>
            <div class="card-features-list">
                ✓ <b>Up to 5 personal private repos</b><br>
                ✓ Cryptographic signed token verification<br>
                ✓ 1-click surgical auto-remediations<br>
                ✓ Local Git pre-commit hooks<br>
                ✓ Priority email updates
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_pro else "Select Developer Pro ($1)",
            key="btn_activate_pro",
            disabled=is_pro,
            type="primary" if not is_pro else "secondary",
            on_click=select_plan,
            args=(PlanTier.DEVELOPER_PRO.value, "Developer Pro ($1/mo)"),
            use_container_width=True
        )

    # 3. TEAM ENTERPRISE ($99)
    with p3:
        st.markdown("""
        <div class="pricing-card">
            <div class="card-tier-title" style="color:#FBBF24;">Team Enterprise</div>
            <div class="card-tier-amt">$99<span style="font-size:14px; color:#71717A;">/mo</span></div>
            <div class="card-tier-sub">For startups & GitHub Organizations</div>
            <div class="card-features-list">
                ✓ <b>GitHub Organizations support</b><br>
                ✓ <b>Unlimited team repositories</b><br>
                ✓ Autonomous PR review bot & blocker<br>
                ✓ Pytest self-healing engine<br>
                ✓ SLA support & custom rules
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_team else "Select Team Enterprise ($99)",
            key="btn_activate_team",
            disabled=is_team,
            on_click=select_plan,
            args=(PlanTier.TEAM_ENTERPRISE.value, "Team Enterprise ($99/mo)"),
            use_container_width=True
        )

    # LICENSE ACTIVATION STRIP
    st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
    lk_col1, lk_col2, lk_col3 = st.columns([2, 1.8, 1])
    with lk_col1:
        st.markdown("""
        <div style="padding-top:4px;">
            <div style="font-size:13.5px; font-weight:600; color:#FAFAFA;">🔑 Activate Customer License Key</div>
            <div style="font-size:11.5px; color:#71717A;">Supports LemonSqueezy license keys or offline signed Ed25519 tokens.</div>
        </div>
        """, unsafe_allow_html=True)
    with lk_col2:
        st.text_input("License Key:", key="custom_key_input", placeholder="LemonSqueezy UUID or KAVACH-PRO-... token", label_visibility="collapsed")
    with lk_col3:
        st.button("Activate Key", key="btn_activate_key", type="primary", on_click=activate_custom_key, use_container_width=True)

    if st.session_state.get("key_feedback"):
        status, msg = st.session_state.key_feedback
        if status == "success":
            st.success(msg)
        else:
            st.error(msg)

# ================= TAB 3: GITHUB SETUP =================
elif active_tab == "GitHub":
    st.markdown("""
    <div style="margin-bottom:12px;">
        <div style="font-size:14px; font-weight:600; color:#FAFAFA;">1-Minute GitHub Actions Security Gate</div>
        <div style="font-size:12px; color:#71717A;">Block vulnerable pull requests before they reach your production branch.</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("Create `.github/workflows/kavach.yml` in your repository:")
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
        uses: rajrajak99/kavach-ai@v1.3.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: 'CRITICAL'
''', language="yaml")

    st.markdown("#### 📦 Run Locally via Terminal:")
    st.code("pip install --upgrade kavach-ai\nkavach .", language="bash")
