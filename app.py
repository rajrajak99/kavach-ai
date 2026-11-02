"""
Kavach AI - Autonomous AST Code Security Inspector & 1-Click Surgical Patcher
Billion-Dollar SaaS Design: Electric Violet (#7C6CFF) + Matte Near-Black (#07070A)
"""

import streamlit as st
import html
import base64
import os
import requests
from kavach_license import PlanTier, LicenseManager
from core.surgical_analyzer import SurgicalAnalyzer
from core.diff_parser import DiffParser
from samples.vulnerable_samples import SAMPLE_PYTHON_MULTI

# ----------------- STREAMLIT PAGE CONFIG -----------------
st.set_page_config(
    page_title="Kavach AI — Autonomous Code Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ----------------- CACHED STATIC ASSETS & ENGINES -----------------
@st.cache_data
def get_logo_base64():
    p = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
    if os.path.exists(p):
        with open(p, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    return ""

@st.cache_resource
def get_analyzer():
    return SurgicalAnalyzer()

@st.cache_resource
def get_parser():
    return DiffParser()

@st.cache_data(ttl=3600)
def analyze_code_cached(code_str: str):
    analyzer = get_analyzer()
    parser = get_parser()
    diffs = []
    if "diff --git" in code_str or "@@" in code_str:
        diffs = parser.parse_git_diff(code_str)
    if not diffs:
        sn_name = "snippet.py"
        if "function " in code_str or "const " in code_str or "var " in code_str:
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
    # Pre-populate demo code so first-time visitors immediately see the engine in action
    st.session_state.user_code = SAMPLE_PYTHON_MULTI
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

# ----------------- BILLION-DOLLAR SAAS CSS (ELECTRIC VIOLET) -----------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* 1. Global Reset & Theme Variables */
    :root {
        --bg-main: #07070A;
        --bg-surface: #0F0F14;
        --border-subtle: #1E1E28;
        --border-hover: rgba(124, 108, 255, 0.4);
        --accent: #7C6CFF;
        --accent-hover: #6A59F0;
        --accent-glow: rgba(124, 108, 255, 0.16);
        --text-primary: #EDEDF2;
        --text-muted: #8A8A99;
        --pass: #3DDC97;
        --vuln: #FF5C6C;
        --warn: #FFB454;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: #EDEDF2 !important;
        background-color: #07070A !important;
    }
    .stApp {
        background-color: #07070A !important;
    }

    /* 2. Absolute Removal of Streamlit Boilerplate & Glitch Lines */
    [data-testid="stDecoration"],
    [data-testid="stHeader"],
    header[data-testid="stHeader"],
    header,
    div[data-testid="stToolbar"] {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
        min-height: 0 !important;
        max-height: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        background: transparent !important;
    }
    #MainMenu, footer {
        display: none !important;
        visibility: hidden !important;
    }

    .block-container {
        padding-top: 1.25rem !important;
        padding-bottom: 2rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        max-width: 1260px !important;
        margin: 0 auto !important;
    }

    /* 3. Single-Row Navbar Container */
    .brand-wrap {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .brand-logo-img {
        width: 26px;
        height: 26px;
        border-radius: 7px;
        object-fit: cover;
        border: 1px solid rgba(255, 255, 255, 0.12);
    }
    .brand-title {
        font-size: 15px;
        font-weight: 600;
        color: #EDEDF2;
        letter-spacing: -0.02em;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .brand-pill {
        font-size: 10.5px;
        font-weight: 500;
        color: #7C6CFF;
        background: rgba(124, 108, 255, 0.12);
        border: 1px solid rgba(124, 108, 255, 0.25);
        padding: 1px 7px;
        border-radius: 99px;
        font-family: 'JetBrains Mono', monospace;
    }
    .plan-pill {
        font-size: 11px;
        font-weight: 500;
        padding: 4px 10px;
        border-radius: 99px;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.02em;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        white-space: nowrap;
    }
    .pill-free {
        color: #8A8A99;
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid #1E1E28;
    }
    .pill-pro {
        color: #7C6CFF;
        background: rgba(124, 108, 255, 0.12);
        border: 1px solid rgba(124, 108, 255, 0.3);
    }
    .pill-team {
        color: #7C6CFF;
        background: rgba(124, 108, 255, 0.18);
        border: 1px solid #7C6CFF;
        box-shadow: 0 0 15px rgba(124, 108, 255, 0.2);
    }

    /* 4. Segmented Control Navbar */
    div[data-testid="stSegmentedControl"] {
        background: #0F0F14 !important;
        border: 1px solid #1E1E28 !important;
        border-radius: 10px !important;
        padding: 3px !important;
    }
    div[data-testid="stSegmentedControl"] button {
        background: transparent !important;
        color: #8A8A99 !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        border-radius: 7px !important;
        border: none !important;
        padding: 4px 16px !important;
        height: 30px !important;
        min-height: 30px !important;
        transition: all 0.18s ease !important;
    }
    div[data-testid="stSegmentedControl"] button:hover {
        color: #EDEDF2 !important;
    }
    div[data-testid="stSegmentedControl"] button[aria-checked="true"] {
        background: #1E1E28 !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.35) !important;
    }

    /* 5. Buttons & Inputs */
    div[data-testid="stButton"] button {
        white-space: nowrap !important;
        text-overflow: clip !important;
        overflow: visible !important;
    }
    div[data-testid="stButton"] > button[kind="primary"] {
        background: #7C6CFF !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        height: 36px !important;
        min-height: 36px !important;
        padding: 0 16px !important;
        border-radius: 8px !important;
        border: none !important;
        box-shadow: 0 0 20px rgba(124, 108, 255, 0.25) !important;
        transition: all 0.18s ease !important;
    }
    div[data-testid="stButton"] > button[kind="primary"]:hover {
        background: #6A59F0 !important;
        box-shadow: 0 0 28px rgba(124, 108, 255, 0.4) !important;
        transform: translateY(-1px);
    }
    div[data-testid="stButton"] > button[kind="secondary"] {
        background: #0F0F14 !important;
        color: #EDEDF2 !important;
        border: 1px solid #1E1E28 !important;
        font-size: 12px !important;
        font-weight: 500 !important;
        height: 36px !important;
        min-height: 36px !important;
        border-radius: 8px !important;
        padding: 0 12px !important;
        transition: all 0.18s ease !important;
    }
    div[data-testid="stButton"] > button[kind="secondary"]:hover {
        background: #161620 !important;
        border-color: rgba(124, 108, 255, 0.4) !important;
        color: #FFFFFF !important;
    }

    /* GitHub Popover Button */
    div[data-testid="stPopover"] > button {
        background: #0F0F14 !important;
        color: #EDEDF2 !important;
        border: 1px solid #1E1E28 !important;
        font-size: 12px !important;
        height: 32px !important;
        min-height: 32px !important;
        border-radius: 8px !important;
        padding: 0 12px !important;
        transition: all 0.18s ease !important;
    }
    div[data-testid="stPopover"] > button:hover {
        background: #161620 !important;
        border-color: rgba(124, 108, 255, 0.4) !important;
        color: #FFFFFF !important;
    }

    /* 6. Hero & Positioning Banner */
    .hero-container {
        text-align: center;
        padding: 20px 0 18px 0;
        margin-bottom: 12px;
    }
    .hero-heading {
        font-size: 25px;
        font-weight: 700;
        letter-spacing: -0.025em;
        color: #EDEDF2;
        margin-bottom: 6px;
    }
    .hero-lead {
        font-size: 13.5px;
        color: #8A8A99;
        max-width: 620px;
        margin: 0 auto 12px auto;
        line-height: 1.5;
    }
    .trust-strip {
        display: inline-flex;
        align-items: center;
        gap: 12px;
        font-size: 11.5px;
        color: #8A8A99;
        background: #0F0F14;
        border: 1px solid #1E1E28;
        padding: 5px 16px;
        border-radius: 99px;
    }
    .trust-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #3DDC97;
        box-shadow: 0 0 6px rgba(61, 220, 151, 0.6);
        display: inline-block;
    }
    .trust-sep {
        color: #272732;
    }
    .trust-link {
        color: #7C6CFF;
        text-decoration: none;
        font-weight: 500;
        transition: color 0.15s;
    }
    .trust-link:hover {
        color: #9D91FF;
        text-decoration: underline;
    }

    /* 7. Code Editor & Diagnostics Toolbars */
    .ide-tab-label {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        font-size: 12px;
        font-family: 'JetBrains Mono', monospace;
        color: #EDEDF2;
        background: #0F0F14;
        border: 1px solid #1E1E28;
        padding: 4px 12px;
        border-radius: 8px;
        height: 36px;
        box-sizing: border-box;
        white-space: nowrap !important;
    }
    .ide-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #3DDC97;
        box-shadow: 0 0 6px rgba(61, 220, 151, 0.6);
    }
    .ide-meta {
        color: #8A8A99;
        font-size: 11.5px;
    }

    div[data-testid="stTextArea"] textarea {
        background: #0A0A0F !important;
        color: #EDEDF2 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 12.5px !important;
        line-height: 1.6 !important;
        border: 1px solid #1E1E28 !important;
        border-radius: 10px !important;
        padding: 12px 14px !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #7C6CFF !important;
        box-shadow: 0 0 0 1px rgba(124, 108, 255, 0.3) !important;
    }

    /* 8. Diagnostic Container (440px Match) */
    div[data-testid="stVerticalBlock"]:has(> div[data-testid="stContainer"]) {
        gap: 0 !important;
    }
    div[data-testid="stContainer"] {
        border: 1px solid #1E1E28 !important;
        border-radius: 10px !important;
        background: #0A0A0F !important;
    }

    /* Minimal Terminal Empty State */
    .terminal-empty-box {
        background: #0F0F14;
        border: 1px solid #1E1E28;
        border-radius: 10px;
        padding: 16px 18px;
        font-family: 'JetBrains Mono', monospace;
    }
    .terminal-bar {
        display: flex;
        align-items: center;
        gap: 6px;
        padding-bottom: 10px;
        border-bottom: 1px solid #1E1E28;
        margin-bottom: 10px;
    }
    .term-dot {
        width: 9px;
        height: 9px;
        border-radius: 50%;
    }
    .term-dot.red { background: #FF5C6C; opacity: 0.8; }
    .term-dot.yellow { background: #FFB454; opacity: 0.8; }
    .term-dot.green { background: #3DDC97; opacity: 0.8; }
    .term-title {
        color: #8A8A99;
        font-size: 11px;
        margin-left: 6px;
    }
    .term-body {
        font-size: 11.5px;
        line-height: 1.7;
    }
    .term-line {
        color: #EDEDF2;
    }
    .term-prompt {
        color: #7C6CFF;
        font-weight: 600;
        margin-right: 6px;
    }
    .term-line.muted {
        color: #8A8A99;
        font-size: 11px;
    }
    .term-line.success {
        color: #3DDC97;
        margin-top: 6px;
    }
    .term-line.info {
        color: #7C6CFF;
        font-size: 11px;
        margin-top: 4px;
    }

    /* Diagnostics Banners */
    .diag-banner {
        border-radius: 8px;
        padding: 9px 13px;
        font-size: 12px;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .diag-blocked {
        background: rgba(255, 92, 108, 0.1);
        border: 1px solid rgba(255, 92, 108, 0.25);
        color: #FF5C6C;
    }
    .diag-warning {
        background: rgba(255, 180, 84, 0.1);
        border: 1px solid rgba(255, 180, 84, 0.25);
        color: #FFB454;
    }
    .diag-clean {
        background: rgba(61, 220, 151, 0.1);
        border: 1px solid rgba(61, 220, 151, 0.25);
        color: #3DDC97;
    }

    div[data-testid="stExpander"] {
        border: 1px solid #1E1E28 !important;
        border-radius: 8px !important;
        background: #0F0F14 !important;
        margin-bottom: 8px !important;
        transition: border-color 0.18s ease !important;
    }
    div[data-testid="stExpander"]:hover {
        border-color: rgba(124, 108, 255, 0.35) !important;
    }
    div[data-testid="stExpander"] summary {
        font-size: 12.5px !important;
        font-weight: 600 !important;
        padding: 6px 10px !important;
        color: #EDEDF2 !important;
    }

    /* Diff View Styling */
    .diff-box-vuln {
        background: rgba(255, 92, 108, 0.06);
        border: 1px solid rgba(255, 92, 108, 0.2);
        border-radius: 6px;
        padding: 6px 10px;
        margin-bottom: 6px;
    }
    .diff-box-patch {
        background: rgba(61, 220, 151, 0.06);
        border: 1px solid rgba(61, 220, 151, 0.2);
        border-radius: 6px;
        padding: 6px 10px;
        margin-bottom: 6px;
    }

    /* 9. Billion-Dollar SaaS Pricing Cards */
    .pricing-header-wrap {
        text-align: center;
        padding: 14px 0 18px 0;
    }
    .pricing-headline {
        font-size: 24px;
        font-weight: 700;
        letter-spacing: -0.025em;
        color: #EDEDF2;
        margin-bottom: 4px;
    }
    .pricing-subhead {
        font-size: 13.5px;
        color: #8A8A99;
        margin-bottom: 14px;
    }

    .pricing-card {
        background: #0F0F14;
        border: 1px solid #1E1E28;
        border-radius: 14px;
        padding: 24px 22px;
        position: relative;
        transition: all 0.2s ease;
        height: 100%;
        box-sizing: border-box;
    }
    .pricing-card:hover {
        border-color: rgba(124, 108, 255, 0.3);
    }
    .pricing-card-featured {
        background: radial-gradient(ellipse at top, rgba(124, 108, 255, 0.1) 0%, #0F0F14 70%);
        border: 1px solid #7C6CFF;
        box-shadow: 0 0 50px rgba(124, 108, 255, 0.16);
    }
    .popular-badge {
        position: absolute;
        top: 14px;
        right: 14px;
        font-size: 10.5px;
        font-weight: 600;
        background: #7C6CFF;
        color: #FFFFFF;
        padding: 2px 9px;
        border-radius: 99px;
        box-shadow: 0 0 12px rgba(124, 108, 255, 0.4);
    }
    .card-tier-title {
        font-size: 15px;
        font-weight: 600;
        color: #EDEDF2;
        margin-bottom: 4px;
        letter-spacing: -0.01em;
    }
    .card-tier-amt {
        font-size: 2.2rem;
        font-weight: 700;
        color: #EDEDF2;
        letter-spacing: -0.03em;
        margin-bottom: 2px;
    }
    .card-tier-sub {
        font-size: 12px;
        color: #8A8A99;
        margin-bottom: 16px;
        min-height: 32px;
    }
    .card-features-list {
        font-size: 12.5px;
        line-height: 1.8;
        color: #C7C7D1;
        border-top: 1px solid #1E1E28;
        padding-top: 14px;
    }

    /* Activation Strip & Feedback */
    .activation-card {
        background: #0F0F14;
        border: 1px solid #1E1E28;
        border-radius: 12px;
        padding: 16px 20px;
        margin-top: 18px;
    }
    .alert-success {
        background: rgba(61, 220, 151, 0.1);
        border: 1px solid rgba(61, 220, 151, 0.25);
        color: #3DDC97;
        padding: 8px 14px;
        border-radius: 8px;
        font-size: 12.5px;
        margin-top: 10px;
        font-weight: 500;
    }
    .alert-error {
        background: rgba(255, 92, 108, 0.1);
        border: 1px solid rgba(255, 92, 108, 0.25);
        color: #FF5C6C;
        padding: 8px 14px;
        border-radius: 8px;
        font-size: 12.5px;
        margin-top: 10px;
        font-weight: 500;
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
    badge_html = '<span class="plan-pill pill-free">● Free Community</span>'

nav_col1, nav_col2, nav_col3 = st.columns([1.15, 1.25, 1.3], gap="small", vertical_alignment="center")

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

# Clear temporary license error feedback when user navigates away from Pricing
if active_tab != "Pricing" and st.session_state.get("key_feedback"):
    st.session_state.key_feedback = None

with nav_col3:
    auth_subcol1, auth_subcol2 = st.columns([1.1, 1.0], gap="small", vertical_alignment="center")
    with auth_subcol1:
        if st.session_state.github_user:
            u = st.session_state.github_user
            with st.popover(f"👤 @{u['login']}", use_container_width=True):
                st.markdown(f"""
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                    <img src="{u['avatar_url']}" style="width:36px; height:36px; border-radius:50%; border:1px solid #7C6CFF;" />
                    <div>
                        <div style="font-weight:600; color:#EDEDF2; font-size:13px;">{html.escape(u['name'])}</div>
                        <div style="font-size:11px; color:#8A8A99;">@{html.escape(u['login'])} • {u['public_repos']} Repos</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(badge_html, unsafe_allow_html=True)
                st.markdown("<div style='margin-top:8px;'></div>", unsafe_allow_html=True)
                st.button("🚪 Sign Out", key="btn_signout", on_click=logout_github, use_container_width=True)
        else:
            with st.popover("🐙 GitHub Sign In", use_container_width=True):
                st.markdown("<div style='font-weight:600; font-size:12.5px; margin-bottom:3px; color:#EDEDF2;'>GitHub Identity</div>", unsafe_allow_html=True)
                st.caption("Link username to bind offline cryptographic licenses.")
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

SQL_SAMPLE = '''import sqlite3

def find_user(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerable SQL Injection (CWE-89)
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
'''

# ================= TAB 1: GOLDEN RATIO CODE INSPECTOR =================
if active_tab == "Inspector":
    # Hero Positioning & Trust Bar
    st.markdown("""
    <div class="hero-container">
        <div class="hero-heading">Catch secrets & SQL injection before they ship.</div>
        <div class="hero-lead">Deterministic intra-procedural AST taint analyzer with 1-click surgical auto-patching. Zero false positives.</div>
        <div class="trust-strip">
            <span><span class="trust-dot"></span> Zero Data Retention</span>
            <span class="trust-sep">·</span>
            <span>⚡ 100% Offline AST Engine</span>
            <span class="trust-sep">·</span>
            <span>🛡️ 1-Click Surgical Remediations</span>
            <span class="trust-sep">·</span>
            <a href="https://github.com/rajrajak99/kavach-ai" target="_blank" class="trust-link">★ Star on GitHub</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

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
        tb_col1, tb_col2, tb_col3 = st.columns([1.1, 2.0, 1.2], gap="small", vertical_alignment="center")
        with tb_col1:
            st.markdown("""
            <div class="ide-tab-label">
                <span class="ide-dot"></span>
                <span style="font-weight:600; color:#EDEDF2;">demo.py</span>
                <span class="ide-meta">UTF-8</span>
            </div>
            """, unsafe_allow_html=True)
        with tb_col2:
            q1, q2, q3 = st.columns([1.1, 1.0, 0.9], gap="small")
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
            placeholder="// Paste code here or select Secrets / SQLi above to inspect..."
        )

    # RIGHT COLUMN: 40% DIAGNOSTIC INSPECTOR
    with col_result:
        # Diagnostic Header Bar with generous width to prevent text wrapping
        r_head1, r_head2 = st.columns([2.0, 1.0], gap="small", vertical_alignment="center")
        with r_head1:
            if not current_code:
                status_text = "Awaiting Scan"
            elif not findings:
                status_text = "Clean (0 Issues)"
            else:
                status_text = f"{len(findings)} Issue(s) Detected"

            st.markdown(f"""
            <div class="ide-tab-label">
                <span style="font-weight:600; color:#EDEDF2;">Diagnostics</span>
                <span class="ide-meta">• {status_text}</span>
            </div>
            """, unsafe_allow_html=True)
        with r_head2:
            if findings:
                crit_badge = f'<span style="color:#FF5C6C; font-weight:600;">{metrics["critical"]} Crit</span>'
                sec_badge = f'<span style="color:#FFB454; font-weight:600;">{metrics["security"]} Sec</span>'
                perf_badge = f'<span style="color:#7C6CFF; font-weight:600;">{metrics["performance"]} Perf</span>'
                st.markdown(f"<div style='text-align:right; font-size:11.5px; font-family:\"JetBrains Mono\"; padding-top:6px; white-space:nowrap;'>{crit_badge} • {sec_badge} • {perf_badge}</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='text-align:right; font-size:11.5px; color:#8A8A99; font-family:\"JetBrains Mono\"; padding-top:6px; white-space:nowrap;'>Zero Noise</div>", unsafe_allow_html=True)

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
                        <div class="term-line info">ℹ Select 'Secrets' or 'SQLi' above to run live AST analysis.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            elif not findings:
                st.markdown("""
                <div class="diag-banner diag-clean">
                    <span style="font-size:16px;">✓</span>
                    <div>
                        <div style="font-weight:600; font-size:12.5px;">ALL CHECKS PASSED — READY TO MERGE</div>
                        <div style="font-size:11.5px; opacity:0.85;">Zero security vulnerabilities or resource leaks detected in this code.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                if metrics['critical'] > 0:
                    st.markdown(f"""
                    <div class="diag-banner diag-blocked">
                        <span style="font-size:16px;">✕</span>
                        <div>
                            <div style="font-weight:600; font-size:12.5px;">MERGE BLOCKED • {metrics['critical']} Critical Exploit(s)</div>
                            <div style="font-size:11.5px; opacity:0.85;">High-risk attack vectors identified. Apply surgical patches below.</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="diag-banner diag-warning">
                        <span style="font-size:16px;">⚠</span>
                        <div>
                            <div style="font-weight:600; font-size:12.5px;">SECURITY AUDIT • {metrics['security']} Warning(s)</div>
                            <div style="font-size:11.5px; opacity:0.85;">Vulnerabilities or resource leaks flagged for review.</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                for i, f in enumerate(findings, 1):
                    cat_safe = html.escape(f.category)
                    exp_safe = html.escape(f.explanation)
                    cwe_safe = html.escape(f.cwe_id or "CWE-General")
                    is_crit = (f.severity.upper() == "CRITICAL")
                    sev_color = "#FF5C6C" if is_crit else ("#FFB454" if f.severity.upper() == "WARNING" else "#7C6CFF")

                    with st.expander(f"L{f.line_number} [{f.severity}] {cat_safe} • {cwe_safe}", expanded=(i <= 2)):
                        st.markdown(f"<div style='font-size:12px; color:#C7C7D1; margin-bottom:8px;'>{exp_safe}</div>", unsafe_allow_html=True)
                        c_sub1, c_sub2 = st.columns(2)
                        with c_sub1:
                            st.caption("❌ Current Problem Code:")
                            st.code(f.problem_code, language=f.language)
                        with c_sub2:
                            st.caption("✅ Surgical 1-Click Patch:")
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

    # Header & Billing Toggle
    st.markdown("""
    <div class="pricing-header-wrap">
        <div class="pricing-headline">Predictable pricing for developers and teams.</div>
        <div class="pricing-subhead">Start free for open source. Upgrade when you need private repo coverage and CI gates.</div>
    </div>
    """, unsafe_allow_html=True)

    b_col1, b_col2, b_col3 = st.columns([1.5, 1.2, 1.5], gap="small", vertical_alignment="center")
    with b_col2:
        billing_cycle = st.segmented_control(
            "Billing Cycle",
            ["Annual (Save 50%)", "Monthly"],
            default="Annual (Save 50%)",
            label_visibility="collapsed",
            key="pricing_billing_toggle"
        ) or "Annual (Save 50%)"

    st.markdown("<div style='margin-top:14px;'></div>", unsafe_allow_html=True)

    p1, p2, p3 = st.columns(3, gap="medium")

    # 1. COMMUNITY ($0)
    with p1:
        st.markdown("""
        <div class="pricing-card">
            <div class="card-tier-title">Community</div>
            <div class="card-tier-amt">$0</div>
            <div class="card-tier-sub">Forever free for public open-source repos</div>
            <div class="card-features-list">
                ✓ <b>Unlimited public repositories</b><br>
                ✓ High-speed offline AST scanning<br>
                ✓ Local CLI execution (<code>kavach .</code>)<br>
                ✓ Free for students & open source<br>
                ✓ Zero code telemetry or data retention
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_free else "Use Free Community",
            key="btn_activate_free",
            disabled=is_free,
            on_click=select_plan,
            args=(PlanTier.FREE.value, "Community Free ($0)"),
            use_container_width=True
        )

    # 2. DEVELOPER PRO ($1/mo or $2/mo)
    with p2:
        if billing_cycle == "Monthly":
            pro_price = "$2"
            pro_sub = "$2 billed monthly • Independent devs"
        else:
            pro_price = "$1"
            pro_sub = "$12 billed annually (Save 50%) • Independent devs"

        st.markdown(f"""
        <div class="pricing-card pricing-card-featured">
            <div class="popular-badge">Most Popular</div>
            <div class="card-tier-title">Developer Pro</div>
            <div class="card-tier-amt">{pro_price}<span style="font-size:15px; color:#8A8A99; font-weight:500;">/mo</span></div>
            <div class="card-tier-sub">{pro_sub}</div>
            <div class="card-features-list">
                ✓ <b>Up to 5 personal private repos</b><br>
                ✓ Cryptographic Ed25519 token verification<br>
                ✓ 1-click surgical auto-remediations<br>
                ✓ Local Git pre-commit hooks<br>
                ✓ Priority email updates & patches
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_pro else f"Select Developer Pro ({pro_price}/mo)",
            key="btn_activate_pro",
            disabled=is_pro,
            type="primary" if not is_pro else "secondary",
            on_click=select_plan,
            args=(PlanTier.DEVELOPER_PRO.value, f"Developer Pro ({pro_price}/mo)"),
            use_container_width=True
        )

    # 3. TEAM ENTERPRISE ($99/mo or $119/mo)
    with p3:
        if billing_cycle == "Monthly":
            team_price = "$119"
            team_sub = "$119 billed monthly • Startups & Orgs"
        else:
            team_price = "$99"
            team_sub = "$1,188 billed annually (Save 17%) • Startups & Orgs"

        st.markdown(f"""
        <div class="pricing-card">
            <div class="card-tier-title">Team Enterprise</div>
            <div class="card-tier-amt">{team_price}<span style="font-size:15px; color:#8A8A99; font-weight:500;">/mo</span></div>
            <div class="card-tier-sub">{team_sub}</div>
            <div class="card-features-list">
                ✓ <b>GitHub Organizations support</b><br>
                ✓ <b>Unlimited team repositories</b><br>
                ✓ Autonomous PR review bot & merge blocker<br>
                ✓ Pytest self-healing engine integration<br>
                ✓ SLA support & custom AST rule sets
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.button(
            "Active Plan" if is_team else f"Select Team Enterprise ({team_price}/mo)",
            key="btn_activate_team",
            disabled=is_team,
            on_click=select_plan,
            args=(PlanTier.TEAM_ENTERPRISE.value, f"Team Enterprise ({team_price}/mo)"),
            use_container_width=True
        )

    # LICENSE ACTIVATION STRIP
    st.markdown("<div style='margin-top:22px;'></div>", unsafe_allow_html=True)
    with st.container():
        lk_col1, lk_col2, lk_col3 = st.columns([2.1, 1.8, 1.0], gap="medium", vertical_alignment="center")
        with lk_col1:
            st.markdown("""
            <div>
                <div style="font-size:14px; font-weight:600; color:#EDEDF2;">🔑 Activate Customer License Key</div>
                <div style="font-size:12px; color:#8A8A99;">Supports LemonSqueezy license UUIDs or offline signed Ed25519 tokens.</div>
            </div>
            """, unsafe_allow_html=True)
        with lk_col2:
            st.text_input(
                "License Key:",
                key="custom_key_input",
                placeholder="LemonSqueezy UUID or KAVACH-PRO-... token",
                label_visibility="collapsed"
            )
        with lk_col3:
            st.button(
                "Activate Key",
                key="btn_activate_key",
                type="primary",
                on_click=activate_custom_key,
                use_container_width=True
            )

        # Only display error/success banner if the user explicitly performed an activation action
        if st.session_state.get("key_feedback"):
            status, msg = st.session_state.key_feedback
            if status == "success":
                st.markdown(f'<div class="alert-success">✓ {html.escape(msg)}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="alert-error">✕ {html.escape(msg)}</div>', unsafe_allow_html=True)

# ================= TAB 3: GITHUB SETUP =================
elif active_tab == "GitHub":
    st.markdown("""
    <div style="margin-bottom:14px;">
        <div style="font-size:18px; font-weight:700; color:#EDEDF2; letter-spacing:-0.02em;">1-Minute GitHub Actions Security Gate</div>
        <div style="font-size:13px; color:#8A8A99;">Block vulnerable pull requests before they reach your production branch.</div>
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
