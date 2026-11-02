import pytest
from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer
from core.ai_reasoner import AIReasoner, ThreatIntelligence
from samples.vulnerable_samples import SAMPLE_NODE_JS_EXPRESS, SAMPLE_PYTHON_MULTI, SAMPLE_CPP_MEMORY_AND_SECURITY
from ci_bot import build_github_markdown_report, BOT_SIGNATURE

def test_noise_filter():
    assert DiffParser.is_noise_file("package-lock.json") is True
    assert DiffParser.is_noise_file("bundle.min.js") is True
    assert DiffParser.is_noise_file("user_routes.py") is False

def test_python_security_detection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diffs = parser.parse_git_diff(SAMPLE_PYTHON_MULTI)
    assert len(diffs) == 1
    
    findings = analyzer.analyze_file_diff(diffs[0])
    assert len(findings) >= 2
    categories = [f.category for f in findings]
    assert any("Secret" in c for c in categories)
    assert any("Command" in c for c in categories)

def test_javascript_nodejs_detection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diffs = parser.parse_git_diff(SAMPLE_NODE_JS_EXPRESS)
    assert len(diffs) == 1
    
    findings = analyzer.analyze_file_diff(diffs[0])
    assert len(findings) >= 3
    categories = [f.category for f in findings]
    assert any("JavaScript" in c or "Credential" in c for c in categories)
    assert any("eval" in c or "Arbitrary" in c for c in categories)

def test_ci_bot_markdown_generation():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diffs = parser.parse_git_diff(SAMPLE_PYTHON_MULTI)
    analysis = analyzer.generate_pull_request_review(diffs)
    
    report = build_github_markdown_report(analysis, total_files=1)
    assert BOT_SIGNATURE in report
    assert "Kavach AI" in report
    assert "```suggestion" in report
    assert "Critical Exploits" in report

def test_ai_hybrid_reasoner():
    reasoner = AIReasoner(provider="offline")
    intel = reasoner.analyze_threat(
        category="Raw SQL Injection",
        problem_code="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        fixed_code="cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        cwe_id="CWE-89",
        language="python"
    )
    assert isinstance(intel, ThreatIntelligence)
    assert intel.cwe_id == "CWE-89"
    assert intel.cvss_score >= 9.0
    assert "SQL" in intel.attack_vector or "query" in intel.attack_vector
    assert "Deterministic" in intel.provider_used

def test_cpp_security_detection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diffs = parser.parse_git_diff(SAMPLE_CPP_MEMORY_AND_SECURITY)
    assert len(diffs) == 1
    
    findings = analyzer.analyze_file_diff(diffs[0])
    assert len(findings) >= 3
    categories = [f.category for f in findings]
    assert any("Buffer Overflow" in c for c in categories)
    assert any("Command Injection" in c for c in categories)
    assert any("Secret" in c for c in categories)

def test_division_safety_and_no_crash():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
def calc(a, b):
    result = a / b
    return result
"""
    diff = parser.parse_raw_snippet("calc.py", code)
    findings = analyzer.analyze_file_diff(diff)
    assert len(findings) >= 1
    assert any("ZeroDivision" in f.category for f in findings)

def test_shell_true_detection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
import subprocess
def run_user(cmd):
    subprocess.run(cmd, shell=True)
"""
    diff = parser.parse_raw_snippet("runner.py", code)
    findings = analyzer.analyze_file_diff(diff)
    assert len(findings) >= 1
    assert any("shell=True" in f.category for f in findings)

def test_license_manager_tiers():
    from core.license_manager import LicenseManager, PlanTier
    
    assert LicenseManager.get_tier_for_key("BUILDER-DEV-1") == PlanTier.DEVELOPER_PRO
    assert LicenseManager.get_tier_for_key("KV-TEAM-ORG-99") == PlanTier.TEAM_ENTERPRISE
    assert LicenseManager.get_tier_for_key("INVALID-KEY-123") is None

    # Public repo defaults to free
    is_auth, tier, msg = LicenseManager.validate_execution_policy(license_key=None)
    assert is_auth is True
    assert tier == PlanTier.FREE

def test_license_manager_org_abuse_prevention(monkeypatch):
    from core.license_manager import LicenseManager, PlanTier
    
    # Mock GitHub Organization context
    monkeypatch.setattr(
        LicenseManager,
        "inspect_github_context",
        lambda: {"is_ci": True, "repository": "bigcorp/api", "owner": "bigcorp", "visibility": "private", "owner_type": "Organization"}
    )

    # 1. Developer Pro ($1) key should be REJECTED for an Organization
    is_auth, tier, msg = LicenseManager.validate_execution_policy(license_key="BUILDER-DEV-1")
    assert is_auth is False
    assert "Organization detected" in msg

    # 2. Team Enterprise ($99) key should be ACCEPTED for an Organization
    is_auth, tier, msg = LicenseManager.validate_execution_policy(license_key="KV-TEAM-ORG-99")
    assert is_auth is True
    assert tier == PlanTier.TEAM_ENTERPRISE

def test_variable_aliased_sql_injection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
def search_users(role):
    query_stmt = f"SELECT id, username FROM users WHERE role = '{role}'"
    # Some intermediate logic
    cursor.execute(query_stmt)
"""
    diff = parser.parse_raw_snippet("test_taint.py", code)
    findings = analyzer.analyze_file_diff(diff)
    categories = [f.category for f in findings]
    assert any("Variable-Aliased Indirect SQL Injection" in c for c in categories)
    taint_finding = next(f for f in findings if "Variable-Aliased" in f.category)
    assert taint_finding.cwe_id == "CWE-89"
    assert taint_finding.severity == "CRITICAL"
    assert "query_stmt" in taint_finding.explanation

def test_obfuscated_secret_constant_folding():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
_part_a = "ghp_"
_part_b = "1234567890abcdef1234567890abcdef"
github_backup_pat = _part_a + _part_b
"""
    diff = parser.parse_raw_snippet("test_secrets.py", code)
    findings = analyzer.analyze_file_diff(diff)
    categories = [f.category for f in findings]
    assert any("Obfuscated GitHub Token via String Concatenation" in c for c in categories)
    secret_finding = next(f for f in findings if "Obfuscated" in f.category)
    assert secret_finding.cwe_id == "CWE-798"
    assert secret_finding.severity == "CRITICAL"

def test_env_fallback_secret_inspection():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
import os
auth_token = os.environ.get("MASTER_TOKEN", "sk-99887766554433221100112233445566")
"""
    diff = parser.parse_raw_snippet("test_env.py", code)
    findings = analyzer.analyze_file_diff(diff)
    categories = [f.category for f in findings]
    assert any("Hardcoded Secret in Environment Variable Fallback" in c for c in categories)
    fallback_finding = next(f for f in findings if "Fallback" in f.category)
    assert fallback_finding.cwe_id == "CWE-798"
    assert fallback_finding.severity == "CRITICAL"

def test_try_finally_file_close_no_false_positive():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
def read_config(path):
    f = open(path, "r")
    try:
        return f.read()
    finally:
        f.close()
"""
    diff = parser.parse_raw_snippet("test_leak.py", code)
    findings = analyzer.analyze_file_diff(diff)
    assert not any("Resource Leak" in f.category for f in findings)

def test_unmanaged_file_leak_still_detected():
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    code = """
def dump_data(filename, payload):
    fd = open(filename, "w")
    fd.write(payload)
"""
    diff = parser.parse_raw_snippet("test_leak_real.py", code)
    findings = analyzer.analyze_file_diff(diff)
    assert any("Resource Leak" in f.category for f in findings)

def test_cli_license_gating(monkeypatch, tmp_path):
    from cli import scan_path
    from core.license_manager import LicenseManager, PlanTier

    # Mock organization context requiring Team tier
    monkeypatch.setattr(
        LicenseManager,
        "inspect_github_context",
        lambda: {"is_ci": True, "repository": "mega-corp/core", "owner": "mega-corp", "visibility": "private", "owner_type": "Organization"}
    )

    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1\n", encoding="utf-8")

    # 1. Blocked when running without Team license key in Org context
    code = scan_path(str(test_file), as_json=True, license_key=None)
    assert code == 1

    # 2. Blocked with Developer Pro key in Org context
    code = scan_path(str(test_file), as_json=True, license_key="BUILDER-DEV-1")
    assert code == 1

    # 3. Authorized with Team Enterprise key in Org context
    code = scan_path(str(test_file), as_json=True, license_key="KV-TEAM-ORG-99")
    assert code == 0

