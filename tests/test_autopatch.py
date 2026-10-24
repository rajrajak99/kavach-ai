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
    assert "AutoPatch AI Security & Code Health Review" in report
    assert "```suggestion" in report
    assert "Critical Runtime Crashes" in report

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
