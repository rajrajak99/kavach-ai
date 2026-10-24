import os
import tempfile
from pathlib import Path
import pytest

from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer, PatchFinding
from core.self_healing import SelfHealingTestRunner

SAMPLE_LEAKED_SECRET = """import os
api_key = "sk-live-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4"
print("Initialized client")
"""

def test_self_healing_success(tmp_path):
    target = tmp_path / "app_secret.py"
    target.write_text(SAMPLE_LEAKED_SECRET, encoding="utf-8")

    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diff = parser.parse_raw_snippet(str(target), SAMPLE_LEAKED_SECRET)
    review = analyzer.generate_pull_request_review([diff])
    findings = review["findings"]

    assert len(findings) >= 1

    runner = SelfHealingTestRunner()
    result = runner.heal_file(
        str(target),
        findings,
        test_command="python -c \"import ast; ast.parse(open('app_secret.py').read())\"",
        working_dir=str(tmp_path)
    )

    assert result.status == "VERIFIED_PASSED"
    assert result.patches_applied >= 1
    # Check that backup file was removed
    assert not (tmp_path / "app_secret.py.autopatch_bak").exists()

    # Check that file content contains 'os.environ.get'
    patched_content = target.read_text(encoding="utf-8")
    assert "os.environ.get" in patched_content

def test_self_healing_rollback_on_test_failure(tmp_path):
    target = tmp_path / "service_secret.py"
    target.write_text(SAMPLE_LEAKED_SECRET, encoding="utf-8")

    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    diff = parser.parse_raw_snippet(str(target), SAMPLE_LEAKED_SECRET)
    review = analyzer.generate_pull_request_review([diff])
    findings = review["findings"]

    runner = SelfHealingTestRunner()
    # Test command simulates failing tests
    result = runner.heal_file(
        str(target),
        findings,
        test_command="python -c \"import sys; sys.exit(2)\"",
        working_dir=str(tmp_path)
    )

    assert result.status == "ROLLBACK_TEST_FAILED"
    assert result.test_exit_code == 2

    # Verify atomic rollback: content is preserved verbatim
    restored_content = target.read_text(encoding="utf-8")
    assert restored_content == SAMPLE_LEAKED_SECRET
    assert not (tmp_path / "service_secret.py.autopatch_bak").exists()

def test_self_healing_syntax_guard(tmp_path):
    target = tmp_path / "broken_patch.py"
    target.write_text("def test():\n    pass\n", encoding="utf-8")

    # Manually craft a finding with broken syntax
    broken_finding = PatchFinding(
        severity="SECURITY",
        category="Test",
        line_number=2,
        problem_code="pass",
        fixed_code="def broken_syntax( {",  # invalid python
        explanation="Testing syntax guard",
        github_suggestion_block="```suggestion\ndef broken_syntax( {\n```",
        cwe_id="CWE-TEST"
    )

    runner = SelfHealingTestRunner()
    result = runner.heal_file(
        str(target),
        [broken_finding],
        test_command="python -c \"exit(0)\"",
        working_dir=str(tmp_path)
    )

    assert result.status == "ROLLBACK_SYNTAX_ERROR"
    restored_content = target.read_text(encoding="utf-8")
    assert restored_content == "def test():\n    pass\n"
