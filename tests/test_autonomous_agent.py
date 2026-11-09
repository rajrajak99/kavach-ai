import pytest
from pathlib import Path
from core.autonomous_agent import AutonomousSecurityAgent

def test_autonomous_agent_successful_patch(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = 10\ny = 0\nres = x / y\n", encoding="utf-8")
    
    agent = AutonomousSecurityAgent(str(tmp_path))
    res = agent.evaluate_and_remediate(
        target_file="app.py",
        target_content="res = x / y",
        replacement_content="res = x / y if y != 0 else 0",
        test_command=None,
        vuln_id="CWE-369"
    )
    assert res.success is True
    assert res.patch_applied is True
    assert res.auto_merge_eligible is True
    assert "kavach/patch-cwe_369" in res.branch_name

def test_autonomous_agent_failed_tests(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = 10\n", encoding="utf-8")

    agent = AutonomousSecurityAgent(str(tmp_path))
    res = agent.evaluate_and_remediate(
        target_file="app.py",
        target_content="x = 10",
        replacement_content="x = 20",
        test_command="python -c \"import sys; sys.exit(1)\"",
        vuln_id="TEST-FAIL"
    )
    assert res.success is False
    assert res.tests_passed is False
    assert res.auto_merge_eligible is False
