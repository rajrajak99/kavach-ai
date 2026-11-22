import os
import pytest
from pathlib import Path
from kavach_license import get_master_secret, LicenseManager, PlanTier, generate_signed_license
from core.surgical_analyzer import SurgicalAnalyzer
from core.diff_parser import DiffParser
from core.sca_scanner import SCAScanner
from core.container_scanner import ContainerSecurityScanner
from core.polyglot.ts_scanner import TSScanner
from core.polyglot.go_scanner import GoScanner
from core.autonomous_agent import AutonomousSecurityAgent

def test_kavach_master_signing_key_env_sync(monkeypatch):
    custom_key = "test_custom_signing_key_12345"
    monkeypatch.delenv("KAVACH_MASTER_SECRET", raising=False)
    monkeypatch.setenv("KAVACH_MASTER_SIGNING_KEY", custom_key)
    assert get_master_secret() == custom_key

def test_pro_user_authorized_on_public_org_repo(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    event_data = {
        "repository": {
            "private": False,
            "owner": {"type": "Organization"}
        }
    }
    import tempfile, json
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
        json.dump(event_data, f)
        temp_event = f.name

    try:
        monkeypatch.setenv("GITHUB_EVENT_PATH", temp_event)
        pro_key = generate_signed_license("dev@company.com", tier="PRO")
        is_auth, tier, msg = LicenseManager.validate_execution_policy(license_key=pro_key)
        assert is_auth is True
        assert tier == PlanTier.DEVELOPER_PRO
        assert "Authorized" in msg
    finally:
        if os.path.exists(temp_event):
            os.remove(temp_event)

def test_zero_division_ignores_pathlib_paths():
    analyzer = SurgicalAnalyzer()
    parser = DiffParser()
    code = '''
import pathlib
from pathlib import Path

def get_file(filename):
    base_dir = Path("/var/log")
    target_path = base_dir / filename
    return target_path
'''
    diff = parser.parse_raw_snippet("test_path.py", code)
    findings = analyzer.analyze_file_diff(diff)
    zero_div = [f for f in findings if f.category == "Unchecked ZeroDivisionError"]
    assert len(zero_div) == 0

def test_zero_division_whitespace_fix():
    analyzer = SurgicalAnalyzer()
    parser = DiffParser()
    code = '''
def calc_ratio(total, denom):
    ratio = total / denom
    return ratio
'''
    diff = parser.parse_raw_snippet("math_ops.py", code)
    findings = analyzer.analyze_file_diff(diff)
    zero_div = [f for f in findings if f.category == "Unchecked ZeroDivisionError"]
    assert len(zero_div) == 1
    assert "safe_denom = denom if denom != 0 else 1e-7" in zero_div[0].fixed_code
    assert "/ safe_denom" in zero_div[0].fixed_code

def test_os_system_concatenation_detected():
    analyzer = SurgicalAnalyzer()
    parser = DiffParser()
    code = '''
import os

def ping_host(host):
    os.system("ping -c 1 " + host)
'''
    diff = parser.parse_raw_snippet("network.py", code)
    findings = analyzer.analyze_file_diff(diff)
    cmd_findings = [f for f in findings if "Command Injection" in f.category]
    assert len(cmd_findings) >= 1
    assert cmd_findings[0].cwe_id == "CWE-78"

def test_requirements_with_spaces_parsed_properly():
    sca = SCAScanner()
    manifests = {
        "requirements.txt": "requests >= 2.31.0\nurllib3 == 2.0.7\n"
    }
    codes = {
        "main.py": "import requests\nimport urllib3\n"
    }
    findings = sca.scan_dependencies_and_reachability(manifests, codes)
    assert len(findings) == 0

def test_docker_compose_loopback_not_flagged():
    scanner = ContainerSecurityScanner()
    content = '''
version: '3.8'
services:
  db:
    image: postgres:15
    ports:
      - "127.0.0.1:5432:5432"
'''
    findings = scanner.scan_docker_compose(content, file_path="docker-compose.prod.yml")
    port_findings = [f for f in findings if f.rule_id == "COMPOSE-EXPOSED-DATABASE-PORT"]
    assert len(port_findings) == 0

def test_ts_scanner_dompurify_not_flagged():
    ts_scanner = TSScanner()
    code = '''
import DOMPurify from 'dompurify';

export function ContentBox({ cleanHtml }: { cleanHtml: string }) {
    return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(cleanHtml) }} />;
}
'''
    findings = ts_scanner.scan_code(code, file_path="Component.tsx")
    xss_findings = [f for f in findings if f.category == "CROSS_SITE_SCRIPTING"]
    assert len(xss_findings) == 0

def test_diff_parser_filenames_with_spaces():
    parser = DiffParser()
    raw_diff = '''diff --git a/my folder/sub file.py b/my folder/sub file.py
index 0000000..1111111 100644
--- a/my folder/sub file.py
+++ b/my folder/sub file.py
@@ -1,1 +1,1 @@
-old line
+new line
'''
    diffs = parser.parse_git_diff(raw_diff)
    assert len(diffs) == 1
    assert diffs[0].filename_new == "my folder/sub file.py"

def test_autonomous_agent_safe_execution(tmp_path):
    agent = AutonomousSecurityAgent(str(tmp_path))
    test_file = tmp_path / "hello.py"
    test_file.write_text("x = 1\n", encoding="utf-8")
    
    result = agent.evaluate_and_remediate(
        target_file="hello.py",
        target_content="x = 1",
        replacement_content="x = 2",
        test_command="python -c \"import sys; sys.exit(0)\"",
        vuln_id="testfix"
    )
    assert result.success is True
    assert test_file.read_text(encoding="utf-8") == "x = 1\n"

def test_container_multiline_run_and_ipv6_ports():
    from core.container_scanner import ContainerSecurityScanner, is_compose_file
    scanner = ContainerSecurityScanner()
    
    # 1. Multiline RUN with curl | bash
    dockerfile = """
FROM python:3.11-slim
RUN apt-get update && \\
    curl -fsSL https://get.docker.com | \\
    sh
USER appuser
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000 || exit 1
"""
    df_findings = scanner.scan_dockerfile(dockerfile)
    pipe_findings = [f for f in df_findings if f.rule_id == "DOCKER-INSECURE-PIPE"]
    assert len(pipe_findings) == 1
    assert pipe_findings[0].line_number == 3

    # 2. IPv6 database port in prod compose
    compose_ipv6 = """
version: '3.8'
services:
  db:
    image: postgres:15
    ports:
      - "[::]:5432:5432"
"""
    c_findings = scanner.scan_docker_compose(compose_ipv6, file_path="docker-compose.prod.yml")
    port_findings = [f for f in c_findings if f.rule_id == "COMPOSE-EXPOSED-DATABASE-PORT"]
    assert len(port_findings) == 1

    # 3. Long-form published port in prod compose
    compose_long_form = """
version: '3.8'
services:
  redis:
    image: redis:7
    ports:
      - target: 6379
        published: 6379
        protocol: tcp
"""
    c_findings2 = scanner.scan_docker_compose(compose_long_form, file_path="compose.prod.yaml")
    port_findings2 = [f for f in c_findings2 if f.rule_id == "COMPOSE-EXPOSED-DATABASE-PORT"]
    assert len(port_findings2) == 1

    # 4. is_compose_file tests
    assert is_compose_file("docker-compose.dev.yml") is True
    assert is_compose_file("compose.yaml") is True
    assert is_compose_file("compose.dev.yaml") is True
    assert is_compose_file("sub/docker-compose.prod.yml") is True
    assert is_compose_file("app.py") is False

def test_patch_validator_preserves_indentation_and_rejects_empty():
    from core.patch_validator import PatchValidator
    
    # 1. Reject empty
    valid, msg = PatchValidator.validate_python_syntax("")
    assert valid is False
    assert "Empty" in msg

    valid_ws, msg_ws = PatchValidator.validate_python_syntax("   \n\t  ")
    assert valid_ws is False

    # 2. Preserve indentation in multiline markdown block
    fenced = """```python
    def calculate_total(items):
        total = 0
        for item in items:
            total += item.price
        return total
```"""
    cleaned = PatchValidator.clean_suggestion_block(fenced)
    assert cleaned.startswith("    def calculate_total")
    assert "        total = 0" in cleaned

    # 3. Clean suggestion block with ```py or ```suggestion
    sugg = """```suggestion
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```"""
    cleaned_sugg = PatchValidator.clean_suggestion_block(sugg)
    assert cleaned_sugg.startswith("    cursor.execute")


