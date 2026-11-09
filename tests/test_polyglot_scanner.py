import pytest
from core.polyglot.go_scanner import GoScanner
from core.polyglot.ts_scanner import TSScanner
from core.polyglot.terraform_scanner import TerraformScanner
from core.project_scanner import ProjectASTScanner

def test_go_scanner_sqli():
    scanner = GoScanner()
    code = """package main
import "fmt"
func getUser(id string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
"""
    findings = scanner.scan_code(code, "db.go")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-89"
    assert "SQL_INJECTION" in findings[0].category

def test_go_scanner_command_injection():
    scanner = GoScanner()
    code = """package main
import "os/exec"
func run(cmd string) {
    exec.Command("sh", "-c", cmd)
}
"""
    findings = scanner.scan_code(code, "exec.go")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"

def test_go_scanner_secret():
    scanner = GoScanner()
    dummy_key = "sk_test_" + "0" * 24
    code = f'const key = "{dummy_key}"'
    findings = scanner.scan_code(code, "config.go")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-798"


def test_ts_scanner_command_injection():
    scanner = TSScanner()
    code = """import child_process from 'child_process';
function execute(input) {
    child_process.exec(`ping -c 1 ${input}`);
}
"""
    findings = scanner.scan_code(code, "api.ts")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-78"

def test_ts_scanner_dom_xss():
    scanner = TSScanner()
    code = '<div dangerouslySetInnerHTML={{ __html: userInput }} />'
    findings = scanner.scan_code(code, "component.tsx")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-79"

def test_terraform_open_s3_and_sg():
    scanner = TerraformScanner()
    code = """resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}
resource "aws_security_group" "allow_all" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    findings = scanner.scan_code(code, "infra.tf")
    assert len(findings) == 2
    cwes = {f.cwe_id for f in findings}
    assert "CWE-732" in cwes
    assert "CWE-284" in cwes

def test_project_scanner_polyglot_integration():
    scanner = ProjectASTScanner()
    bundle = {
        "service.py": "def get_user(db, user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n",
        "handler.go": 'package main\nfunc q(s string) { db.Query(fmt.Sprintf("SELECT %s", s)) }\n',
        "view.tsx": '<div dangerouslySetInnerHTML={{ __html: payload }} />\n',
        "main.tf": 'resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
    }
    result = scanner.analyze_file_bundle(bundle, project_name="polyglot-test")
    assert len(result["file_findings"]) == 4
    assert result["metrics"]["critical"] >= 2
