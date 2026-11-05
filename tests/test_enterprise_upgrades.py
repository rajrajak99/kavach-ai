import pytest
from core.surgical_analyzer import SurgicalAnalyzer
from core.diff_parser import DiffParser
from core.project_scanner import ProjectASTScanner
from core.sca_scanner import SCAScanner
from core.billing import BillingManager

@pytest.fixture
def parser():
    return DiffParser()

@pytest.fixture
def analyzer():
    return SurgicalAnalyzer()

# ----------------- 1. CROSS-FILE AST TAINT TESTS -----------------
def test_cross_file_sql_taint():
    scanner = ProjectASTScanner()
    file_contents = {
        "routes/user.py": (
            "from services.query_service import search_users\n\n"
            "def handle_search(request):\n"
            "    user_query = request.args.get('search')\n"
            "    return search_users(user_query)\n"
        ),
        "services/query_service.py": (
            "import sqlite3\n\n"
            "def search_users(query_str):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(query_str)\n"
            "    return cursor.fetchall()\n"
        )
    }

    res = scanner.analyze_file_bundle(file_contents, project_name="test_proj")
    cf_findings = res["cross_file_findings"]
    assert len(cf_findings) >= 1
    f = cf_findings[0]
    assert f.cwe_id == "CWE-89"
    assert "routes/user.py" in f.source_file
    assert "services/query_service.py" in f.sink_file
    assert f.sink_function == "search_users"

def test_cross_file_command_injection_taint():
    scanner = ProjectASTScanner()
    file_contents = {
        "api/handler.py": (
            "from utils.runner import run_system_diagnostic\n\n"
            "def on_ping(req):\n"
            "    target = req.POST.get('host')\n"
            "    run_system_diagnostic(target)\n"
        ),
        "utils/runner.py": (
            "import os\n\n"
            "def run_system_diagnostic(target_host):\n"
            "    os.system(f'ping -c 1 {target_host}')\n"
        )
    }

    res = scanner.analyze_file_bundle(file_contents, project_name="test_proj")
    cf_findings = res["cross_file_findings"]
    assert len(cf_findings) >= 1
    f = cf_findings[0]
    assert f.cwe_id == "CWE-78"

# ----------------- 2. ENTERPRISE FRAMEWORK RULES TESTS -----------------
def test_rule_yaml_unsafe_load(parser, analyzer):
    code = "import yaml\ndata = yaml.load(raw_config)"
    diff = parser.parse_raw_snippet("config.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-502"]
    assert len(findings) == 1
    assert "yaml.safe_load" in findings[0].fixed_code

def test_rule_pickle_loads(parser, analyzer):
    code = "import pickle\nobj = pickle.loads(untrusted_stream)"
    diff = parser.parse_raw_snippet("handler.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-502"]
    assert len(findings) == 1

def test_rule_jwt_unverified_decode(parser, analyzer):
    code = "import jwt\npayload = jwt.decode(token, verify=False)"
    diff = parser.parse_raw_snippet("auth.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-347"]
    assert len(findings) == 1

def test_rule_flask_template_injection(parser, analyzer):
    code = "from flask import render_template_string\nhtml = render_template_string(user_tpl)"
    diff = parser.parse_raw_snippet("view.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-1336"]
    assert len(findings) == 1

def test_rule_orm_text_sqli(parser, analyzer):
    code = "from sqlalchemy import text\nres = db.session.execute(text(f'SELECT * FROM users WHERE id = {uid}'))"
    diff = parser.parse_raw_snippet("repo.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(findings) >= 1
    assert any(f.category == "Raw SQL Injection in ORM text()/raw()" for f in findings)

def test_rule_subprocess_shell_true(parser, analyzer):
    code = "import subprocess\nsubprocess.run(user_cmd, shell=True)"
    diff = parser.parse_raw_snippet("exec.py", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-78"]
    assert len(findings) >= 1
    assert any(f.category == "Remote Command Injection via subprocess(shell=True)" for f in findings)

def test_rule_react_dangerously_set_html(parser, analyzer):
    code = "const el = <div dangerouslySetInnerHTML={{ __html: user_comment }} />;"
    diff = parser.parse_raw_snippet("Component.jsx", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-79"]
    assert len(findings) == 1

def test_rule_frontend_secret_leak(parser, analyzer):
    code = "const apiKey = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;"
    diff = parser.parse_raw_snippet("api.js", code)
    res = analyzer.generate_pull_request_review([diff])
    findings = [f for f in res['findings'] if f.cwe_id == "CWE-798"]
    assert len(findings) == 1

# ----------------- 3. SCA & AST REACHABILITY TESTS -----------------
def test_sca_reachability_classification():
    sca = SCAScanner()
    manifests = {
        "requirements.txt": (
            "requests==2.28.0\n"   # Vulnerable below 2.31.0
            "pyyaml==5.3.1\n"      # Vulnerable below 5.4.0
        )
    }
    # requests is imported in app.py, but pyyaml is NEVER imported
    codes = {
        "app.py": "import requests\nresp = requests.get('https://api.github.com')"
    }

    findings = sca.scan_dependencies_and_reachability(manifests, codes)
    assert len(findings) == 2

    requests_finding = next(f for f in findings if f.package_name == "requests")
    assert requests_finding.is_reachable is True
    assert "REACHABLE IN AST" in requests_finding.reachability_status
    assert "app.py" in requests_finding.imported_files

    yaml_finding = next(f for f in findings if f.package_name == "pyyaml")
    assert yaml_finding.is_reachable is False
    assert "UNREACHABLE" in yaml_finding.reachability_status
    assert len(yaml_finding.imported_files) == 0

# ----------------- 4. BILLING & MoR PIPELINE TESTS -----------------
def test_billing_redirect_activation():
    # Successful payment callback from Dodo Payments / LemonSqueezy
    query_params = {
        "status": "success",
        "payment_id": "dodo_test_ord_987654",
        "tier": "DEVELOPER_PRO"
    }
    res = BillingManager.inspect_and_activate_redirect(query_params)
    assert res is not None
    assert res["activated"] is True
    assert res["tier"] == "DEVELOPER_PRO"
    assert "KV-DEVE-DODO_TEST_OR" in res["license_key"]

def test_billing_invoice_mailto_generation():
    url = BillingManager.get_invoice_request_url("Team Enterprise", "annual")
    assert url.startswith("mailto:rajabhaiyarajak2008@gmail.com?")
    assert "Team+Enterprise" in url or "Team%20Enterprise" in url
