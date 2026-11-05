import pytest
from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer

@pytest.fixture
def parser():
    return DiffParser()

@pytest.fixture
def analyzer():
    return SurgicalAnalyzer()

# ---------------- 1. STATIC SQL & HEALTH CHECKS (ZERO FALSE POSITIVES) ----------------
def test_static_select_1_health_check_not_flagged(parser, analyzer):
    code = """
from sqlalchemy import text
res = db.execute(text("SELECT 1")).scalars().first()
session.execute(text("SELECT 1"))
cursor.execute("SELECT 1")
cursor.execute("SELECT id, name FROM users WHERE is_active = 1")
"""
    diff = parser.parse_raw_snippet("health.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 SQLi findings for static queries, got: {sqli_findings}"

def test_standalone_fstrings_outside_execute_not_flagged(parser, analyzer):
    code = """
cls_name = "UserView"
origin = "_custom"
err = "Permission denied"
missing = "item_1"

# String with 'delete' or 'update' words outside DB execute calls:
msg1 = f"{cls_name} defines delete_object{origin}, which is deprecated"
msg2 = f"Cannot update the pyproject.toml file : {err}"
msg3 = f"golden not added or updated: {missing}"
print(msg1)
print(msg2)
"""
    diff = parser.parse_raw_snippet("logger.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 SQLi findings for non-DB f-strings, got: {sqli_findings}"

# ---------------- 2. PLACEHOLDER & DUMMY SECRETS (ZERO FALSE POSITIVES) ----------------
def test_dummy_and_placeholder_secrets_not_flagged(parser, analyzer):
    code = """
API_KEY = "your_api_key_here_12345678"
SECRET_KEY = "changeme_please_update_me"
DUMMY_TOKEN = "dummy_token_value_99999"
TEST_TOKEN = "test_token_abcdef123456"
BYPASS_TOKEN = "[skip-governor-footer]"
PLACEHOLDER = "<INSERT_OPENAI_KEY_HERE>"
"""
    diff = parser.parse_raw_snippet("config.py", code)
    res = analyzer.generate_pull_request_review([diff])
    secret_findings = [f for f in res['findings'] if f.cwe_id == "CWE-798"]
    assert len(secret_findings) == 0, f"Expected 0 findings for placeholder tokens, got: {secret_findings}"

def test_js_ui_state_key_not_flagged(parser, analyzer):
    code = """
const FILTER_STATE_KEY = 'djangoOrmLens.filter';
const VIEW_STORAGE_KEY = 'app.views.selectedTab';
"""
    diff = parser.parse_raw_snippet("treeProvider.ts", code)
    res = analyzer.generate_pull_request_review([diff])
    secret_findings = [f for f in res['findings'] if f.cwe_id == "CWE-798"]
    assert len(secret_findings) == 0, f"Expected 0 findings for UI state keys, got: {secret_findings}"

# ---------------- 3. REAL EXPLOITABLE VULNERABILITIES ARE FLAGGED ----------------
def test_real_sql_injection_is_flagged(parser, analyzer):
    code = """
uid = "1 OR 1=1"
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    diff = parser.parse_raw_snippet("db.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1

def test_real_orm_text_injection_is_flagged(parser, analyzer):
    code = """
from sqlalchemy import text
uid = "admin'--"
db.execute(text(f"SELECT * FROM accounts WHERE user_id = '{uid}'"))
"""
    diff = parser.parse_raw_snippet("orm.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1

def test_real_live_secrets_are_flagged(parser, analyzer):
    # Assembled dynamically in test to avoid triggering GitHub remote push protection
    stripe_p = "sk_live_"
    stripe_b = "51Abcdefghijklmnopqrstuvwxyz987654"
    aws_p = "AKIA"
    aws_b = "IOSFODNN7ABCD123"
    code = f"""
STRIPE_SECRET = "{stripe_p}{stripe_b}"
AWS_KEY = "{aws_p}{aws_b}"
"""
    diff = parser.parse_raw_snippet("secrets.py", code)
    res = analyzer.generate_pull_request_review([diff])
    secret_findings = [f for f in res['findings'] if f.cwe_id == "CWE-798"]
    assert len(secret_findings) >= 2
