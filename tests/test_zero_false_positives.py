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

def test_string_concatenation_sqli_is_flagged(parser, analyzer):
    code = """
table = "users"
cursor.execute("SELECT * FROM " + table)
"""
    diff = parser.parse_raw_snippet("concat.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1
    # Verify auto-patching never emits '+' concatenation inside suggestion
    for f in sqli_findings:
        assert "+" not in f.fixed_code

def test_ddl_alter_table_concatenation_is_flagged(parser, analyzer):
    code = """
table = "accounts"
cursor.execute("ALTER TABLE " + table + " ADD COLUMN extra VARCHAR(255)")
"""
    diff = parser.parse_raw_snippet("ddl.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1
    for f in sqli_findings:
        assert "+" not in f.fixed_code

def test_orm_text_never_emits_plus_concatenation(parser, analyzer):
    code = """
from sqlalchemy import text
table = "orders"
db.execute(text("SELECT * FROM " + table))
"""
    diff = parser.parse_raw_snippet("orm_concat.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1
    for f in sqli_findings:
        assert "+" not in f.fixed_code
        assert "bindparams" in f.fixed_code or "SECURE DDL" in f.fixed_code

def test_sqlalchemy_orm_where_filter_not_flagged(parser, analyzer):
    code = """
from sqlalchemy import select
from models import Coupon

code = "SUMMER20"
stmt = select(Coupon).where(Coupon.code == code)
result = session.execute(stmt)
"""
    diff = parser.parse_raw_snippet("safe_orm.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 SQLi findings for safe ORM where filter, got: {sqli_findings}"

# ---------------- 4. B2B ZERO FALSE POSITIVES (PLACEHOLDERS, CONSTANTS & TAINT INDIRECTION) ----------------
def test_placeholders_multiplication_not_flagged(parser, analyzer):
    """Confirm placeholders = ','.join('?' * len(ids)) inside queries produces 0 findings."""
    code = """
keys = ["a", "b", "c"]
placeholders = ",".join("?" * len(keys))
query = f"SELECT * FROM embeddings WHERE id IN ({placeholders})"
cursor.execute(query, keys)
cursor.execute(f"SELECT * FROM t WHERE id IN ({','.join('?' * len(keys))})", keys)
"""
    diff = parser.parse_raw_snippet("db_cache.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 SQLi findings for safe placeholder multiplication, got: {sqli_findings}"

def test_uppercase_module_constants_not_flagged(parser, analyzer):
    """Confirm _COLUMNS = 'id, name' inside queries produces 0 findings."""
    code = """
_COLUMNS = "id, name, email, created_at"
TABLE_NAME = "users"
query = f"SELECT {_COLUMNS} FROM {TABLE_NAME} WHERE id = :id"
db.execute(query, {"id": 42})
cursor.execute(f"SELECT {_COLUMNS} FROM users WHERE is_active = 1")
"""
    diff = parser.parse_raw_snippet("queries.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 SQLi findings for uppercase module constants, got: {sqli_findings}"

def test_variable_indirection_sqli_is_flagged(parser, analyzer):
    """Confirm q = f"SELECT * FROM users WHERE name = '{user_input}'"; db.execute(q) IS flagged as CWE-89."""
    code = """
user_input = "admin' OR '1'='1"
q = f"SELECT * FROM users WHERE name = '{user_input}'"
db.execute(q)
"""
    diff = parser.parse_raw_snippet("auth.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1, f"Expected SQLi finding for variable indirection, got: {sqli_findings}"
    assert any(f.cwe_id == "CWE-89" for f in sqli_findings)
    assert any("Variable-Aliased Indirect SQL Injection" in f.category for f in sqli_findings)

def test_pickle_loads_remediation_never_suggests_try_except(parser, analyzer):
    """Confirm CWE-502 remediation recommends HMAC verification or json.loads, never try/except."""
    code = """
import pickle
data = pickle.loads(untrusted_payload)
"""
    diff = parser.parse_raw_snippet("deserializer.py", code)
    res = analyzer.generate_pull_request_review([diff])
    pickle_findings = [f for f in res['findings'] if f.cwe_id == "CWE-502"]
    assert len(pickle_findings) == 1
    assert "try:" not in pickle_findings[0].fixed_code
    assert "except" not in pickle_findings[0].fixed_code
    assert "hmac" in pickle_findings[0].fixed_code.lower() or "json" in pickle_findings[0].fixed_code.lower()

def test_storage_key_names_never_flagged_as_secrets(parser, analyzer):
    """Confirm _KEY_NAME, _COOKIE_NAME, _HEADER, or low-entropy identifiers like 'aso_refresh_token' are never flagged."""
    code = """
const REFRESH_TOKEN_KEY = "aso_refresh_token";
const AUTH_COOKIE_NAME = "jwt_access_cookie";
CSRF_HEADER_NAME = "X-CSRF-TOKEN-KEY"
SESSION_STORAGE_KEY = "user_auth_session"
"""
    diff = parser.parse_raw_snippet("tokens.ts", code)
    res = analyzer.generate_pull_request_review([diff])
    secret_findings = [f for f in res['findings'] if f.cwe_id == "CWE-798"]
    assert len(secret_findings) == 0, f"Expected 0 findings for storage key names, got: {secret_findings}"

def test_asyncpg_indexed_placeholders_and_constant_propagation(parser, analyzer):
    """Verify that PostgreSQL asyncpg $1, $2 placeholders and module constants in join are zero false positive."""
    code = '''
_STARTED_AT_SETTING = "set_config('fraiseql.started_at', 'now', true)"

async def set_session_vars(cursor_or_conn, settings, params):
    is_cursor = hasattr(cursor_or_conn, "execute")
    if is_cursor:
        calls = ["set_config(%s, %s, true)"] * len(settings)
    else:
        calls = [f"set_config(${i}, ${i + 1}, true)" for i in range(1, len(params), 2)]
    statement = "SELECT " + ", ".join([*calls, _STARTED_AT_SETTING])

    if not params:
        await cursor_or_conn.execute(statement)
    elif is_cursor:
        await cursor_or_conn.execute(statement, params)
    else:
        await cursor_or_conn.execute(statement, *params)
'''
    diff = parser.parse_raw_snippet("db.py", code)
    res = analyzer.generate_pull_request_review([diff])
    sqli_findings = [f for f in res['findings'] if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Expected 0 findings for safe asyncpg placeholders, got: {sqli_findings}"

