import pytest
from core.github_app import GitHubAppDaemon

def test_github_app_installation_event():
    daemon = GitHubAppDaemon(app_id="12345", private_key="test-key", webhook_secret="secret123")
    payload = {
        "action": "created",
        "installation": {
            "id": 999,
            "account": {"login": "EnterpriseAcmeCorp"}
        }
    }
    res = daemon.handle_webhook_event("installation", payload)
    assert res["status"] == "success"
    assert "EnterpriseAcmeCorp" in res["message"]

def test_github_app_pr_opened_event():
    daemon = GitHubAppDaemon()
    payload = {
        "action": "opened",
        "repository": {"full_name": "EnterpriseAcmeCorp/payment-gateway"},
        "pull_request": {"number": 42}
    }
    res = daemon.handle_webhook_event("pull_request", payload)
    assert res["status"] == "success"
    assert res["pr_number"] == 42
    assert res["gate_status"] == "SECURITY_GATE_PASSED"

def test_github_app_webhook_signature_verification():
    import hmac
    import hashlib

    secret = "my_super_secret_webhook_key_123"
    daemon = GitHubAppDaemon(webhook_secret=secret)
    body = b'{"action":"opened","pull_request":{"number":1}}'

    # 1. Missing signature header fails closed
    assert daemon.verify_webhook_signature(body, None) is False
    assert daemon.verify_webhook_signature(body, "") is False

    # 2. Tampered signature fails closed
    assert daemon.verify_webhook_signature(body, "sha256=invalidhexsignature00000") is False

    # 3. Valid HMAC-SHA256 signature succeeds
    expected_hex = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    assert daemon.verify_webhook_signature(body, f"sha256={expected_hex}") is True

def test_github_app_pr_blocks_on_vulnerabilities():
    daemon = GitHubAppDaemon()
    vuln_code = 'import os\n\ndef query_db(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    payload = {
        "action": "opened",
        "repository": {"full_name": "EnterpriseAcmeCorp/payment-gateway"},
        "pull_request": {"number": 43},
        "diff": vuln_code
    }
    res = daemon.handle_webhook_event("pull_request", payload)
    assert res["status"] == "success"
    assert res["gate_status"] == "SECURITY_GATE_FAILED"
    assert res["findings_count"] > 0
