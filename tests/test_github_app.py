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
