"""
Kavach AI — Unit Tests for Authentication, Stateless Cryptographic Licensing & Cloud Persistence
Covers:
1. HMAC-SHA256 Stateless License Generator & Verifier (Tamper resistance & Expiry)
2. LicenseManager PlanTier Resolution for Signed Keys
3. AccountStore (PBKDF2 Hashing, Registration, Upgrade, Dual-Auth)
4. CLI Local Credential Persistence (~/.kavach/credentials.json)
5. BillingManager Receipt Generation
"""

import os
import sys
import json
import pytest
from pathlib import Path

# Add project root to path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from kavach_license import (
    generate_signed_license,
    verify_signed_license,
    LicenseManager,
    PlanTier
)
from core.auth_store import AccountStore, get_account_store
from core.billing import BillingManager
from cli import save_credentials, load_persisted_license, clear_credentials, CREDS_FILE


class TestStatelessHMACLicenseEngine:
    def test_generate_and_verify_pro_license(self):
        email = "alice@example.com"
        key = generate_signed_license(email, tier="PRO", valid_days=365)
        assert key.startswith("KAVACH-PRO-")
        
        res = verify_signed_license(key)
        assert res["valid"] is True
        assert res["email"] == email
        assert res["tier"] == "PRO"
        assert len(res["expires"]) == 8  # YYYYMMDD

    def test_generate_and_verify_team_license(self):
        email = "enterprise@bigcorp.io"
        key = generate_signed_license(email, tier="TEAM", valid_days=730)
        assert key.startswith("KAVACH-TEAM-")
        
        res = verify_signed_license(key)
        assert res["valid"] is True
        assert res["email"] == email
        assert res["tier"] == "TEAM"

    def test_tamper_rejection_tier_escalation(self):
        """Tampering with tier prefix (e.g. changing PRO to LTD or TEAM) MUST fail."""
        email = "attacker@evil.com"
        pro_key = generate_signed_license(email, tier="PRO")
        # Attacker attempts to change 'PRO' to 'TEAM' or 'LTD' in the key string
        forged_key = pro_key.replace("KAVACH-PRO-", "KAVACH-TEAM-")
        
        res = verify_signed_license(forged_key)
        assert res["valid"] is False
        assert "tampered" in res.get("error", "").lower() or "verification failed" in res.get("error", "").lower()

    def test_tamper_rejection_signature_corruption(self):
        """Corrupted signature must fail verification."""
        email = "user@test.org"
        key = generate_signed_license(email, tier="PRO")
        parts = key.split("-")
        parts[-1] = "A" * len(parts[-1])  # Corrupt HMAC signature
        corrupted_key = "-".join(parts)

        res = verify_signed_license(corrupted_key)
        assert res["valid"] is False
        assert "tampered" in res.get("error", "").lower() or "verification failed" in res.get("error", "").lower()

    def test_expired_license_rejection(self):
        """Keys past expiration date must be rejected."""
        email = "past@test.org"
        # Generate key with negative validity to simulate expired token
        expired_key = generate_signed_license(email, tier="PRO", valid_days=-5)
        res = verify_signed_license(expired_key)
        assert res["valid"] is False
        assert "expired" in res.get("error", "").lower()

    def test_license_manager_resolves_signed_keys(self):
        """LicenseManager.get_tier_for_key recognizes HMAC-SHA256 keys."""
        pro_key = generate_signed_license("dev@kavach.ai", tier="PRO")
        team_key = generate_signed_license("team@kavach.ai", tier="TEAM")
        ltd_key = generate_signed_license("founder@kavach.ai", tier="LTD")

        assert LicenseManager.get_tier_for_key(pro_key) == PlanTier.DEVELOPER_PRO
        assert LicenseManager.get_tier_for_key(team_key) == PlanTier.TEAM_ENTERPRISE
        assert LicenseManager.get_tier_for_key(ltd_key) == PlanTier.TEAM_ENTERPRISE
        assert LicenseManager.get_tier_for_key("KAVACH-PRO-INVALID-FAKE-KEY") is None


class TestAccountStorePersistence:
    @pytest.fixture
    def temp_store(self, tmp_path):
        db_path = tmp_path / "test_accounts.db"
        store = AccountStore(db_path=str(db_path))
        yield store

    def test_registration_and_password_auth(self, temp_store):
        email = "developer@startup.com"
        password = "SecurePassword123!"

        user = temp_store.register_or_upgrade_user(email, password=password, tier="FREE")
        assert user["email"] == email
        assert user["tier"] == "FREE"
        assert user["license_key"].startswith("KAVACH-")

        # Authenticate with correct password
        auth_success = temp_store.authenticate_user(email, password)
        assert auth_success["authenticated"] is True
        assert auth_success["user"]["email"] == email
        assert "password_hash" not in auth_success["user"]

        # Authenticate with wrong password
        auth_fail = temp_store.authenticate_user(email, "WrongPassword!")
        assert auth_fail["authenticated"] is False
        assert "Incorrect password" in auth_fail["error"]

    def test_authenticate_with_license_key(self, temp_store):
        email = "contractor@client.com"
        user = temp_store.register_or_upgrade_user(email, tier="PRO")
        lic_key = user["license_key"]

        # Authenticate by passing license key as credential
        auth_res = temp_store.authenticate_user(email, lic_key)
        assert auth_res["authenticated"] is True
        assert auth_res["user"]["email"] == email
        assert auth_res["user"]["tier"] == "PRO"

    def test_upgrade_user_tier(self, temp_store):
        email = "upgrading_user@tech.co"
        temp_store.register_or_upgrade_user(email, password="InitialPassword1", tier="FREE")

        # Upgrade user to TEAM
        upgraded = temp_store.register_or_upgrade_user(email, tier="TEAM", payment_id="pay_123456")
        assert upgraded["tier"] == "TEAM"
        assert "KAVACH-TEAM-" in upgraded["license_key"]

        # Verify retrieved user
        stored = temp_store.get_user_by_email(email)
        assert stored["tier"] == "TEAM"
        assert stored["payment_id"] == "pay_123456"

    def test_stateless_license_auth_without_prior_registration(self, temp_store):
        """Authenticating with a cryptographically valid key auto-enrolls user."""
        email = "offline_buyer@corp.com"
        valid_key = generate_signed_license(email, tier="PRO")

        auth_res = temp_store.authenticate_user(email, valid_key)
        assert auth_res["authenticated"] is True
        assert auth_res["user"]["tier"] == "PRO"

        # Verify user is now persisted in store
        in_db = temp_store.get_user_by_email(email)
        assert in_db is not None
        assert in_db["license_key"] == valid_key


class TestCLIPersistence:
    def test_cli_save_load_and_clear_credentials(self, tmp_path, monkeypatch):
        test_creds_file = tmp_path / "credentials.json"
        monkeypatch.setattr("cli.CREDS_FILE", test_creds_file)

        test_key = generate_signed_license("cli_tester@domain.com", "PRO")
        
        # 1. Save
        saved = save_credentials(test_key, "cli_tester@domain.com", "PRO", "20361103")
        assert saved is True
        assert test_creds_file.exists()

        # 2. Load
        loaded_key = load_persisted_license()
        assert loaded_key == test_key

        # 3. Clear
        cleared = clear_credentials()
        assert cleared is True
        assert not test_creds_file.exists()


class TestBillingReceiptGeneration:
    def test_generate_receipt_text(self):
        email = "founder@startup.io"
        key = generate_signed_license(email, tier="TEAM")
        payment_id = "dodo_ch_888999"

        receipt = BillingManager.generate_receipt_text(email, "TEAM", key, payment_id)
        assert "OFFICIAL CUSTOMER LICENSE KEY & RECEIPT" in receipt
        assert email in receipt
        assert "TEAM" in receipt
        assert key in receipt
        assert payment_id in receipt
        assert "kavach --login" in receipt
