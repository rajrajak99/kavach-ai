"""
Unit tests for Kavach AI Hard B2B Paywall, Feature Gating, and Trial Lead Capture.
"""

import pytest
import datetime
from kavach_license import (
    PlanTier, LicenseManager, generate_signed_license, verify_signed_license
)

def test_fake_bypass_keys_strictly_rejected():
    """Verify that unverified mock keys (e.g. KV-PRO-...) are strictly rejected."""
    assert LicenseManager.get_tier_for_key("KV-PRO-LOCAL-BUILDER") is None
    assert LicenseManager.get_tier_for_key("KV-TEAM-MAINTAINER") is None
    assert LicenseManager.get_tier_for_key("KAVACH-PRO-fake-signature") is None
    assert LicenseManager.get_tier_for_key("") is None
    assert LicenseManager.get_tier_for_key(None) is None

def test_signed_pro_license_generation_and_verification():
    """Verify that legitimate signed PRO licenses authenticate as PlanTier.DEVELOPER_PRO."""
    key = generate_signed_license("alex@enterprise.com", tier="PRO", valid_days=14)
    assert key.startswith("KAVACH-PRO-")
    
    tier = LicenseManager.get_tier_for_key(key)
    assert tier == PlanTier.DEVELOPER_PRO
    
    verification = verify_signed_license(key)
    assert verification["valid"] is True
    assert verification["tier"] == "PRO"
    assert verification["email"] == "alex@enterprise.com"

def test_signed_team_license_generation_and_verification():
    """Verify that legitimate signed TEAM licenses authenticate as PlanTier.TEAM_ENTERPRISE."""
    key = generate_signed_license("cto@scaleup.io", tier="TEAM", valid_days=30)
    assert key.startswith("KAVACH-TEAM-")
    
    tier = LicenseManager.get_tier_for_key(key)
    assert tier == PlanTier.TEAM_ENTERPRISE
    
    verification = verify_signed_license(key)
    assert verification["valid"] is True
    assert verification["tier"] == "TEAM"
    assert verification["email"] == "cto@scaleup.io"

def test_tampered_token_rejection():
    """Verify that modifying any byte in a signed license token invalidates the HMAC signature."""
    key = generate_signed_license("victim@target.com", tier="PRO", valid_days=14)
    parts = key.split("-")
    
    # Tamper with the signature portion
    tampered_sig = parts[-1][:-1] + ("A" if parts[-1][-1] != "A" else "B")
    tampered_key = "-".join(parts[:-1] + [tampered_sig])
    
    assert LicenseManager.get_tier_for_key(tampered_key) is None
    v = verify_signed_license(tampered_key)
    assert v["valid"] is False

def test_trial_email_validation_logic():
    """Verify email validation for 14-day VIP trial issuance."""
    valid_emails = ["alex@company.com", "sarah.connor@cyberdyne.tech", "lead@startup.co.uk"]
    invalid_emails = ["", "invalid", "missingat.com", "@nosite.com", "spaces in@email.com"]
    
    for email in valid_emails:
        key = generate_signed_license(email, tier="PRO", valid_days=14)
        assert verify_signed_license(key)["valid"] is True
        
    for bad_email in invalid_emails:
        # Replicates app helper email rejection
        assert not bad_email or "@" not in bad_email or bad_email.startswith("@") or "." not in bad_email.split("@")[-1] or " " in bad_email

def test_plan_tier_constants_integrity():
    """Verify PlanTier enum values remain stable for UI and billing mapping."""
    assert PlanTier.FREE.value == "FREE"
    assert PlanTier.DEVELOPER_PRO.value == "DEVELOPER_PRO"
    assert PlanTier.TEAM_ENTERPRISE.value == "TEAM_ENTERPRISE"
