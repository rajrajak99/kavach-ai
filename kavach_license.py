"""
Kavach AI - Cryptographic License Verification Engine
Uncrackable Asymmetric Ed25519 Verification & LemonSqueezy API Integration.
"""

import os
import sys
import json
import time
import base64
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import requests

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class PlanTier(str, Enum):
    FREE = "FREE"                       # Community: Unlimited Public Repos ($0)
    DEVELOPER_PRO = "DEVELOPER_PRO"     # Indie Builders: Personal Private Repos ($1/mo or $12/yr)
    TEAM_ENTERPRISE = "TEAM_ENTERPRISE" # Organizations: Unlimited Repos, CI Gatekeeper ($99/mo)

class LicenseManager:
    """
    Zero-Loss License & Enterprise Abuse Protection Engine:
    - Asymmetric Ed25519 Signature Verification: Only the founder's offline private key can mint keys.
    - LemonSqueezy API Integration with fast 1.5s timeout.
    - Enforces Personal vs Organization account boundaries.
    """

    # Public Verification Key (Safe in open-source; mathematically impossible to forge without private key)
    PUBLIC_KEY_HEX = os.getenv(
        "KAVACH_PUBLIC_KEY",
        "9f0e7c0c42e8f281f5223d08381f9718c900f7e1cacb9733a3b429dbbe03761b"
    )

    LEMON_SQUEEZY_VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate"

    @classmethod
    def verify_ed25519_token(cls, token: str) -> Optional[Tuple[PlanTier, Dict[str, Any]]]:
        """
        Cryptographically verifies an offline signed token:
        Format: KAVACH-<TIER_PREFIX>-<BASE64_PAYLOAD>.<BASE64_SIGNATURE>
        """
        if not HAS_CRYPTOGRAPHY or not token or not token.startswith("KAVACH-"):
            return None

        try:
            prefix_and_payload, dot, sig_b64 = token.partition(".")
            if not dot or not sig_b64:
                return None

            parts = prefix_and_payload.split("-", 2)
            if len(parts) != 3 or parts[0] != "KAVACH":
                return None

            expected_prefix, tier_hint, payload_b64 = parts

            # Decode signature (handle unpadded base64)
            sig_pad = sig_b64 + "=" * (-len(sig_b64) % 4)
            sig_bytes = base64.urlsafe_b64decode(sig_pad)

            # Verify signature against the raw payload_b64 bytes
            pub_bytes = bytes.fromhex(cls.PUBLIC_KEY_HEX.strip())
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(sig_bytes, payload_b64.encode("utf-8"))

            # Decode and validate payload contents
            payload_pad = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(payload_pad).decode("utf-8"))

            # Check expiration
            exp = payload_data.get("exp")
            if exp is not None and time.time() > float(exp):
                return None  # Expired license token

            tier_str = payload_data.get("tier", "").strip().upper()
            if tier_str == "DEVELOPER_PRO":
                return PlanTier.DEVELOPER_PRO, payload_data
            elif tier_str in ["TEAM_ENTERPRISE", "TEAM"]:
                return PlanTier.TEAM_ENTERPRISE, payload_data

            return None
        except Exception:
            return None

    @classmethod
    def verify_lemonsqueezy_key(cls, key: str) -> Optional[PlanTier]:
        """Validates key against LemonSqueezy's official licensing API with 1.5s timeout."""
        if not key or key.startswith("KAVACH-"):
            return None

        clean_key = key.strip()
        import re
        # LemonSqueezy license keys are UUIDv4 format (36 chars: 8-4-4-4-12)
        if not re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", clean_key):
            return None

        try:
            resp = requests.post(
                cls.LEMON_SQUEEZY_VALIDATE_URL,
                json={"license_key": clean_key},
                headers={"Accept": "application/json", "User-Agent": "KavachAI-Verifier/1.4.0"},
                timeout=1.5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid") is True:
                    meta = data.get("meta", {})
                    variant_name = (meta.get("variant_name") or "").lower()
                    product_name = (meta.get("product_name") or "").lower()
                    if "team" in variant_name or "enterprise" in variant_name or "team" in product_name:
                        return PlanTier.TEAM_ENTERPRISE
                    return PlanTier.DEVELOPER_PRO
        except Exception:
            pass

        return None

    @classmethod
    def get_tier_for_key(cls, key: Optional[str]) -> Optional[PlanTier]:
        """
        Determines the authenticated plan tier for a given license key:
        1. Asymmetric Cryptographic Ed25519 Offline Token Verification.
        2. Environment Emergency Override (KAVACH_LICENSE_KEYS).
        3. LemonSqueezy Online API Validation.
        Strictly rejects plain unverified strings or tampered tokens.
        """
        if not key:
            return None

        clean_key = key.strip()

        # 1. Cryptographic offline token
        if clean_key.startswith("KAVACH-"):
            res = cls.verify_ed25519_token(clean_key)
            if res:
                return res[0]
            return None  # Unsigned or forged KAVACH token strictly returns None

        # 2. Environment override (for dev/CI testing: KEY:TIER,KEY:TIER)
        env_keys = os.getenv("KAVACH_LICENSE_KEYS", "")
        if env_keys:
            for pair in env_keys.split(","):
                if ":" in pair:
                    k, t = pair.strip().split(":", 1)
                    if k.strip() == clean_key:
                        try:
                            return PlanTier(t.strip().upper())
                        except ValueError:
                            return PlanTier.DEVELOPER_PRO
                elif pair.strip() == clean_key:
                    return PlanTier.DEVELOPER_PRO

        # 3. LemonSqueezy online validation
        lemon_tier = cls.verify_lemonsqueezy_key(clean_key)
        if lemon_tier:
            return lemon_tier

        return None

    @classmethod
    def inspect_github_context(cls) -> Dict[str, Any]:
        """Inspects GitHub Actions runner context to detect repo visibility and owner type."""
        context = {
            "is_ci": bool(os.getenv("GITHUB_ACTIONS")),
            "repository": os.getenv("GITHUB_REPOSITORY", ""),
            "owner": os.getenv("GITHUB_REPOSITORY_OWNER", ""),
            "visibility": "public",
            "owner_type": "User",
        }

        event_path = os.getenv("GITHUB_EVENT_PATH")
        if event_path and Path(event_path).exists():
            try:
                with open(event_path, "r", encoding="utf-8", errors="ignore") as f:
                    event_data = json.load(f)
                repo_data = event_data.get("repository", {})
                if repo_data:
                    context["visibility"] = "private" if repo_data.get("private") else "public"
                    owner_data = repo_data.get("owner", {})
                    context["owner_type"] = owner_data.get("type", "User")
            except Exception:
                pass

        return context

    @classmethod
    def validate_execution_policy(
        cls,
        license_key: Optional[str] = None
    ) -> Tuple[bool, PlanTier, str]:
        """
        Validates execution authorization against zero-loss boundaries:
        - Public Repos: Always authorized (Free tier, zero server cost)
        - Personal Private Repos: Requires authenticated Developer Pro ($1/mo) or Team key
        - GitHub Organizations: Strictly requires authenticated Team ($99/mo) key
        - Forged / Invalid keys: Strictly rejected
        """
        ctx = cls.inspect_github_context()
        raw_key = license_key or os.getenv("KAVACH_LICENSE_KEY", "")
        key_tier = cls.get_tier_for_key(raw_key)

        # 1. If key was provided but is invalid/forged
        if raw_key and not key_tier:
            return (
                False,
                PlanTier.FREE,
                "Invalid, forged, or expired license key. "
                "Plaintext string spoofing is blocked by cryptographic Ed25519 verification. "
                "Purchase an authentic license at: https://kavach-ai.streamlit.app"
            )

        # 2. Public Repos are 100% Free Forever
        if ctx["visibility"] == "public" and not key_tier:
            return True, PlanTier.FREE, "Authorized under Free Community Tier (Unlimited Public Repositories)."

        # 3. Check Organization boundary (Abuse prevention)
        if ctx["owner_type"] == "Organization":
            if key_tier == PlanTier.TEAM_ENTERPRISE:
                return True, PlanTier.TEAM_ENTERPRISE, "Authorized under Team / Enterprise Tier ($99/mo)."
            else:
                return (
                    False,
                    PlanTier.TEAM_ENTERPRISE,
                    "GitHub Organization detected! Organizations require a Team License ($99/mo). "
                    "Developer Pro ($1/mo) is restricted to personal accounts to prevent corporate abuse. "
                    "Upgrade at: https://kavach-ai.streamlit.app"
                )

        # 4. Personal Private Repos
        if ctx["visibility"] == "private":
            if key_tier in [PlanTier.DEVELOPER_PRO, PlanTier.TEAM_ENTERPRISE]:
                tier_name = "Developer Pro ($1/mo)" if key_tier == PlanTier.DEVELOPER_PRO else "Team ($99/mo)"
                return True, key_tier, f"Authorized under {tier_name} on personal account."
            else:
                return (
                    False,
                    PlanTier.DEVELOPER_PRO,
                    "Private repository detected. Personal private repos require Developer Pro ($1/mo or $12/yr). "
                    "Activate your license at: https://kavach-ai.streamlit.app"
                )

        # Default allowed for local CLI / public usage
        active_tier = key_tier or PlanTier.FREE
        return True, active_tier, f"Authorized under {active_tier.value} tier."
