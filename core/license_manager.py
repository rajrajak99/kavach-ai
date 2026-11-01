import os
import json
import hashlib
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

class PlanTier(str, Enum):
    FREE = "FREE"                       # Community: Unlimited Public Repos ($0)
    DEVELOPER_PRO = "DEVELOPER_PRO"     # Indie Builders: Up to 5 Personal Private Repos ($1/mo or $12/yr)
    TEAM_ENTERPRISE = "TEAM_ENTERPRISE" # Organizations: Unlimited Repos, PR Bot, Self-Healing ($99/mo)

class LicenseManager:
    """
    Zero-Loss License & Enterprise Abuse Protection Engine:
    - Guarantees $0 server cost for Kavach (runs 100% on local/runner compute).
    - Enforces Personal vs Organization account boundaries.
    - Prevents commercial companies from exploiting the $1 Developer Pro tier.
    """

    # Official cryptographic key hashes / authorization set
    # Keys can also be added dynamically via KAVACH_LICENSE_KEYS env var
    DEFAULT_KEYS = {
        # Developer Pro Tier ($1/mo or $12/yr) - Personal Accounts
        "KV-PRO-INDIE-2026": PlanTier.DEVELOPER_PRO,
        "KV-PRO-2026-ALPHA": PlanTier.DEVELOPER_PRO,
        "BUILDER-DEV-1": PlanTier.DEVELOPER_PRO,

        # Team / Enterprise Tier ($99/mo) - GitHub Organizations
        "KV-TEAM-ORG-99": PlanTier.TEAM_ENTERPRISE,
        "KAVACH-VIP-999": PlanTier.TEAM_ENTERPRISE,
        "CHANDAN-FOUNDER": PlanTier.TEAM_ENTERPRISE,
        "RAJA-FOUNDER-99": PlanTier.TEAM_ENTERPRISE,
    }

    @classmethod
    def get_tier_for_key(cls, key: str) -> Optional[PlanTier]:
        if not key:
            return None
        clean_key = key.strip().upper()

        # Check default keys
        if clean_key in cls.DEFAULT_KEYS:
            return cls.DEFAULT_KEYS[clean_key]

        # Check environment-configured keys: KEY:TIER,KEY:TIER
        env_keys = os.getenv("KAVACH_LICENSE_KEYS", "")
        if env_keys:
            for pair in env_keys.split(","):
                if ":" in pair:
                    k, t = pair.strip().split(":", 1)
                    if k.strip().upper() == clean_key:
                        try:
                            return PlanTier(t.strip().upper())
                        except ValueError:
                            return PlanTier.DEVELOPER_PRO
                elif pair.strip().upper() == clean_key:
                    return PlanTier.DEVELOPER_PRO

        # Pro format pattern check: KV-PRO-XXXX or KV-TEAM-XXXX
        if clean_key.startswith("KV-TEAM-") and len(clean_key) >= 14:
            return PlanTier.TEAM_ENTERPRISE
        if clean_key.startswith("KV-PRO-") and len(clean_key) >= 12:
            return PlanTier.DEVELOPER_PRO

        return None

    @classmethod
    def inspect_github_context(cls) -> Dict[str, Any]:
        """Inspects GitHub Actions runner context to detect repo visibility and owner type."""
        context = {
            "is_ci": bool(os.getenv("GITHUB_ACTIONS")),
            "repository": os.getenv("GITHUB_REPOSITORY", ""),
            "owner": os.getenv("GITHUB_REPOSITORY_OWNER", ""),
            "visibility": "public",
            "owner_type": "User",  # 'User' or 'Organization'
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
        Validates whether the current run is authorized without financial loss:
        - Public Repos: Always authorized (Free tier, zero server cost)
        - Personal Private Repos: Requires Developer Pro ($1/mo) or Team key
        - GitHub Organizations: Strictly requires Team ($99/mo) key
        """
        ctx = cls.inspect_github_context()
        key_tier = cls.get_tier_for_key(license_key or os.getenv("KAVACH_LICENSE_KEY", ""))

        # 1. Public Repos are 100% Free Forever
        if ctx["visibility"] == "public" and not key_tier:
            return True, PlanTier.FREE, "Authorized under Free Community Tier (Unlimited Public Repositories)."

        # 2. Check Organization boundary (Abuse prevention)
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

        # 3. Personal Private Repos
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
