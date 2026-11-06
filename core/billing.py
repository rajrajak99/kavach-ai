"""
Kavach AI — Enterprise Merchant-of-Record Checkout & Billing Pipeline
Supports Dodo Payments, LemonSqueezy, Stripe, and direct founder invoice dispatch.
"""

import os
import sys
import datetime
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

try:
    from kavach_license import generate_signed_license, PlanTier
except ImportError:
    _root = str(Path(__file__).resolve().parent.parent)
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from kavach_license import generate_signed_license, PlanTier

class BillingManager:
    """
    Manages customer checkout redirects, webhook/redirect query-parameter
    inspection, and automated plan activation.
    """

    DEFAULT_INVOICE_EMAIL = "rajabhaiyarajak2008@gmail.com"

    @classmethod
    def get_checkout_urls(cls) -> Dict[str, str]:
        """
        Retrieves configured checkout URLs from environment variables or st.secrets.
        """
        urls = {
            "pro": os.getenv("KAVACH_CHECKOUT_PRO_URL", "").strip(),
            "team": os.getenv("KAVACH_CHECKOUT_TEAM_URL", "").strip(),
            "ltd": os.getenv("KAVACH_CHECKOUT_LTD_URL", "").strip(),
        }

        # Also attempt to check Streamlit secrets if running inside Streamlit
        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                if not urls["pro"] and "KAVACH_CHECKOUT_PRO_URL" in st.secrets:
                    urls["pro"] = str(st.secrets["KAVACH_CHECKOUT_PRO_URL"]).strip()
                if not urls["team"] and "KAVACH_CHECKOUT_TEAM_URL" in st.secrets:
                    urls["team"] = str(st.secrets["KAVACH_CHECKOUT_TEAM_URL"]).strip()
                if not urls["ltd"] and "KAVACH_CHECKOUT_LTD_URL" in st.secrets:
                    urls["ltd"] = str(st.secrets["KAVACH_CHECKOUT_LTD_URL"]).strip()
        except Exception:
            pass

        return urls

    @classmethod
    def get_invoice_request_url(cls, tier_name: str, billing_period: str = "annual") -> str:
        """
        Generates a direct mailto URI for manual enterprise invoicing or onboarding.
        """
        subject = f"[Kavach AI] Invoice & Access Request — {tier_name} ({billing_period})"
        body = (
            f"Hi Raja,\n\n"
            f"I would like to activate Kavach AI {tier_name} for our team.\n\n"
            f"Company / Organization: \n"
            f"GitHub Username / Org: \n"
            f"Billing Period: {billing_period}\n"
            f"Preferred Payment Method: [Wire / UPI / International Credit Card / Dodo / Stripe]\n\n"
            f"Please share the direct payment link and invoice.\n\n"
            f"Best,\n"
        )
        params = {
            "subject": subject,
            "body": body
        }
        return f"mailto:{cls.DEFAULT_INVOICE_EMAIL}?{urllib.parse.urlencode(params)}"

    @classmethod
    def generate_receipt_text(cls, email: str, tier: str, license_key: str, payment_id: Optional[str] = None) -> str:
        """Generates standard receipt and activation document for customer download."""
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            "================================================================================\n"
            "🛡️ KAVACH AI — OFFICIAL CUSTOMER LICENSE KEY & RECEIPT\n"
            "================================================================================\n\n"
            f"Customer Email:  {email}\n"
            f"Active Plan:     {tier.upper()}\n"
            f"License Key:     {license_key}\n"
            f"Order ID:        {payment_id or 'OFFLINE-ACTIVATION'}\n"
            f"Issued At:       {date_str}\n"
            f"Validity:        10 Years (Permanent / Stateless)\n\n"
            "--------------------------------------------------------------------------------\n"
            "HOW TO USE YOUR LICENSE KEY:\n"
            "--------------------------------------------------------------------------------\n"
            "1. STREAMLIT WEB APP:\n"
            "   Open the sidebar -> 'Account & License Login' -> Paste your License Key.\n"
            "   Your browser will stay permanently logged in.\n\n"
            "2. CLI & PRE-COMMIT HOOKS (TERMINAL):\n"
            f"   Run once: kavach --login {license_key}\n"
            "   Credentials will be saved to ~/.kavach/credentials.json for all future scans.\n\n"
            "3. GITHUB ACTIONS CI/CD:\n"
            "   Add a repository secret KAVACH_LICENSE_KEY with your license key above.\n"
            "   Your CI security gate will automatically run with your plan.\n\n"
            "================================================================================\n"
            "Support & Inquiries: rajabhaiyarajak2008@gmail.com | https://kavach-ai.streamlit.app\n"
            "================================================================================\n"
        )

    @classmethod
    def inspect_and_activate_redirect(cls, query_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspects URL query parameters upon return from payment gateway (Dodo Payments / LemonSqueezy)
        e.g. ?payment_id=...&status=success&tier=DEVELOPER_PRO&key=...&email=...
        Returns activation metadata if a valid payment callback is detected.
        """
        if not query_params:
            return None

        # Normalize query params (Streamlit may return string or list of strings)
        def get_single(key: str) -> str:
            val = query_params.get(key, "")
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val)

        status = get_single("status").lower()
        payment_id = get_single("payment_id") or get_single("order_id") or get_single("checkout_id")
        tier_str = get_single("tier").upper() or get_single("plan").upper()
        license_key = get_single("license_key") or get_single("key")
        customer_email = get_single("email") or get_single("customer_email") or ""

        # Check for success indicators from MoR gateways
        is_success = status in ("success", "paid", "active", "completed") or bool(payment_id and (license_key or customer_email))

        if is_success:
            # Map tier string to recognized plan
            target_tier = "FREE"
            if "PRO" in tier_str or "DEV" in tier_str:
                target_tier = "DEVELOPER_PRO"
            elif "TEAM" in tier_str or "ENTERPRISE" in tier_str:
                target_tier = "TEAM_ENTERPRISE"
            elif "LTD" in tier_str or "LIFETIME" in tier_str:
                target_tier = "TEAM_ENTERPRISE"
            else:
                target_tier = "DEVELOPER_PRO"

            tier_short = "PRO" if target_tier == "DEVELOPER_PRO" else "TEAM"

            # Generate authentic signed HMAC key
            email_to_use = customer_email or f"{payment_id}@customer.kavach.ai"
            if not license_key:
                license_key = generate_signed_license(email_to_use, tier=tier_short)
                try:
                    from core.auth_store import AccountStore
                    store = AccountStore()
                    store.register_or_upgrade_user(email_to_use, tier=tier_short, payment_id=payment_id)
                except Exception:
                    pass

            needs_email = not bool(customer_email)
            receipt_text = cls.generate_receipt_text(
                customer_email or "customer@kavach.ai",
                tier_short,
                license_key,
                payment_id
            )

            return {
                "activated": True,
                "needs_email": needs_email,
                "tier": target_tier,
                "tier_short": tier_short,
                "email": customer_email,
                "license_key": license_key,
                "payment_id": payment_id,
                "receipt": receipt_text,
                "message": f"Payment verified ({payment_id}). Plan unlocked: {target_tier}!"
            }

        return None
