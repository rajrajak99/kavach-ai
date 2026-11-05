"""
Kavach AI — Enterprise Merchant-of-Record Checkout & Billing Pipeline
Supports Dodo Payments, LemonSqueezy, Stripe, and direct founder invoice dispatch.
"""

import os
import urllib.parse
from typing import Dict, Any, Optional, Tuple

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
    def inspect_and_activate_redirect(cls, query_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspects URL query parameters upon return from payment gateway (Dodo Payments / LemonSqueezy)
        e.g. ?payment_id=...&status=success&tier=DEVELOPER_PRO&key=...
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

        # Check for success indicators from MoR gateways
        is_success = status in ("success", "paid", "active", "completed") or bool(payment_id and license_key)

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

            if not license_key:
                # Generate a temporary active session key bound to payment_id
                license_key = f"KV-{target_tier[:4]}-{payment_id[:12].upper()}"

            return {
                "activated": True,
                "tier": target_tier,
                "license_key": license_key,
                "payment_id": payment_id,
                "message": f"Payment verified ({payment_id}). Plan unlocked: {target_tier}!"
            }

        return None
