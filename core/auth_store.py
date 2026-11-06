"""
Kavach AI — Enterprise User Account & Cloud Persistence Store
Dual-Backend Engine:
1. Primary: Cloud Supabase REST / PostgreSQL (Survives container restarts)
2. Fallback: Local Embedded SQLite (data/kavach_accounts.db)
Stateless HMAC-SHA256 signed license keys and PBKDF2 password security.
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import hmac
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

try:
    from core.license_manager import generate_signed_license, verify_signed_license, PlanTier
except (ImportError, AttributeError):
    try:
        from kavach_license import generate_signed_license, verify_signed_license, PlanTier
    except ImportError:
        _root = str(Path(__file__).resolve().parent.parent)
        if _root not in sys.path:
            sys.path.insert(0, _root)
        from kavach_license import generate_signed_license, verify_signed_license, PlanTier

class AccountStore:
    """
    Manages persistent user accounts, authentication credentials,
    and cryptographic license synchronization.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path).resolve()
        else:
            base_dir = Path(__file__).resolve().parent.parent
            self.db_path = (base_dir / "data" / "kavach_accounts.db").resolve()

        self._init_sqlite()

    def _get_cloud_config(self) -> Tuple[Optional[str], Optional[str]]:
        """Retrieves Supabase / Remote DB credentials from st.secrets or env."""
        url = os.getenv("SUPABASE_URL", "").strip()
        key = os.getenv("SUPABASE_KEY", "").strip() or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        
        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                if not url and "SUPABASE_URL" in st.secrets:
                    url = str(st.secrets["SUPABASE_URL"]).strip()
                if not key and "SUPABASE_KEY" in st.secrets:
                    key = str(st.secrets["SUPABASE_KEY"]).strip()
        except Exception:
            pass

        return (url or None, key or None)

    def _init_sqlite(self):
        """Initializes local SQLite database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS kavach_accounts (
                email TEXT PRIMARY KEY,
                password_hash TEXT,
                salt TEXT,
                tier TEXT NOT NULL DEFAULT 'FREE',
                license_key TEXT,
                payment_id TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hashes password with PBKDF2-SHA256 (100,000 iterations)."""
        if not salt:
            salt = os.urandom(16).hex()
        pwd_bytes = password.encode("utf-8")
        salt_bytes = salt.encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000).hex()
        return key, salt

    @staticmethod
    def verify_password(password: str, password_hash: str, salt: str) -> bool:
        """Verifies password using constant-time comparison."""
        expected_hash, _ = AccountStore.hash_password(password, salt=salt)
        return hmac.compare_digest(password_hash, expected_hash)

    # ----------------- CLOUD SYNCHRONIZATION HELPERS -----------------
    def _sync_to_cloud(self, user_record: Dict[str, Any]) -> bool:
        """Attempts to sync user account to Supabase REST table."""
        supabase_url, supabase_key = self._get_cloud_config()
        if not supabase_url or not supabase_key:
            return False

        try:
            import urllib.request
            endpoint = f"{supabase_url.rstrip('/')}/rest/v1/kavach_accounts"
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates"
            }
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(user_record).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status in (200, 201, 204)
        except Exception:
            return False

    def _fetch_from_cloud(self, email: str) -> Optional[Dict[str, Any]]:
        """Attempts to fetch user account from Supabase REST table."""
        supabase_url, supabase_key = self._get_cloud_config()
        if not supabase_url or not supabase_key:
            return None

        try:
            import urllib.request
            import urllib.parse
            clean_email = email.strip().lower()
            params = urllib.parse.urlencode({"email": f"eq.{clean_email}", "select": "*"})
            endpoint = f"{supabase_url.rstrip('/')}/rest/v1/kavach_accounts?{params}"
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}",
                "Accept": "application/json"
            }
            req = urllib.request.Request(endpoint, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, list) and len(data) > 0:
                        return data[0]
        except Exception:
            pass
        return None

    # ----------------- ACCOUNT MANAGEMENT -----------------
    def register_or_upgrade_user(
        self,
        email: str,
        password: Optional[str] = None,
        tier: str = "PRO",
        payment_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates or updates a user account, generating an HMAC-signed license key.
        Returns the sanitized user dictionary.
        """
        clean_email = email.strip().lower()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Check existing user
        existing = self.get_user_by_email(clean_email, include_secrets=True)

        # Generate fresh HMAC-SHA256 signed license key
        license_key = generate_signed_license(clean_email, tier=tier)

        if existing:
            pwd_hash = existing.get("password_hash")
            salt = existing.get("salt")
            if password:
                pwd_hash, salt = self.hash_password(password)

            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute("""
                UPDATE kavach_accounts
                SET password_hash = ?, salt = ?, tier = ?, license_key = ?, payment_id = ?, updated_at = ?
                WHERE email = ?;
                """, (pwd_hash, salt, tier, license_key, payment_id or existing.get("payment_id"), now_str, clean_email))
                conn.commit()
            finally:
                conn.close()

            created_at = existing.get("created_at", now_str)
        else:
            pwd_hash, salt = ("", "")
            if password:
                pwd_hash, salt = self.hash_password(password)

            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO kavach_accounts (email, password_hash, salt, tier, license_key, payment_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (clean_email, pwd_hash, salt, tier, license_key, payment_id, now_str, now_str))
                conn.commit()
            finally:
                conn.close()

            created_at = now_str

        user_record = {
            "email": clean_email,
            "password_hash": pwd_hash,
            "salt": salt,
            "tier": tier,
            "license_key": license_key,
            "payment_id": payment_id,
            "created_at": created_at,
            "updated_at": now_str
        }

        # Background sync to cloud if available
        self._sync_to_cloud(user_record)

        # Return sanitized record
        return {
            "email": clean_email,
            "tier": tier,
            "license_key": license_key,
            "payment_id": payment_id,
            "created_at": created_at
        }

    def authenticate_user(
        self,
        identifier: str,
        password_or_license_key: str
    ) -> Dict[str, Any]:
        """
        Authenticates a user via either:
        1. Email + Password
        2. Signed KAVACH-... License Key
        """
        clean_id = identifier.strip().lower() if identifier else ""
        clean_secret = password_or_license_key.strip() if password_or_license_key else ""

        # Case 1: License Key Authentication (Stateless or Stored)
        key_candidate = clean_secret if clean_secret.startswith("KAVACH-") else (clean_id if clean_id.startswith("KAVACH-") else "")
        if key_candidate:
            v_res = verify_signed_license(key_candidate)
            if v_res.get("valid"):
                email = v_res["email"]
                tier = v_res["tier"]
                # Look up user or auto-register into local store
                user = self.get_user_by_email(email)
                if not user:
                    user = self.register_or_upgrade_user(email=email, tier=tier)
                else:
                    user["license_key"] = key_candidate
                return {
                    "authenticated": True,
                    "user": user,
                    "error": None
                }
            return {
                "authenticated": False,
                "user": None,
                "error": v_res.get("error", "Invalid or tampered license key.")
            }

        # Case 2: Email + Password Authentication
        if not clean_id or not clean_secret:
            return {
                "authenticated": False,
                "user": None,
                "error": "Email and password are required."
            }

        user_with_secrets = self.get_user_by_email(clean_id, include_secrets=True)
        if not user_with_secrets:
            # Check Cloud DB
            cloud_user = self._fetch_from_cloud(clean_id)
            if cloud_user:
                # Cache into local SQLite
                with sqlite3.connect(str(self.db_path)) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                    INSERT OR REPLACE INTO kavach_accounts (email, password_hash, salt, tier, license_key, payment_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        cloud_user.get("email"), cloud_user.get("password_hash"),
                        cloud_user.get("salt"), cloud_user.get("tier"),
                        cloud_user.get("license_key"), cloud_user.get("payment_id"),
                        cloud_user.get("created_at"), cloud_user.get("updated_at")
                    ))
                    conn.commit()
                user_with_secrets = cloud_user

        if not user_with_secrets:
            return {
                "authenticated": False,
                "user": None,
                "error": "No account found with this email."
            }

        pwd_hash = user_with_secrets.get("password_hash")
        salt = user_with_secrets.get("salt")
        if not pwd_hash or not salt:
            return {
                "authenticated": False,
                "user": None,
                "error": "No password set for this account. Please authenticate with your License Key."
            }

        if self.verify_password(clean_secret, pwd_hash, salt):
            return {
                "authenticated": True,
                "user": {
                    "email": user_with_secrets["email"],
                    "tier": user_with_secrets["tier"],
                    "license_key": user_with_secrets["license_key"],
                    "payment_id": user_with_secrets.get("payment_id"),
                    "created_at": user_with_secrets.get("created_at")
                },
                "error": None
            }

        return {
            "authenticated": False,
            "user": None,
            "error": "Incorrect password. Please verify and try again."
        }

    def get_user_by_email(self, email: str, include_secrets: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieves user by email address."""
        clean_email = email.strip().lower()
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM kavach_accounts WHERE email = ?;", (clean_email,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                if not include_secrets:
                    d.pop("password_hash", None)
                    d.pop("salt", None)
                return d
        finally:
            conn.close()
        return None

    def get_user_by_license(self, license_key: str) -> Optional[Dict[str, Any]]:
        """Retrieves user by their license key."""
        clean_key = license_key.strip()
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM kavach_accounts WHERE license_key = ?;", (clean_key,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d.pop("password_hash", None)
                d.pop("salt", None)
                return d
        finally:
            conn.close()
        return None

_GLOBAL_ACCOUNT_STORE: Optional[AccountStore] = None

def get_account_store(db_path: Optional[str] = None) -> AccountStore:
    """Returns singleton AccountStore instance."""
    global _GLOBAL_ACCOUNT_STORE
    if _GLOBAL_ACCOUNT_STORE is None or db_path is not None:
        _GLOBAL_ACCOUNT_STORE = AccountStore(db_path=db_path)
    return _GLOBAL_ACCOUNT_STORE
