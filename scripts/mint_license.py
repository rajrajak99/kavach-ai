"""
Kavach AI - Offline Admin License Minting Engine
(Private Founder Tool - NEVER Commit Private Keys)
"""

import os
import sys
import json
import time
import base64
import argparse
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print("Error: cryptography package is required to mint licenses. Run: pip install cryptography")
    sys.exit(1)

def load_env_file():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if "#" in line:
                    line = line.split("#", 1)[0].strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"\''))

def mint_license(tier: str, subject: str, days: int = 365) -> str:
    load_env_file()
    priv_hex = os.getenv("KAVACH_MASTER_SIGNING_KEY", "")
    if not priv_hex:
        raise RuntimeError("KAVACH_MASTER_SIGNING_KEY not found in environment or .env")

    clean_sub = subject.strip()
    if not clean_sub:
        raise ValueError("Subject cannot be empty or whitespace.")

    tier_clean = tier.strip().upper()
    if tier_clean in ["PRO", "DEVELOPER_PRO"]:
        full_tier = "DEVELOPER_PRO"
        prefix_tag = "PRO"
    elif tier_clean in ["TEAM", "TEAM_ENTERPRISE", "ENTERPRISE"]:
        full_tier = "TEAM_ENTERPRISE"
        prefix_tag = "TEAM"
    else:
        raise ValueError(f"Invalid tier: {tier}. Choose PRO or TEAM.")

    now = int(time.time())
    exp = (now + (days * 86400)) if days != 0 else None

    payload = {
        "tier": full_tier,
        "sub": clean_sub,
        "exp": exp,
        "iat": now
    }

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("utf-8").rstrip("=")

    try:
        priv_bytes = bytes.fromhex(priv_hex.strip())
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    except Exception as e:
        raise RuntimeError(f"Invalid Ed25519 private key in KAVACH_MASTER_SIGNING_KEY: {e}")
    
    # Sign the canonical prefix + payload string to prevent prefix swapping
    message_to_sign = f"KAVACH-{prefix_tag}-{payload_b64}"
    sig = priv_key.sign(message_to_sign.encode("utf-8"))
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

    token = f"{message_to_sign}.{sig_b64}"
    return token

def main():
    parser = argparse.ArgumentParser(description="Kavach AI Founder License Minting CLI")
    parser.add_argument("--tier", choices=["pro", "team"], required=True, help="License tier (pro or team)")
    parser.add_argument("--sub", required=True, help="Licensed GitHub username or Organization slug")
    parser.add_argument("--days", type=int, default=365, help="Validity period in days (default: 365, 0 = lifetime)")
    args = parser.parse_args()

    if args.days < 0:
        print("Error: Validity days cannot be negative.", file=sys.stderr)
        sys.exit(1)

    try:
        token = mint_license(tier=args.tier, subject=args.sub, days=args.days)
    except Exception as e:
        print(f"Error minting license: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n=======================================================")
    print("  🛡️ Kavach AI - Cryptographically Signed License Token")
    print("=======================================================")
    print(f"Subject:   {args.sub.strip()}")
    print(f"Tier:      {args.tier.upper()}")
    print(f"Validity:  {args.days} days" if args.days > 0 else "Validity:  LIFETIME")
    print(f"Token:\n{token}\n")
    print("Instructions for Customer:")
    print(f"  CLI:    kavach <path> --license-key \"{token}\"")
    print(f"  GitHub: Set secret KAVACH_LICENSE_KEY = \"{token}\"")
    print("=======================================================\n")

if __name__ == "__main__":
    main()
