import { NextRequest, NextResponse } from "next/server";
import crypto from "node:crypto";

const DEFAULT_PUBLIC_KEY_HEX = "9f0e7c0c42e8f281f5223d08381f9718c900f7e1cacb9733a3b429dbbe03761b";
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function getMasterSecret(): string {
  const envSecret = process.env.KAVACH_MASTER_SECRET || process.env.KAVACH_MASTER_SIGNING_KEY;
  if (envSecret && envSecret.trim()) {
    return envSecret.trim();
  }
  // Deterministic fallback for local development if environment secret is not set
  return "kavach_master_hmac_secret_2026";
}

function getEd25519PublicKey(): crypto.KeyObject | null {
  try {
    const pubHex = (process.env.KAVACH_MASTER_PUBLIC_KEY || process.env.KAVACH_PUBLIC_KEY || DEFAULT_PUBLIC_KEY_HEX).trim();
    if (pubHex.length !== 64) return null;
    const der = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pubHex, "hex")]);
    return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    return null;
  }
}

function verifyHmacLicense(keyCandidate: string, secret: string): { valid: boolean; tier?: string; email?: string; error?: string } {
  const cleanKey = keyCandidate.trim();
  if (!cleanKey.startsWith("KAVACH-")) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }
  const tokens = cleanKey.split("-");
  if (tokens.length < 5) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  const prefix = tokens[0];
  const tier = tokens[1].toUpperCase();
  const sig = tokens[tokens.length - 1].toUpperCase();
  const expDate = tokens[tokens.length - 2];
  const b64Email = tokens.slice(2, tokens.length - 2).join("-");

  if (prefix !== "KAVACH") {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  // Decode email
  let email = "";
  try {
    email = Buffer.from(b64Email, "base64url").toString("utf-8");
  } catch {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  // Recompute HMAC signature
  const payload = `KAVACH-${tokens[1]}-${b64Email}-${expDate}`;
  const fullSig = crypto.createHmac("sha256", secret).update(payload).digest("hex").toUpperCase();
  const expectedSig32 = fullSig.slice(0, 32);
  const expectedSig12 = fullSig.slice(0, 12);

  const sigBuf = Buffer.from(sig);
  const exp32Buf = Buffer.from(expectedSig32);
  const exp12Buf = Buffer.from(expectedSig12);

  const match32 = sigBuf.length === exp32Buf.length && crypto.timingSafeEqual(sigBuf, exp32Buf);
  const match12 = sigBuf.length === exp12Buf.length && crypto.timingSafeEqual(sigBuf, exp12Buf);

  if (!match32 && !match12) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  // Expiration check: expDate is YYYYMMDD
  const todayStr = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  if (expDate < todayStr) {
    return { valid: false, error: `License expired on ${expDate}` };
  }

  const normalizedTier = (tier === "TEAM" || tier === "LTD" || tier === "ENTERPRISE") ? "TEAM" : "PRO";
  return { valid: true, tier: normalizedTier, email };
}

function verifyEd25519License(token: string): { valid: boolean; tier?: string; sub?: string; error?: string } {
  const cleanToken = token.trim();
  if (!cleanToken.startsWith("KAVACH-") || !cleanToken.includes(".")) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  const dotIdx = cleanToken.indexOf(".");
  const prefixAndPayload = cleanToken.slice(0, dotIdx);
  const sigB64 = cleanToken.slice(dotIdx + 1);

  const parts = prefixAndPayload.split("-", 3);
  if (parts.length !== 3 || parts[0] !== "KAVACH") {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  const tierHint = parts[1].toUpperCase();
  const payloadB64 = parts[2];

  const pubKey = getEd25519PublicKey();
  if (!pubKey) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  let verified = false;
  try {
    const sigBuf = Buffer.from(sigB64, "base64url");
    // Verify against prefixAndPayload (modern format)
    verified = crypto.verify(null, Buffer.from(prefixAndPayload, "utf-8"), pubKey, sigBuf);
    if (!verified) {
      // Legacy fallback: verify against payloadB64
      verified = crypto.verify(null, Buffer.from(payloadB64, "utf-8"), pubKey, sigBuf);
    }
  } catch {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  if (!verified) {
    return { valid: false, error: "Invalid cryptographic signature" };
  }

  try {
    const payloadStr = Buffer.from(payloadB64, "base64url").toString("utf-8");
    const payload = JSON.parse(payloadStr);

    if (payload.exp !== null && payload.exp !== undefined) {
      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec > Number(payload.exp)) {
        return { valid: false, error: "License expired" };
      }
    }

    const payloadTier = (payload.tier || "").toString().toUpperCase();
    if (tierHint === "PRO" && (payloadTier === "DEVELOPER_PRO" || payloadTier === "PRO")) {
      return { valid: true, tier: "PRO", sub: payload.sub };
    } else if (tierHint === "TEAM" && (payloadTier === "TEAM_ENTERPRISE" || payloadTier === "TEAM")) {
      return { valid: true, tier: "TEAM", sub: payload.sub };
    }

    return { valid: false, error: "Invalid cryptographic signature" };
  } catch {
    return { valid: false, error: "Invalid cryptographic signature" };
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = body.action || "activate";

    if (action === "claim_pilot") {
      const email = (body.email || "").trim().toLowerCase();
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
      if (!email || !emailRegex.test(email)) {
        return NextResponse.json(
          { valid: false, error: "Please provide a valid enterprise or developer email address." },
          { status: 400 }
        );
      }

      const b64Email = Buffer.from(email, "utf-8").toString("base64url");
      const exp = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const expDate = exp.toISOString().slice(0, 10).replace(/-/g, "");
      const payload = `KAVACH-PRO-${b64Email}-${expDate}`;
      const secret = getMasterSecret();
      const sig = crypto.createHmac("sha256", secret).update(payload).digest("hex").slice(0, 32).toUpperCase();
      const key = `${payload}-${sig}`;

      return NextResponse.json({
        valid: true,
        key,
        tier: "DEVELOPER_PRO",
        email,
        message: "VIP pilot license generated and cryptographically signed."
      });
    }

    if (action === "activate") {
      const keyCandidate = (body.key || "").trim();
      if (!keyCandidate) {
        return NextResponse.json(
          { valid: false, error: "License key cannot be blank.", message: "License key cannot be blank." },
          { status: 400 }
        );
      }

      if (!keyCandidate.startsWith("KAVACH-")) {
        return NextResponse.json(
          { valid: false, error: "Invalid cryptographic signature", message: "Invalid cryptographic signature" },
          { status: 400 }
        );
      }

      // 1. Ed25519 Token Verification
      if (keyCandidate.includes(".")) {
        const edResult = verifyEd25519License(keyCandidate);
        if (!edResult.valid) {
          return NextResponse.json(
            { valid: false, error: edResult.error || "Invalid cryptographic signature", message: edResult.error || "Invalid cryptographic signature" },
            { status: 400 }
          );
        }
        return NextResponse.json({
          valid: true,
          tier: edResult.tier,
          message: "Cryptographically verified"
        });
      }

      // 2. HMAC-SHA256 Token Verification
      const hmacResult = verifyHmacLicense(keyCandidate, getMasterSecret());
      if (!hmacResult.valid) {
        return NextResponse.json(
          { valid: false, error: hmacResult.error || "Invalid cryptographic signature", message: hmacResult.error || "Invalid cryptographic signature" },
          { status: 400 }
        );
      }

      return NextResponse.json({
        valid: true,
        tier: hmacResult.tier,
        message: "Cryptographically verified"
      });
    }

    return NextResponse.json({ valid: false, error: "Unknown action" }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ valid: false, error: err.message || "License processing error" }, { status: 500 });
  }
}

