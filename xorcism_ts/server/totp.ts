/**
 * totp.ts — RFC 6238 time-based one-time passwords (authenticator-app 2FA), stdlib crypto only.
 *
 * The TOTP option that complements the WebAuthn/passkey support (webauthn.ts): a 6-digit code from
 * Google Authenticator / Authy / 1Password etc., as a second factor on top of the password. Opt-in
 * per user (XUSER.TotpEnabled); the login flow only requires it for users who have enrolled.
 *
 * Verified against the RFC 6238 Appendix B test vectors (see tools/totp_test in the harness).
 */
import crypto from "crypto";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP = 30;     // seconds
const DIGITS = 6;
const WINDOW = 1;    // accept +/- 1 time-step (clock skew)

/** A new 20-byte (160-bit) base32 secret. */
export function randomSecret(): string {
  const buf = crypto.randomBytes(20);
  return base32Encode(buf);
}

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = (s || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

/** HMAC-based OTP (RFC 4226) for a given counter. */
function hotp(secretB32: string, counter: number): string {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  // 64-bit big-endian counter (safe for the next ~290k years of unix time / 30s)
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (bin % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

/** The current TOTP code (mostly for tests). */
export function totpCode(secretB32: string, nowMs = Date.now()): string {
  return hotp(secretB32, Math.floor(nowMs / 1000 / STEP));
}

/** Constant-time check of a user-supplied 6-digit code against the secret (+/- WINDOW steps). */
export function verifyTotp(secretB32: string, code: string, nowMs = Date.now()): boolean {
  const c = (code || "").replace(/\D/g, "");
  if (c.length !== DIGITS || !secretB32) return false;
  const counter = Math.floor(nowMs / 1000 / STEP);
  for (let w = -WINDOW; w <= WINDOW; w++) {
    const expected = hotp(secretB32, counter + w);
    // length-equal constant-time compare
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(c))) return true;
  }
  return false;
}

/** otpauth:// provisioning URI for the QR code / manual entry. */
export function otpauthUri(secretB32: string, account: string, issuer = "XORCISM"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret: secretB32, issuer, algorithm: "SHA1", digits: String(DIGITS), period: String(STEP) });
  return `otpauth://totp/${label}?${params.toString()}`;
}
