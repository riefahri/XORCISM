/**
 * webauthn.ts — WebAuthn / FIDO2 verification ("passkeys") WITHOUT any external
 * dependency, using only Node's `crypto` module.
 *
 * Covers:
 *   • registration (attestation) — trust in the authenticator is delegated:
 *     the user is already authenticated when adding a key, so we don't need to
 *     verify the attestation chain (attestation="none").
 *   • authentication (assertion) — cryptographic verification of the signature.
 *
 * Supported signature algorithms: ES256 (-7, P-256 curve) and RS256
 * (-257). Both use SHA-256.
 */
import crypto from "crypto";

export function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, "base64url");
}
export function bufToB64url(b: Buffer | Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}
function sha256(b: crypto.BinaryLike): Buffer {
  return crypto.createHash("sha256").update(b).digest();
}

// ── Minimal CBOR decoder (RFC 8949) — enough for attestationObject + COSE keys ─
interface CborResult { value: unknown; offset: number }
function decodeCbor(buf: Buffer, offset = 0): CborResult {
  const first = buf[offset++];
  const major = first >> 5;
  const minor = first & 0x1f;
  let len = minor;
  if (minor === 24) { len = buf[offset]; offset += 1; }
  else if (minor === 25) { len = buf.readUInt16BE(offset); offset += 2; }
  else if (minor === 26) { len = buf.readUInt32BE(offset); offset += 4; }
  else if (minor === 27) {
    const hi = buf.readUInt32BE(offset); const lo = buf.readUInt32BE(offset + 4); offset += 8;
    len = hi * 2 ** 32 + lo; // WebAuthn lengths stay within the safe-integer range
  }
  switch (major) {
    case 0: return { value: len, offset };                        // unsigned integer
    case 1: return { value: -1 - len, offset };                   // negative integer
    case 2: return { value: buf.subarray(offset, offset + len), offset: offset + len }; // bytes
    case 3: return { value: buf.subarray(offset, offset + len).toString("utf8"), offset: offset + len };
    case 4: {
      const arr: unknown[] = [];
      for (let i = 0; i < len; i++) { const r = decodeCbor(buf, offset); arr.push(r.value); offset = r.offset; }
      return { value: arr, offset };
    }
    case 5: {
      const m = new Map<unknown, unknown>();
      for (let i = 0; i < len; i++) {
        const k = decodeCbor(buf, offset); offset = k.offset;
        const v = decodeCbor(buf, offset); offset = v.offset;
        m.set(k.value, v.value);
      }
      return { value: m, offset };
    }
    case 6: return decodeCbor(buf, offset); // tag: ignored, we return the tagged value
    case 7:
      if (minor === 20) return { value: false, offset };
      if (minor === 21) return { value: true, offset };
      if (minor === 22) return { value: null, offset };
      return { value: undefined, offset };
    default: throw new Error("CBOR: type majeur non supporté " + major);
  }
}

// ── COSE key → Node KeyObject (via JWK) ─────────────────────────────────────────
interface CoseKey { keyObject: crypto.KeyObject; alg: number }
function coseToKey(cose: Map<number, unknown>): CoseKey {
  const kty = Number(cose.get(1));
  const alg = Number(cose.get(3));
  if (kty === 2) { // EC2
    if (Number(cose.get(-1)) !== 1) throw new Error("COSE: courbe EC non supportée (P-256 requis)");
    const x = cose.get(-2) as Buffer, y = cose.get(-3) as Buffer;
    const jwk = { kty: "EC", crv: "P-256", x: bufToB64url(x), y: bufToB64url(y) } as crypto.JsonWebKey;
    return { keyObject: crypto.createPublicKey({ key: jwk, format: "jwk" }), alg: alg || -7 };
  }
  if (kty === 3) { // RSA
    const n = cose.get(-1) as Buffer, e = cose.get(-2) as Buffer;
    const jwk = { kty: "RSA", n: bufToB64url(n), e: bufToB64url(e) } as crypto.JsonWebKey;
    return { keyObject: crypto.createPublicKey({ key: jwk, format: "jwk" }), alg: alg || -257 };
  }
  throw new Error("COSE: type de clé non supporté (EC2 ou RSA requis)");
}

// ── authenticatorData ───────────────────────────────────────────────────────────
interface AuthData {
  rpIdHash: Buffer; flags: number; signCount: number;
  aaguid?: Buffer; credentialId?: Buffer; cosePublicKey?: Map<number, unknown>;
}
function parseAuthData(buf: Buffer): AuthData {
  let o = 0;
  const rpIdHash = buf.subarray(o, o + 32); o += 32;
  const flags = buf[o]; o += 1;
  const signCount = buf.readUInt32BE(o); o += 4;
  const res: AuthData = { rpIdHash, flags, signCount };
  if (flags & 0x40) { // AT: attested credential data present
    const aaguid = buf.subarray(o, o + 16); o += 16;
    const idLen = buf.readUInt16BE(o); o += 2;
    const credentialId = buf.subarray(o, o + idLen); o += idLen;
    const { value } = decodeCbor(buf, o);
    res.aaguid = aaguid; res.credentialId = credentialId; res.cosePublicKey = value as Map<number, unknown>;
  }
  return res;
}

function checkClientData(clientDataJSON: Buffer, expectedType: string, expectedChallenge: string, expectedOrigin: string): void {
  let cd: { type?: string; challenge?: string; origin?: string };
  try { cd = JSON.parse(clientDataJSON.toString("utf8")); } catch { throw new Error("clientDataJSON illisible"); }
  if (cd.type !== expectedType) throw new Error("clientData.type invalide");
  if (cd.challenge !== expectedChallenge) throw new Error("challenge invalide");
  if (cd.origin !== expectedOrigin) throw new Error("origin invalide");
}

// ── Registration (attestation) ────────────────────────────────────────────────
export interface RegistrationResult {
  credentialId: string; // base64url
  publicKeyJwk: string; // JSON
  alg: number;
  signCount: number;
  aaguid: string;       // base64url
}
export function verifyRegistration(opts: {
  attestationObjectB64u: string; clientDataJSONB64u: string;
  expectedChallenge: string; expectedOrigin: string; expectedRpId: string;
}): RegistrationResult {
  const clientDataJSON = b64urlToBuf(opts.clientDataJSONB64u);
  checkClientData(clientDataJSON, "webauthn.create", opts.expectedChallenge, opts.expectedOrigin);
  const att = decodeCbor(b64urlToBuf(opts.attestationObjectB64u)).value as Map<string, unknown>;
  const authData = att.get("authData");
  if (!Buffer.isBuffer(authData)) throw new Error("authData manquant");
  const ad = parseAuthData(authData);
  if (!(ad.flags & 0x01)) throw new Error("User Presence (UP) manquant");
  if (!ad.rpIdHash.equals(sha256(opts.expectedRpId))) throw new Error("rpIdHash invalide");
  if (!ad.credentialId || !ad.cosePublicKey) throw new Error("données de credential absentes");
  const { keyObject, alg } = coseToKey(ad.cosePublicKey);
  if (alg !== -7 && alg !== -257) throw new Error("algorithme non supporté (ES256/RS256 requis)");
  return {
    credentialId: bufToB64url(ad.credentialId),
    publicKeyJwk: JSON.stringify(keyObject.export({ format: "jwk" })),
    alg,
    signCount: ad.signCount,
    aaguid: ad.aaguid ? bufToB64url(ad.aaguid) : "",
  };
}

// ── Authentication (assertion) ────────────────────────────────────────────────
export function verifyAssertion(opts: {
  authenticatorDataB64u: string; clientDataJSONB64u: string; signatureB64u: string;
  publicKeyJwk: string; alg: number;
  expectedChallenge: string; expectedOrigin: string; expectedRpId: string;
  prevSignCount: number;
}): { signCount: number } {
  const clientDataJSON = b64urlToBuf(opts.clientDataJSONB64u);
  checkClientData(clientDataJSON, "webauthn.get", opts.expectedChallenge, opts.expectedOrigin);
  const authData = b64urlToBuf(opts.authenticatorDataB64u);
  const ad = parseAuthData(authData);
  if (!(ad.flags & 0x01)) throw new Error("User Presence (UP) manquant");
  if (!ad.rpIdHash.equals(sha256(opts.expectedRpId))) throw new Error("rpIdHash invalide");

  const signedData = Buffer.concat([authData, sha256(clientDataJSON)]);
  const keyObject = crypto.createPublicKey({ key: JSON.parse(opts.publicKeyJwk) as crypto.JsonWebKey, format: "jwk" });
  if (!crypto.verify("sha256", signedData, keyObject, b64urlToBuf(opts.signatureB64u)))
    throw new Error("signature invalide");

  // Anti-cloning counter: must increase (0/0 tolerated: authenticator without a counter)
  if (ad.signCount !== 0 && ad.signCount <= opts.prevSignCount)
    throw new Error("signCount non progressif (clonage suspecté)");
  return { signCount: ad.signCount };
}
