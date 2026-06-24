/**
 * auth.ts (routes) — /api/auth/login, /logout, /me, /change-password
 * OWASP measures: generic errors, anti-brute-force (lockout + IP rate limit),
 * password policy, session regeneration on login.
 */

import crypto from "crypto";
import { Router, Request, Response } from "express";
import * as xid from "../xid";
import {
  hashPassword,
  verifyPassword,
  startSession,
  endSession,
  clientIp,
  passwordPolicyError,
  parseCookies,
  userCanPage,
} from "../auth";
import { tr } from "../i18n";
import { honeypotTriggered } from "../antibot";
import { verifyRegistration, verifyAssertion, bufToB64url } from "../webauthn";
import { randomSecret, verifyTotp, otpauthUri } from "../totp";

const router = Router();

// Simple per-IP rate limiting (anti-brute-force) — in-memory sliding window
const ipHits = new Map<string, { count: number; first: number }>();
const RL_WINDOW_MS = 15 * 60 * 1000;
const RL_MAX = 20;

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const e = ipHits.get(ip);
  if (!e || now - e.first > RL_WINDOW_MS) {
    ipHits.set(ip, { count: 1, first: now });
    return false;
  }
  e.count++;
  return e.count > RL_MAX;
}

// POST /api/auth/login
router.post("/login", (req: Request, res: Response) => {
  const ip = clientIp(req);
  const { email, password } = req.body as { email?: string; password?: string };

  if (rateLimited(ip)) {
    xid.addAudit({ userId: null, action: "login_ratelimited", detail: email, ip });
    return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  }

  // Generic error message to avoid revealing whether the account exists (OWASP)
  const GENERIC = tr(req, "err.badCredentials");
  if (!email || !password) return void res.status(400).json({ error: GENERIC });

  const user = xid.findUserByEmail(email);
  if (!user) {
    xid.addAudit({ userId: null, action: "login_failed", detail: `inconnu:${email}`, ip });
    return void res.status(401).json({ error: GENERIC });
  }
  if (user.IsLockedOut) {
    xid.addAudit({ userId: user.UserID, action: "login_locked", ip });
    return void res.status(403).json({ error: tr(req, "err.accountLocked") });
  }
  if (!verifyPassword(password, user.PasswordHash)) {
    xid.recordLoginFailure(user.UserID);
    xid.addAudit({ userId: user.UserID, action: "login_failed", ip });
    return void res.status(401).json({ error: GENERIC });
  }

  // Password OK. If the user enrolled an authenticator app (TOTP), require the second
  // factor before opening a session: issue a short-lived pending token, do NOT start a
  // session yet. The client then POSTs /totp/verify with the 6-digit code.
  if (user.TotpEnabled) {
    purgePendingTotp();
    const pendingToken = crypto.randomBytes(24).toString("base64url");
    pendingTotp.set(pendingToken, { userId: user.UserID, expires: Date.now() + TOTP_PENDING_TTL });
    xid.addAudit({ userId: user.UserID, action: "login_totp_required", ip });
    return void res.json({ totpRequired: true, pendingToken });
  }

  // Success: regenerates the session (fixation), logs
  xid.recordLoginSuccess(user.UserID);
  startSession(req, res, user.UserID);
  xid.addAudit({ userId: user.UserID, action: "login", ip });
  res.json({
    ok: true,
    mustChangePassword: !!user.MustChangePassword,
    email: user.Email,
  });
});

// ── TOTP (authenticator-app 2FA, RFC 6238) ───────────────────────────────────
// Opt-in second factor (XUSER.TotpEnabled). A successful password login for an
// enrolled user yields a short-lived pending token; the code is then submitted to
// /totp/verify which finally opens the session.
const TOTP_RE = /^[0-9]{6}$/;
const TOTP_PENDING_TTL = 5 * 60 * 1000;
interface PendingTotp { userId: number; expires: number }
const pendingTotp = new Map<string, PendingTotp>();
function purgePendingTotp(): void {
  const now = Date.now();
  for (const [k, v] of pendingTotp) if (v.expires < now) pendingTotp.delete(k);
}

// POST /api/auth/totp/verify { pendingToken, code } — public, 2nd step of login
router.post("/totp/verify", (req: Request, res: Response) => {
  const ip = clientIp(req);
  const GENERIC = tr(req, "err.badCredentials");
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  purgePendingTotp();
  const { pendingToken, code } = req.body as { pendingToken?: string; code?: string };
  const pend = pendingToken ? pendingTotp.get(pendingToken) : undefined;
  if (!pend || pend.expires < Date.now()) {
    return void res.status(401).json({ error: GENERIC });
  }
  const user = xid.getUserById(pend.userId);
  if (!user || !user.TotpEnabled || !user.TotpSecret) {
    pendingTotp.delete(pendingToken!);
    return void res.status(401).json({ error: GENERIC });
  }
  if (user.IsLockedOut) {
    pendingTotp.delete(pendingToken!);
    return void res.status(403).json({ error: tr(req, "err.accountLocked") });
  }
  if (!TOTP_RE.test(String(code || "")) || !verifyTotp(user.TotpSecret, String(code))) {
    xid.recordLoginFailure(user.UserID); // shares the lockout counter
    xid.addAudit({ userId: user.UserID, action: "login_totp_failed", ip });
    return void res.status(401).json({ error: GENERIC });
  }
  pendingTotp.delete(pendingToken!); // single use
  xid.recordLoginSuccess(user.UserID);
  startSession(req, res, user.UserID);
  xid.addAudit({ userId: user.UserID, action: "login_totp", ip });
  res.json({ ok: true, mustChangePassword: !!user.MustChangePassword, email: user.Email });
});

// GET /api/auth/totp/status — authenticated → { enabled }
router.get("/totp/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const u = xid.getUserById(req.user.UserID);
  res.json({ enabled: !!u?.TotpEnabled });
});

// POST /api/auth/totp/enroll — authenticated → generates a fresh (un-activated) secret
router.post("/totp/enroll", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const secret = randomSecret();
  // Stored but not yet enabled — only activation (a verified code) flips TotpEnabled on.
  xid.setUserTotp(req.user.UserID, secret, 0);
  xid.addAudit({ userId: req.user.UserID, action: "totp_enroll", ip: clientIp(req) });
  res.json({ secret, otpauthUri: otpauthUri(secret, req.user.Email) });
});

// POST /api/auth/totp/activate { code } — authenticated → confirms enrolment
router.post("/totp/activate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const u = xid.getUserById(req.user.UserID);
  if (!u?.TotpSecret) return void res.status(400).json({ error: tr(req, "totp.notEnrolled") });
  const code = String((req.body as { code?: string }).code || "");
  if (!TOTP_RE.test(code) || !verifyTotp(u.TotpSecret, code)) {
    return void res.status(400).json({ error: tr(req, "totp.badCode") });
  }
  xid.setUserTotp(req.user.UserID, u.TotpSecret, 1);
  xid.addAudit({ userId: req.user.UserID, action: "totp_activate", ip: clientIp(req) });
  res.json({ ok: true, enabled: true });
});

// POST /api/auth/totp/disable { code } — authenticated → turns 2FA off (requires a valid code)
router.post("/totp/disable", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const u = xid.getUserById(req.user.UserID);
  if (!u?.TotpEnabled || !u.TotpSecret) return void res.json({ ok: true, enabled: false });
  const code = String((req.body as { code?: string }).code || "");
  if (!TOTP_RE.test(code) || !verifyTotp(u.TotpSecret, code)) {
    return void res.status(400).json({ error: tr(req, "totp.badCode") });
  }
  xid.setUserTotp(req.user.UserID, null, 0);
  xid.addAudit({ userId: req.user.UserID, action: "totp_disable", ip: clientIp(req) });
  res.json({ ok: true, enabled: false });
});

// ── PIN authentication (scrambled keypad, bank style) ─────────────────
// The keypad shows the digits 0-9 at randomly drawn positions for each
// challenge. The client sends the clicked POSITIONS (never the digits); the PIN
// is therefore not typed on the keyboard (anti-keylogger) and the order changes on every
// login (anti replay / shoulder-surfing).
const PIN_RE = /^[0-9]{4,6}$/;
interface PinChallenge { lowered: string; perm: number[]; expires: number }
const pinChallenges = new Map<string, PinChallenge>();
const PIN_CHALLENGE_TTL = 2 * 60 * 1000;

function purgePinChallenges(): void {
  const now = Date.now();
  for (const [k, v] of pinChallenges) if (v.expires < now) pinChallenges.delete(k);
}

// GET /api/auth/pin-challenge?email=… → { challengeId, layout:[d@pos0..d@pos9] }
router.get("/pin-challenge", (req: Request, res: Response) => {
  const ip = clientIp(req);
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  purgePinChallenges();
  const email = String(req.query.email || "").trim().toLowerCase();
  // Random permutation of the digits 0-9 (Fisher-Yates, cryptographic RNG).
  const perm = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  for (let i = perm.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  const challengeId = crypto.randomBytes(18).toString("base64url");
  pinChallenges.set(challengeId, { lowered: email, perm, expires: Date.now() + PIN_CHALLENGE_TTL });
  // layout[pos] = digit shown on the button at this position
  res.json({ challengeId, layout: perm });
});

// POST /api/auth/pin-login { email, challengeId, positions:[…] }
router.post("/pin-login", (req: Request, res: Response) => {
  const ip = clientIp(req);
  const GENERIC = tr(req, "err.badCredentials");
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  const { email, challengeId, positions } = req.body as { email?: string; challengeId?: string; positions?: number[] };
  if (!email || !challengeId || !Array.isArray(positions)) return void res.status(400).json({ error: GENERIC });

  const ch = pinChallenges.get(challengeId);
  pinChallenges.delete(challengeId); // single use
  const lowered = String(email).trim().toLowerCase();
  if (!ch || ch.expires < Date.now() || ch.lowered !== lowered) {
    xid.addAudit({ userId: null, action: "pin_login_failed", detail: "challenge", ip });
    return void res.status(401).json({ error: GENERIC });
  }
  // Reconstructs the PIN from the clicked positions: digit = perm[position].
  if (positions.length < 4 || positions.length > 6 ||
      positions.some((p) => !Number.isInteger(p) || p < 0 || p > 9)) {
    return void res.status(401).json({ error: GENERIC });
  }
  const pin = positions.map((p) => ch.perm[p]).join("");

  const user = xid.findUserByEmail(lowered);
  if (!user || !user.PinHash) {
    xid.addAudit({ userId: user?.UserID ?? null, action: "pin_login_failed", detail: "no-pin", ip });
    return void res.status(401).json({ error: GENERIC });
  }
  if (user.IsLockedOut) return void res.status(403).json({ error: tr(req, "err.accountLocked") });
  if (!verifyPassword(pin, user.PinHash)) {
    xid.recordLoginFailure(user.UserID); // shares the password counter/lockout
    xid.addAudit({ userId: user.UserID, action: "pin_login_failed", ip });
    return void res.status(401).json({ error: GENERIC });
  }
  xid.recordLoginSuccess(user.UserID);
  startSession(req, res, user.UserID);
  xid.addAudit({ userId: user.UserID, action: "pin_login", ip });
  res.json({ ok: true, mustChangePassword: !!user.MustChangePassword, email: user.Email });
});

// POST /api/auth/set-pin { pin } | { clear:true } — authenticated user
router.post("/set-pin", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const b = req.body as { pin?: string; clear?: boolean };
  if (b.clear) {
    xid.setUserPinHash(req.user.UserID, null);
    xid.addAudit({ userId: req.user.UserID, action: "pin_cleared", ip: clientIp(req) });
    return void res.json({ ok: true, pinSet: false });
  }
  const pin = String(b.pin || "");
  if (!PIN_RE.test(pin)) return void res.status(400).json({ error: tr(req, "pin.invalid") });
  // Rejects trivially weak PINs (all identical / simple sequence).
  if (/^(\d)\1+$/.test(pin) || "0123456789".includes(pin) || "9876543210".includes(pin)) {
    return void res.status(400).json({ error: tr(req, "pin.weak") });
  }
  xid.setUserPinHash(req.user.UserID, hashPassword(pin));
  xid.addAudit({ userId: req.user.UserID, action: "pin_set", ip: clientIp(req) });
  res.json({ ok: true, pinSet: true });
});

// ── Passkeys (WebAuthn / FIDO2 / passkeys) ────────────────────────────────
// rpId = host name (without port); origin = scheme://host. WebAuthn only allows
// localhost or a domain in a secure context (HTTPS) — not bare IP addresses.
function rpInfo(req: Request): { rpId: string; origin: string } {
  const host = String(req.headers.host || "localhost");
  const rpId = host.split(":")[0];
  const proto = req.secure || req.headers["x-forwarded-proto"] === "https" ? "https" : "http";
  return { rpId, origin: `${proto}://${host}` };
}

const WA_TTL = 5 * 60 * 1000;
interface WaChallenge { challenge: string; expires: number; userId?: number }
const waChallenges = new Map<string, WaChallenge>();
function purgeWaChallenges(): void {
  const now = Date.now();
  for (const [k, v] of waChallenges) if (v.expires < now) waChallenges.delete(k);
}
function newChallengeId(): string { return crypto.randomBytes(18).toString("base64url"); }

// POST /api/auth/passkey/register/options — authenticated user
router.post("/passkey/register/options", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  purgeWaChallenges();
  const { rpId } = rpInfo(req);
  const challenge = crypto.randomBytes(32).toString("base64url");
  const challengeId = newChallengeId();
  waChallenges.set(challengeId, { challenge, expires: Date.now() + WA_TTL, userId: req.user.UserID });
  res.json({
    challengeId,
    options: {
      challenge,
      rp: { id: rpId, name: "XORCISM" },
      user: {
        id: bufToB64url(Buffer.from(String(req.user.UserID))),
        name: req.user.Email,
        displayName: req.user.DisplayName || req.user.Email,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      timeout: 60000,
      attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      excludeCredentials: xid.credentialIdsForUser(req.user.UserID).map((id) => ({ type: "public-key", id })),
    },
  });
});

// POST /api/auth/passkey/register/verify — authenticated user
router.post("/passkey/register/verify", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const ip = clientIp(req);
  const b = req.body as { challengeId?: string; name?: string; credential?: {
    id?: string; response?: { clientDataJSON?: string; attestationObject?: string; transports?: string[] };
  } };
  const ch = b.challengeId ? waChallenges.get(b.challengeId) : undefined;
  if (b.challengeId) waChallenges.delete(b.challengeId); // single use
  const cred = b.credential;
  if (!ch || ch.expires < Date.now() || ch.userId !== req.user.UserID ||
      !cred?.id || !cred.response?.clientDataJSON || !cred.response?.attestationObject) {
    return void res.status(400).json({ error: tr(req, "err.badRequest") });
  }
  const { rpId, origin } = rpInfo(req);
  try {
    const r = verifyRegistration({
      attestationObjectB64u: cred.response.attestationObject,
      clientDataJSONB64u: cred.response.clientDataJSON,
      expectedChallenge: ch.challenge, expectedOrigin: origin, expectedRpId: rpId,
    });
    if (xid.getWebauthnCredential(r.credentialId)) {
      return void res.status(409).json({ error: "Cette clé d'accès est déjà enregistrée." });
    }
    xid.addWebauthnCredential({
      credentialId: r.credentialId, userId: req.user.UserID, publicKeyJwk: r.publicKeyJwk,
      alg: r.alg, signCount: r.signCount, aaguid: r.aaguid,
      transports: Array.isArray(cred.response.transports) ? cred.response.transports.join(",") : null,
      name: String(b.name || "").trim().slice(0, 80) || "Clé d'accès",
    });
    xid.addAudit({ userId: req.user.UserID, action: "passkey_register", resourceKey: r.credentialId, ip });
    res.json({ ok: true });
  } catch (e) {
    xid.addAudit({ userId: req.user.UserID, action: "passkey_register_failed", detail: (e as Error).message, ip });
    res.status(400).json({ error: (e as Error).message });
  }
});

// POST /api/auth/passkey/login/options — public ({ email? } optional)
router.post("/passkey/login/options", (req: Request, res: Response) => {
  const ip = clientIp(req);
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  purgeWaChallenges();
  const { rpId } = rpInfo(req);
  const challenge = crypto.randomBytes(32).toString("base64url");
  const challengeId = newChallengeId();
  waChallenges.set(challengeId, { challenge, expires: Date.now() + WA_TTL });
  // allowCredentials: restricted to the user's keys if the email is provided
  // (otherwise empty → "discoverable"/resident key). Does not reveal whether the account exists.
  let allow: string[] = [];
  const email = String((req.body as { email?: string })?.email || "").trim();
  if (email) {
    const u = xid.findUserByEmail(email);
    if (u) allow = xid.credentialIdsForUser(u.UserID);
  }
  res.json({
    challengeId,
    options: {
      challenge, rpId, timeout: 60000, userVerification: "preferred",
      allowCredentials: allow.map((id) => ({ type: "public-key", id })),
    },
  });
});

// POST /api/auth/passkey/login/verify — public → opens a session
router.post("/passkey/login/verify", (req: Request, res: Response) => {
  const ip = clientIp(req);
  const GENERIC = tr(req, "err.badCredentials");
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  const b = req.body as { challengeId?: string; credential?: {
    id?: string; response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string };
  } };
  const ch = b.challengeId ? waChallenges.get(b.challengeId) : undefined;
  if (b.challengeId) waChallenges.delete(b.challengeId); // single use
  const cred = b.credential;
  if (!ch || ch.expires < Date.now() || !cred?.id ||
      !cred.response?.clientDataJSON || !cred.response?.authenticatorData || !cred.response?.signature) {
    return void res.status(400).json({ error: GENERIC });
  }
  const stored = xid.getWebauthnCredential(cred.id);
  if (!stored) {
    xid.addAudit({ userId: null, action: "passkey_login_failed", detail: "credential inconnu", ip });
    return void res.status(401).json({ error: GENERIC });
  }
  const user = xid.getUserById(stored.UserID);
  if (!user) return void res.status(401).json({ error: GENERIC });
  if (user.IsLockedOut) return void res.status(403).json({ error: tr(req, "err.accountLocked") });
  const { rpId, origin } = rpInfo(req);
  try {
    const r = verifyAssertion({
      authenticatorDataB64u: cred.response.authenticatorData,
      clientDataJSONB64u: cred.response.clientDataJSON,
      signatureB64u: cred.response.signature,
      publicKeyJwk: stored.PublicKeyJwk, alg: stored.Alg,
      expectedChallenge: ch.challenge, expectedOrigin: origin, expectedRpId: rpId,
      prevSignCount: stored.SignCount,
    });
    xid.updateWebauthnUsage(stored.CredentialID, r.signCount);
    xid.recordLoginSuccess(user.UserID);
    startSession(req, res, user.UserID);
    xid.addAudit({ userId: user.UserID, action: "passkey_login", resourceKey: stored.CredentialID, ip });
    res.json({ ok: true, mustChangePassword: !!user.MustChangePassword, email: user.Email });
  } catch (e) {
    xid.addAudit({ userId: user.UserID, action: "passkey_login_failed", detail: (e as Error).message, ip });
    res.status(401).json({ error: GENERIC });
  }
});

// GET /api/auth/passkeys — list of the user's passkeys
router.get("/passkeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  res.json(xid.listWebauthnCredentials(req.user.UserID));
});

// DELETE /api/auth/passkeys/:id — removes a passkey
router.delete("/passkeys/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const ok = xid.deleteWebauthnCredential(req.user.UserID, String(req.params.id));
  if (ok) xid.addAudit({ userId: req.user.UserID, action: "passkey_delete", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok });
});

// POST /api/auth/logout
router.post("/logout", (req: Request, res: Response) => {
  if (req.user) xid.addAudit({ userId: req.user.UserID, action: "logout", ip: clientIp(req) });
  endSession(req, res);
  res.json({ ok: true });
});

// GET /api/auth/me
router.get("/me", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  res.json({
    email: req.user.Email,
    displayName: req.user.DisplayName,
    isAdmin: req.user.isAdmin,
    isSuperAdmin: req.user.isSuperAdmin,
    tenantId: req.user.tenantId,
    tenantName: req.user.tenantName,
    roles: req.user.roles,
    mustChangePassword: req.user.mustChangePassword,
    pinSet: !!xid.getUserById(req.user.UserID)?.PinHash,
    canPentest: req.user.isAdmin || userCanPage(req.user, "/pentest"),
  });
});

// POST /api/auth/change-password
router.post("/change-password", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });
  const { currentPassword, newPassword } = req.body as {
    currentPassword?: string;
    newPassword?: string;
  };
  const u = xid.getUserById(req.user.UserID);
  if (!u) return void res.status(401).json({ error: tr(req, "err.notAuthenticated") });

  if (!currentPassword || !verifyPassword(currentPassword, u.PasswordHash)) {
    xid.addAudit({ userId: u.UserID, action: "password_change_failed", ip: clientIp(req) });
    return void res.status(400).json({ error: tr(req, "err.currentPwWrong") });
  }
  const policy = passwordPolicyError(newPassword ?? "");
  if (policy) return void res.status(400).json({ error: tr(req, policy) });
  if (newPassword === currentPassword)
    return void res.status(400).json({ error: tr(req, "pw.same") });

  xid.setPassword(u.UserID, hashPassword(newPassword!), 0);
  // Invalidates the other sessions except the current one
  const token = parseCookies(req)["xid_session"];
  xid.deleteUserSessions(u.UserID);
  if (token) startSession(req, res, u.UserID); // new current session
  xid.addAudit({ userId: u.UserID, action: "password_changed", ip: clientIp(req) });
  res.json({ ok: true });
});

// ── Registration (self-service) ────────────────────────────────────────────────────
router.post("/register", (req: Request, res: Response) => {
  if ((process.env.XORCISM_ALLOW_REGISTER ?? "1") === "0")
    return void res.status(403).json({ error: tr(req, "register.disabled") });
  const ip = clientIp(req);
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  // Anti-bot honeypot: filled hidden field ⇒ we simulate a success without creating anything.
  if (honeypotTriggered(req)) { xid.addAudit({ userId: null, action: "register_honeypot", ip }); return void res.json({ ok: true }); }
  const { email, displayName, password } = req.body as { email?: string; displayName?: string; password?: string };
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return void res.status(400).json({ error: tr(req, "register.badEmail") });
  if (xid.findUserByEmail(email))
    return void res.status(409).json({ error: tr(req, "register.exists") });
  const policy = passwordPolicyError(password ?? "");
  if (policy) return void res.status(400).json({ error: tr(req, policy) });

  const envT = Number(process.env.XORCISM_REGISTER_TENANT);
  const tenantId = Number.isFinite(envT) && envT > 0 ? envT : xid.firstNonSystemTenant();
  const uid = xid.createUser({
    email, displayName: (displayName || "").trim() || email.split("@")[0],
    passwordHash: hashPassword(password!), tenantId,
  });
  xid.assignRole(uid, xid.ensureRole("User", "Utilisateur standard"));
  startSession(req, res, uid);
  xid.addAudit({ userId: uid, action: "register", ip });
  res.json({ ok: true, email });
});

// ── Forgotten password → token (1 h); generic message (anti-enumeration) ──────
function baseUrl(req: Request): string {
  if (process.env.XORCISM_BASE_URL) return process.env.XORCISM_BASE_URL.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] as string) || (req.secure ? "https" : "http");
  return `${proto}://${req.headers.host}`;
}

router.post("/forgot", (req: Request, res: Response) => {
  const ip = clientIp(req);
  if (rateLimited(ip)) return void res.status(429).json({ error: tr(req, "err.tooManyAttempts") });
  const { email } = req.body as { email?: string };
  const user = email ? xid.findUserByEmail(email) : undefined;
  if (user && !user.IsLockedOut) {
    const token = xid.createPasswordReset(user.UserID);
    const link = `${baseUrl(req)}/reset?token=${token}`;
    // TODO production: send via SMTP (nodemailer). Without SMTP, the link is logged on the server.
    console.log(`[reset] lien pour ${user.Email} : ${link}`);
    xid.addAudit({ userId: user.UserID, action: "password_forgot", ip });
  }
  res.json({ ok: true });
});

router.post("/reset", (req: Request, res: Response) => {
  const { token, newPassword } = req.body as { token?: string; newPassword?: string };
  const policy = passwordPolicyError(newPassword ?? "");
  if (policy) return void res.status(400).json({ error: tr(req, policy) });
  const uid = token ? xid.consumePasswordReset(token) : null;
  if (!uid) return void res.status(400).json({ error: tr(req, "reset.invalid") });
  xid.setPassword(uid, hashPassword(newPassword!), 0);
  xid.deleteUserSessions(uid);
  startSession(req, res, uid);
  xid.addAudit({ userId: uid, action: "password_reset", ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
