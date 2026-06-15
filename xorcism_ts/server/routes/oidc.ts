/**
 * oidc.ts (routes) — Generic OAuth2 / OpenID Connect login (discovery + PKCE).
 *
 * Adds to the email/password authentication (XID): "Sign in with…".
 * Authorization Code + PKCE (S256) flow, state + nonce (anti-CSRF / anti-replay).
 * On first login, the user is auto-created (User role, System tenant),
 * linked by verified email.
 *
 * Configuration (environment variables):
 *   OIDC_ISSUER         e.g. https://accounts.google.com  (provider URL)
 *   OIDC_CLIENT_ID
 *   OIDC_CLIENT_SECRET
 *   OIDC_REDIRECT_URI   (optional; otherwise derived from the request: .../api/auth/oidc/callback)
 *   OIDC_SCOPES         (optional; default "openid email profile")
 *
 * Security: no secret is logged; the id_token is obtained directly from the
 * token endpoint over TLS (its signature can be validated by the TLS channel, cf.
 * OIDC §3.1.3.7); iss/aud/exp/nonce are verified; email_verified is required.
 */

import { Router, Request, Response } from "express";
import crypto from "crypto";
import * as xid from "../xid";
import { startSession, clientIp, hashPassword, parseCookies } from "../auth";

const ISSUER = (process.env.OIDC_ISSUER || "").replace(/\/$/, "");
const CLIENT_ID = process.env.OIDC_CLIENT_ID || "";
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || "";
const REDIRECT_URI = process.env.OIDC_REDIRECT_URI || "";
const SCOPES = process.env.OIDC_SCOPES || "openid email profile";

export function oidcEnabled(): boolean {
  return !!(ISSUER && CLIENT_ID && CLIENT_SECRET);
}

const router = Router();

// ── OIDC discovery (.well-known) — cached for 1 h ───────────────────────────
interface OidcMeta {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
}
let metaCache: { meta: OidcMeta; exp: number } | null = null;

async function discover(): Promise<OidcMeta> {
  if (metaCache && metaCache.exp > Date.now()) return metaCache.meta;
  const url = `${ISSUER}/.well-known/openid-configuration`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`discovery ${r.status}`);
  const meta = (await r.json()) as OidcMeta;
  if (!meta.authorization_endpoint || !meta.token_endpoint)
    throw new Error("métadonnées OIDC incomplètes");
  metaCache = { meta, exp: Date.now() + 3600_000 };
  return meta;
}

// ── Ongoing flows: state → { nonce, verifier, exp } (TTL 10 min) ───────────────
const flows = new Map<string, { nonce: string; verifier: string; exp: number }>();
function gcFlows(): void {
  const now = Date.now();
  for (const [k, v] of flows) if (v.exp < now) flows.delete(k);
}

const b64url = (buf: Buffer): string => buf.toString("base64url");

function redirectUri(req: Request): string {
  if (REDIRECT_URI) return REDIRECT_URI;
  const proto = (req.headers["x-forwarded-proto"] as string) || (req.secure ? "https" : "http");
  return `${proto}://${req.headers.host}/api/auth/oidc/callback`;
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length < 2) throw new Error("JWT invalide");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// ── State (to show/hide the button on the login page) ─────────────────
router.get("/oidc/status", (_req: Request, res: Response) => {
  res.json({ enabled: oidcEnabled() });
});

// ── Start: redirects to the provider ────────────────────────────────────
router.get("/oidc/login", async (req: Request, res: Response) => {
  if (!oidcEnabled()) return void res.status(404).send("OIDC non configuré");
  try {
    const meta = await discover();
    gcFlows();
    const state = b64url(crypto.randomBytes(24));
    const nonce = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
    flows.set(state, { nonce, verifier, exp: Date.now() + 600_000 });

    // Browser ↔ flow binding cookie (additional CSRF protection)
    res.cookie("oidc_state", state, {
      httpOnly: true,
      sameSite: "lax", // lax: the cookie must survive the return redirect (GET)
      secure: req.secure || req.headers["x-forwarded-proto"] === "https",
      maxAge: 600_000,
      path: "/api/auth/oidc",
    });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: redirectUri(req),
      scope: SCOPES,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    res.redirect(`${meta.authorization_endpoint}?${params.toString()}`);
  } catch (e) {
    res.status(500).send(`OIDC: erreur de démarrage (${(e as Error).message})`);
  }
});

// ── Callback: exchanges the code, validates, opens a session ──────────────────────
router.get("/oidc/callback", async (req: Request, res: Response) => {
  if (!oidcEnabled()) return void res.status(404).send("OIDC non configuré");
  const code = String(req.query.code || "");
  const state = String(req.query.state || "");
  const cookieState = parseCookies(req)["oidc_state"];
  res.clearCookie("oidc_state", { path: "/api/auth/oidc" });

  const flow = state ? flows.get(state) : undefined;
  if (state) flows.delete(state);
  if (!code || !state || state !== cookieState || !flow || flow.exp < Date.now()) {
    xid.addAudit({ userId: null, action: "oauth_state_invalid", ip: clientIp(req) });
    return void res.status(400).send("OIDC: état invalide ou expiré");
  }

  try {
    const meta = await discover();

    // 1) Code exchange (Authorization Code + PKCE)
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri(req),
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code_verifier: flow.verifier,
    });
    const tokRes = await fetch(meta.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
    });
    if (!tokRes.ok) throw new Error(`token endpoint ${tokRes.status}`);
    const tok = (await tokRes.json()) as { id_token?: string; access_token?: string };
    if (!tok.id_token) throw new Error("id_token manquant");

    // 2) Validation of the id_token claims
    const c = decodeJwtPayload(tok.id_token);
    if (c.iss !== meta.issuer && c.iss !== ISSUER) throw new Error("iss invalide");
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!aud.includes(CLIENT_ID)) throw new Error("aud invalide");
    if (typeof c.exp === "number" && c.exp * 1000 < Date.now()) throw new Error("id_token expiré");
    if (c.nonce !== flow.nonce) throw new Error("nonce invalide");

    // 3) Email (claims, otherwise userinfo)
    let email = typeof c.email === "string" ? c.email : undefined;
    let emailVerified = c.email_verified as boolean | undefined;
    let name = typeof c.name === "string" ? c.name : undefined;
    const sub = typeof c.sub === "string" ? c.sub : "";
    if ((!email || emailVerified === undefined) && meta.userinfo_endpoint && tok.access_token) {
      const ui = await fetch(meta.userinfo_endpoint, {
        headers: { Authorization: `Bearer ${tok.access_token}` },
      });
      if (ui.ok) {
        const u = (await ui.json()) as Record<string, unknown>;
        email = email || (typeof u.email === "string" ? u.email : undefined);
        if (emailVerified === undefined) emailVerified = u.email_verified as boolean | undefined;
        name = name || (typeof u.name === "string" ? u.name : undefined);
      }
    }
    if (!email) throw new Error("email absent des informations du fournisseur");
    if (emailVerified === false) throw new Error("email non vérifié par le fournisseur");

    // 4) Find-or-create (auto-creation: User role, System tenant)
    const ip = clientIp(req);
    let user = xid.findUserByEmail(email);
    if (!user) {
      const systemTenant = xid.ensureTenant("System", true);
      const userRole = xid.ensureRole("User", "Utilisateur standard");
      const randomPw = crypto.randomBytes(24).toString("base64url") + "Aa1!";
      const uid = xid.createUser({
        email,
        displayName: name,
        passwordHash: hashPassword(randomPw),
        mustChange: false,
        tenantId: systemTenant,
      });
      xid.assignRole(uid, userRole);
      xid.addAudit({
        userId: uid,
        action: "oauth_user_created",
        detail: `oidc sub=${sub} email=${email}`,
        ip,
        tenantId: systemTenant,
      });
      user = xid.getUserById(uid);
    }
    if (!user) throw new Error("création de compte impossible");
    if (user.IsLockedOut) {
      xid.addAudit({ userId: user.UserID, action: "login_locked", ip });
      return void res.status(403).send("Compte verrouillé");
    }

    // 5) Opens the session (same mechanism as password login)
    xid.recordLoginSuccess(user.UserID);
    startSession(req, res, user.UserID);
    xid.addAudit({ userId: user.UserID, action: "login_oauth", detail: `oidc sub=${sub}`, ip });
    res.redirect("/");
  } catch (e) {
    xid.addAudit({ userId: null, action: "oauth_login_failed", detail: (e as Error).message, ip: clientIp(req) });
    res.status(400).send(`OIDC: échec de connexion (${(e as Error).message})`);
  }
});

export default router;
