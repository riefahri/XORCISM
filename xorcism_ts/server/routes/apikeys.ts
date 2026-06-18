/**
 * apikeys.ts (routes) — manage your own API keys (session-authenticated).
 * Creating/revoking keys requires a real session, not an API key, so a leaked
 * key cannot mint more keys.
 */
import { Router, Request, Response } from "express";
import * as xid from "../xid";
import { generateApiKey, normalizeScopes } from "../apikey";

const router = Router();
const viaKey = (req: Request): boolean => (req as Request & { apiKeyId?: number }).apiKeyId != null;

// GET /api/apikeys — list the caller's keys (no secrets)
router.get("/apikeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json({ keys: xid.listApiKeys(req.user.UserID) });
});

// POST /api/apikeys { name } — create a key; the raw value is returned ONCE
router.post("/apikeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (viaKey(req)) return void res.status(403).json({ error: "use a logged-in session to manage keys" });
  const name = String(req.body?.name ?? "").trim().slice(0, 80) || "API key";
  const scopes = normalizeScopes(req.body?.scopes ?? req.body?.scope);
  const expiresInDays = Number(req.body?.expiresInDays) > 0 ? Number(req.body?.expiresInDays) : null;
  const { raw, hash, prefix } = generateApiKey();
  const record = xid.createApiKey({ userId: req.user.UserID, tenantId: req.user.tenantId, name, prefix, keyHash: hash, scopes, expiresInDays });
  res.json({ key: raw, record }); // raw shown once — never retrievable again
});

// DELETE /api/apikeys/:id — revoke one of the caller's keys
router.delete("/apikeys/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (viaKey(req)) return void res.status(403).json({ error: "use a logged-in session to manage keys" });
  res.json({ revoked: xid.revokeApiKey(Number(req.params.id), req.user.UserID) });
});

export default router;
