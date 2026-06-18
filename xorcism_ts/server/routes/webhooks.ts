/**
 * webhooks.ts (routes) — manage your outbound webhooks (session-authenticated).
 * Like API keys, these can only be managed from a real session, not via an API key.
 */
import { Router, Request, Response } from "express";
import * as xid from "../xid";
import { generateWebhookSecret, isSafeWebhookUrl, testWebhook, WEBHOOK_EVENTS } from "../webhook";

const router = Router();
const viaKey = (req: Request): boolean => (req as Request & { apiKeyId?: number }).apiKeyId != null;

// GET /api/webhooks — list the caller's webhooks (no secrets) + the catalogue of events
router.get("/webhooks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  res.json({ webhooks: xid.listWebhooks(req.user.UserID), events: WEBHOOK_EVENTS });
});

// POST /api/webhooks { url, events:[] } — register a webhook; the signing secret is returned ONCE
router.post("/webhooks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (viaKey(req)) return void res.status(403).json({ error: "use a logged-in session to manage webhooks" });
  const url = String(req.body?.url ?? "").trim();
  if (!isSafeWebhookUrl(url)) return void res.status(400).json({ error: "url must be a public http(s) endpoint (no localhost/private addresses)" });
  const allowed = new Set<string>([...WEBHOOK_EVENTS, "*"]);
  let events = Array.isArray(req.body?.events) ? (req.body.events as unknown[]).map((e) => String(e)).filter((e) => allowed.has(e)) : [];
  if (!events.length) events = ["*"];
  const secret = generateWebhookSecret();
  // Super-admin hooks are global (TenantID null) so they receive system + all-tenant events,
  // matching how the API dispatches (tenant = null for super-admins).
  const tenantId = req.user.isSuperAdmin ? null : req.user.tenantId;
  const record = xid.createWebhook({ userId: req.user.UserID, tenantId, url, secret, events: events.join(",") });
  res.json({ secret, record }); // secret shown once — used to verify HMAC signatures
});

// DELETE /api/webhooks/:id
router.delete("/webhooks/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (viaKey(req)) return void res.status(403).json({ error: "use a logged-in session to manage webhooks" });
  res.json({ deleted: xid.deleteWebhook(Number(req.params.id), req.user.UserID) });
});

// POST /api/webhooks/:id/test — send a signed test delivery
router.post("/webhooks/:id/test", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const wh = xid.getWebhookOwned(Number(req.params.id), req.user.UserID);
  if (!wh) return void res.status(404).json({ error: "not found" });
  const status = await testWebhook(wh.Url, wh.Secret);
  try { xid.recordWebhookDelivery(wh.WebhookID, status); } catch { /* */ }
  res.json({ status, ok: status >= 200 && status < 300 });
});

export default router;
