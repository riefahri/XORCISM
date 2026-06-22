/** teams.ts (routes) — Microsoft Teams alert/notification distribution.
 *  Manage the tenant's Teams incoming-webhook targets + a "Test" button. Admin-only (it is an
 *  org-level delivery config that holds a webhook secret). The actual fan-out happens automatically
 *  inside notifrules.dispatchEvent(). */
import { Router, Request, Response } from "express";
import { clientIp } from "../auth";
import { listWebhooks, addWebhook, setWebhook, deleteWebhook, testWebhook, testWebhookById, redactUrl, configured } from "../teams";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const admin = (req: Request): boolean => !!(req.user && (req.user.isAdmin || req.user.isSuperAdmin));

router.get("/teams/webhooks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const rows = listWebhooks(ten(req)).map((w) => ({
      id: w.WebhookID, name: w.Name, url: redactUrl(w.WebhookUrl), format: w.Format,
      minLevel: w.MinLevel, eventFilter: w.EventFilter, enabled: !!w.Enabled,
    }));
    res.json({ webhooks: rows, configured: configured(ten(req)), envDefault: !!process.env.TEAMS_WEBHOOK_URL });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/teams/webhooks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const url = String(b.url ?? "").trim();
  if (!/^https:\/\/.+/i.test(url)) return void res.status(400).json({ error: "a https webhook URL is required" });
  const out = addWebhook(ten(req), {
    name: b.name ? String(b.name) : undefined, url,
    format: b.format ? String(b.format) : undefined,
    minLevel: b.minLevel ? String(b.minLevel) : undefined,
    eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
  });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "teams_webhook_add", resourceType: "TEAMSWEBHOOK", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/teams/webhooks/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setWebhook(ten(req), Number(req.params.id), {
    enabled: b.enabled != null ? !!b.enabled : undefined,
    minLevel: b.minLevel ? String(b.minLevel) : undefined,
    format: b.format ? String(b.format) : undefined,
    eventFilter: b.eventFilter !== undefined ? (b.eventFilter ? String(b.eventFilter) : null) : undefined,
    name: b.name ? String(b.name) : undefined,
  });
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/teams/webhooks/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  if (!deleteWebhook(ten(req), Number(req.params.id))) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "teams_webhook_delete", resourceType: "TEAMSWEBHOOK", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/teams/test { url, format } OR { id } — send a one-off test card (does NOT persist).
router.post("/teams/test", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (b.id != null) {
    const out = await testWebhookById(ten(req), Number(b.id));
    if (!out) return void res.status(404).json({ error: "not found" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "teams_webhook_test", resourceType: "TEAMSWEBHOOK", resourceKey: String(b.id), ip: clientIp(req) });
    return void res.json({ ok: out.ok, status: out.status, detail: out.body });
  }
  const url = String(b.url ?? "").trim();
  if (!/^https:\/\/.+/i.test(url)) return void res.status(400).json({ error: "a https webhook URL is required" });
  const out = await testWebhook(url, b.format ? String(b.format) : undefined);
  xid.addAudit({ userId: req.user.UserID ?? null, action: "teams_webhook_test", resourceType: "TEAMSWEBHOOK", resourceKey: out.ok ? "ok" : "fail", ip: clientIp(req) });
  res.json({ ok: out.ok, status: out.status, detail: out.body });
});

export default router;
