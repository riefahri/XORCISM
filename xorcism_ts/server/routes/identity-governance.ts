/** identity-governance.ts (routes) — Identity Governance & Administration (IGA / IDMS): access
 * certification campaigns over the IDENTITY inventory + lifecycle posture + revocation worklist.
 * RBAC anchored on XORCISM.IDENTITY (create needs update on the identity resource). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { idgovDashboard, createCampaign, listCampaigns, getCampaign, reviewItem, markActioned, CampaignScope } from "../identitygov";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete") => userCan(req.user, act, "XORCISM", "IDENTITY");

router.get("/identity-governance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(idgovDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/identity-governance/campaign/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const out = getCampaign(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

// POST /api/identity-governance/campaign { name?, scope, dueDate? } — launch a recertification campaign
router.post("/identity-governance/campaign", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { name?: string; description?: string; scope?: string; dueDate?: string };
  try {
    const out = createCampaign({ name: b.name, description: b.description, scope: b.scope as CampaignScope, dueDate: b.dueDate },
      ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "idgov_campaign_create", resourceType: "ACCESSCAMPAIGN", resourceKey: String(out.id), detail: `${b.scope} · ${out.items} items`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/identity-governance/item/:id { decision, comment? } — certify / revoke / delegate
router.post("/identity-governance/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { decision?: string; comment?: string };
  const ok = reviewItem(Number(req.params.id), String(b.decision || ""), b.comment, ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
  if (!ok) return void res.status(400).json({ error: "invalid decision or item not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "idgov_review", resourceType: "ACCESSREVIEWITEM", resourceKey: String(req.params.id), detail: b.decision, ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/identity-governance/item/:id/actioned — mark a revoke decision de-provisioned
router.post("/identity-governance/item/:id/actioned", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const ok = markActioned(Number(req.params.id), ten(req));
  if (!ok) return void res.status(400).json({ error: "not a pending revocation" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "idgov_revocation_actioned", resourceType: "ACCESSREVIEWITEM", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
