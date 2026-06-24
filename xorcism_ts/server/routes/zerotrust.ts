/** zerotrust.ts (routes) — Zero Trust cockpit (CISA ZTMM v2.0): live pillar maturity, fused trust
 * score, and maturity assessments. RBAC anchored on XCOMPLIANCE.AUDIT (the GRC assessment resource). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { ztDashboard, getZtAssessment, createZtAssessment, setZtItem, deleteZtAssessment, deviceTrustFeed } from "../zerotrust";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const can = (req: Request, act: "read" | "create" | "update" | "delete") => userCan(req.user, act, "XCOMPLIANCE", "AUDIT");

router.get("/zero-trust", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(ztDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// Device-trust export feed — the pull surface a ZTNA/IdP/PEP consumes to gate access.
router.get("/zero-trust/device-trust", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const minTrust = Number(req.query.minTrust);
  try { res.json(deviceTrustFeed(ten(req), Number.isFinite(minTrust) ? minTrust : 60)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/zero-trust/assessment/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "read")) return void res.status(403).json({ error: "forbidden" });
  const out = getZtAssessment(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/zero-trust/assessment", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "create")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  try {
    const out = createZtAssessment({
      name: b.name ? String(b.name) : undefined, scope: b.scope ? String(b.scope) : undefined,
      owner: b.owner ? String(b.owner) : undefined, targetDate: b.targetDate ? String(b.targetDate) : undefined,
      targetStage: b.targetStage != null ? Number(b.targetStage) : undefined,
    }, ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "zt_assessment_create", resourceType: "ZTMATURITYASSESSMENT", resourceKey: String(out.id), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/zero-trust/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "update")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setZtItem(Number(req.params.id), {
    currentStage: b.currentStage != null ? Number(b.currentStage) : undefined,
    targetStage: b.targetStage != null ? Number(b.targetStage) : undefined,
    notes: b.notes != null ? String(b.notes) : undefined,
  }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/zero-trust/assessment/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!can(req, "delete")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteZtAssessment(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "zt_assessment_delete", resourceType: "ZTMATURITYASSESSMENT", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
