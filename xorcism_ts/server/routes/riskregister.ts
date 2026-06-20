/**
 * riskregister.ts (routes) — Risk Register inventory + treatment worklist + guided create.
 * Read-only inventory + a guided "new risk" create endpoint; guarded by RBAC on
 * XCOMPLIANCE.RISKREGISTERENTRY. Generic CRUD also via the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { riskRegisterInventory, createRiskRegisterEntry } from "../riskregister";
import * as xid from "../xid";

const router = Router();

// GET /api/risk-register — risk register inventory + treatment/governance worklist
router.get("/risk-register", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(riskRegisterInventory(tenant));
});

// POST /api/risk-register/entry — guided creation of a risk-register entry
router.post("/risk-register/entry", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const title = String(b.title ?? "").trim();
  if (!title) return void res.status(400).json({ error: "title required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const numOrNull = (v: unknown): number | null => (v != null && String(v) !== "" ? Number(v) : null);
  try {
    const out = createRiskRegisterEntry({
      title,
      description: b.description ? String(b.description) : undefined,
      category: b.category ? String(b.category) : undefined,
      ref: b.ref ? String(b.ref) : undefined,
      ownerPersonId: numOrNull(b.ownerPersonId),
      assetId: numOrNull(b.assetId),
      probability: numOrNull(b.probability),
      impact: numOrNull(b.impact),
      treatment: b.treatment ? String(b.treatment) : undefined,
      status: b.status ? String(b.status) : undefined,
      reviewDate: b.reviewDate ? String(b.reviewDate) : undefined,
      targetDate: b.targetDate ? String(b.targetDate) : undefined,
    }, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "risk_register_create", resourceType: "RISKREGISTERENTRY",
      resourceKey: String(out.id), detail: `title="${title}"`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
