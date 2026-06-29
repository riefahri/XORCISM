/**
 * csfmaturity.ts (routes) — NIST CSF 2.0 maturity self-assessment.
 * Read-only inventory (model + per-function rollups + worklist) + a score endpoint + demo seed.
 * Guarded by RBAC on XCOMPLIANCE.AUDIT (it is a compliance/maturity assessment).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { csfMaturityInventory, saveCsfScore, seedCsfMaturity } from "../csfmaturity";
import * as xid from "../xid";

const router = Router();

// GET /api/csf-maturity — the CSF 2.0 model (106 subcategories, 5 levels) + scores + rollups + worklist
router.get("/csf-maturity", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(csfMaturityInventory(tenant));
});

// POST /api/csf-maturity/score — set current/target maturity for one subcategory
router.post("/csf-maturity/score", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const subId = Number(b.subId);
  if (!Number.isFinite(subId)) return void res.status(400).json({ error: "subId required" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const ok = saveCsfScore(subId, {
    currentLevel: b.currentLevel !== undefined ? Number(b.currentLevel) : undefined,
    targetLevel: b.targetLevel !== undefined ? Number(b.targetLevel) : undefined,
    notes: b.notes != null ? String(b.notes) : undefined,
    ownerPersonId: b.ownerPersonId != null ? Number(b.ownerPersonId) : undefined,
  }, tenant);
  if (!ok) return void res.status(404).json({ error: "subcategory not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "csf_maturity_score", resourceType: "csf-maturity", resourceKey: String(subId), detail: `current=${b.currentLevel ?? ""} target=${b.targetLevel ?? ""}`, ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/csf-maturity/seed — seed a demo maturity profile for the tenant (idempotent)
router.post("/csf-maturity/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  const out = seedCsfMaturity(tenant);
  res.json({ ok: true, ...out });
});

export default router;
