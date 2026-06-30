/**
 * sprs.ts (routes) — SPRS / NIST 800-171 self-assessment score. Read the assessment (score + per-family
 * rollup + 110 requirements), set a requirement's status / weight / notes, and seed a demo profile.
 * Guarded by RBAC on XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { sprsAssessment, setSprsStatus, seedDemo } from "../sprs";
import * as xid from "../xid";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/sprs — full SPRS / 800-171 assessment (score, families, requirements)
router.get("/sprs", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  res.json(sprsAssessment(tenantOf(req)));
});

// POST /api/sprs/status — set one requirement's status / weight override / notes
router.post("/sprs/status", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "AUDIT") && !userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!b.reqId) return void res.status(400).json({ error: "reqId required" });
  const ok = setSprsStatus(String(b.reqId), {
    status: b.status != null ? String(b.status) : undefined,
    weightOverride: b.weightOverride !== undefined ? (b.weightOverride === null || b.weightOverride === "" ? null : Number(b.weightOverride)) : undefined,
    notes: b.notes != null ? String(b.notes) : undefined,
  }, tenantOf(req));
  if (!ok) return void res.status(404).json({ error: "unknown requirement" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "sprs_status", resourceType: "sprs", resourceKey: String(b.reqId), detail: String(b.status ?? ""), ip: clientIp(req) });
  res.json({ ok: true });
});

// POST /api/sprs/seed — seed a demo profile (idempotent)
router.post("/sprs/seed", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? 1 : (req.user.tenantId ?? 1);
  res.json({ ok: true, ...seedDemo(tenant) });
});

export default router;
