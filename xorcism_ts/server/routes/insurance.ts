/**
 * insurance.ts (routes) — Cyber Insurance Readiness (/insurance-readiness). Read-only; RBAC mirrors
 * the exposure / posture views (read XORCISM.ASSET).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { insuranceReadiness, insuranceProgram, saveInsurancePolicy } from "../insurance";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/insurance-readiness", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = ten(req);
  try {
    res.json({ ...insuranceReadiness(tenant), program: insuranceProgram(tenant), canEdit: userCan(req.user, "update", "XORCISM", "ASSET") });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/insurance-readiness/policy — upsert the tenant's cyber-insurance policy record
router.post("/insurance-readiness/policy", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = ten(req);
  try {
    saveInsurancePolicy(tenant, (req.body || {}) as any);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "insurance_policy_save", resourceType: "CYBERINSURANCEPOLICY", resourceKey: String((req.body as any)?.carrier || ""), ip: clientIp(req) });
    res.json({ ...insuranceReadiness(tenant), program: insuranceProgram(tenant), canEdit: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
