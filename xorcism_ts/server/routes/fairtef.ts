/** fairtef.ts (routes) — FAIR Threat/Loss Event Frequency estimator (Monte Carlo). Read-only
 *  inventory + a live calculator (no persistence) + a persist endpoint that writes LEF/ALE back to
 *  the linked risk-register entry. RBAC on XCOMPLIANCE.RISKREGISTERENTRY (the FAIR frequency side). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { fairTefInventory, computeFairTef, saveFairTefAssessment, TefPayload } from "../fairtef";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/fair-tef", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  res.json(fairTefInventory(ten(req)));
});

router.post("/fair-tef/compute", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(computeFairTef((req.body || {}) as TefPayload, ten(req))); }
  catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/fair-tef/assess", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as TefPayload;
  try {
    const out = saveFairTefAssessment(b, ten(req), req.user.UserID ?? null);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "fairtef_assess", resourceType: "fairtef", resourceKey: String(out.assessmentId), detail: `lef=${out.result.lef.mean} ale=${out.result.ale ? out.result.ale.mean : "—"}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
