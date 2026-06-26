/**
 * regincident.ts (routes) — Regulatory incident-reporting obligations (/reg-incident-reporting).
 * RBAC mirrors the incident queue (read/update XINCIDENT.INCIDENT).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { regIncidentObligations, markRegIncidentReport } from "../regincident";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/reg-incident-reporting", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ...regIncidentObligations(ten(req)), canAct: userCan(req.user, "update", "XINCIDENT", "INCIDENT") }); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/reg-incident-reporting/report — mark a regulator/stage obligation submitted (or N/A)
router.post("/reg-incident-reporting/report", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as any;
  if (!b.incidentId || !b.regulator || !b.stage) return void res.status(400).json({ error: "incidentId, regulator, stage required" });
  try {
    markRegIncidentReport(ten(req), b);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "reg_incident_report", resourceType: "REGINCIDENTREPORT", resourceKey: `${b.incidentId}/${b.regulator}/${b.stage}`, ip: clientIp(req) });
    res.json({ ...regIncidentObligations(ten(req)), canAct: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
