/**
 * sla.ts (routes) — Incident SLA view: incidents measured against the resolution
 * SLA defined on each affected asset. Read-only; guarded by read on XINCIDENT.INCIDENT.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { incidentSlaView } from "../sla";

const router = Router();

// GET /api/sla/incidents — incidents vs asset-defined SLAs (breach analysis)
router.get("/sla/incidents", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XINCIDENT", "INCIDENT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(incidentSlaView(tenant));
});

export default router;
