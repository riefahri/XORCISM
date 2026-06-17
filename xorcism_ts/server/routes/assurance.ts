/**
 * assurance.ts (routes) — Continuously-proven compliance: control objectives evaluated
 * live from security telemetry. Read-only; guarded by read on XCOMPLIANCE.AUDIT.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { controlAssurance } from "../assurance";

const router = Router();

// GET /api/assurance — control posture proven from live telemetry
router.get("/assurance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "AUDIT")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(controlAssurance(tenant));
});

export default router;
