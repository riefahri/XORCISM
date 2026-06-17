/**
 * drift.ts (routes) — Attack-surface drift: snapshot the external surface and diff.
 * Read on XORCISM.ASSET. Mounted under /api (authenticated).
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { surfaceDrift, takeSnapshot } from "../drift";

const router = Router();
function guard(req: Request, res: Response): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
}
function tenantOf(req: Request): number | null { return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null); }

// GET /api/drift — surface drift vs the previous snapshot
router.get("/drift", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  res.json(surfaceDrift(tenantOf(req)));
});

// POST /api/drift/snapshot — capture the current surface
router.post("/drift/snapshot", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  const r = takeSnapshot(tenantOf(req), req.user!.UserID);
  xid.addAudit({ userId: req.user!.UserID, action: "surface_snapshot", resourceType: "asset", detail: `${r.assets} assets, ${r.exposed} exposed`, ip: clientIp(req) });
  res.json({ ok: true, ...r });
});

export default router;
