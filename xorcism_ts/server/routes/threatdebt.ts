/**
 * threatdebt.ts (routes) — Adversary Opportunity Index (AOI), the renamed "threat debt" score.
 * Read-only cockpit; RBAC mirrors the exposure view (read XORCISM.ASSET). A GET upserts today's
 * snapshot so the STOCK/FLOW history accrues whenever the page is opened.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { recordThreatDebtSnapshot, threatDebtHistory } from "../threatdebt";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/threat-debt — the AOI cockpit (index + STOCK/FLOW + 7 sources + price-the-fix worklist + history)
router.get("/threat-debt", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try {
    const tenant = ten(req);
    const aoi = recordThreatDebtSnapshot(tenant); // compute + accrue today's point
    const since = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);
    res.json({ ...aoi, history: threatDebtHistory(tenant, since), canAct: userCan(req.user, "update", "XORCISM", "ASSET") });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/threat-debt/snapshot — force-record a snapshot now (manual paydown checkpoint)
router.post("/threat-debt/snapshot", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  try {
    const tenant = ten(req);
    const aoi = recordThreatDebtSnapshot(tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "threatdebt_snapshot", resourceType: "THREATDEBTSNAPSHOT", resourceKey: String(aoi.index), ip: clientIp(req) });
    const since = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);
    res.json({ ...aoi, history: threatDebtHistory(tenant, since), canAct: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
