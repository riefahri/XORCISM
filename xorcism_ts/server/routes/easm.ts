/**
 * easm.ts (routes) — External Attack Surface Management cockpit.
 * Read-only outside-in view; guarded by read on XORCISM.ASSET. Reuses the ASSET estate,
 * ASSETSERVICE / NETWORKSESSION exposure, MONITORINGCHECK TLS posture and cross-DB vulns.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { easmInventory } from "../easm";
import { takeSnapshot } from "../drift";

const router = Router();

// GET /api/easm — external attack surface inventory + exposures worklist
router.get("/easm", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(easmInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/easm/snapshot — capture a surface snapshot so drift can be measured next time
router.post("/easm/snapshot", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json({ ok: true, ...takeSnapshot(tenant, req.user.UserID ?? 0) }); }
  catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

export default router;
