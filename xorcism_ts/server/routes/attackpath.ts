/**
 * attackpath.ts (routes) — Attack-path & choke-point graph over the asset estate.
 * Read-only; guarded by read on XORCISM.ASSET.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { attackPathGraph } from "../attackpath";

const router = Router();

// GET /api/attack-path — reachability graph + easiest paths to crown jewels + choke-points
router.get("/attack-path", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(attackPathGraph(tenant));
});

export default router;
