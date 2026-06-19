/**
 * assets.ts (routes) — Asset Management inventory + governance worklist.
 * Read-only; guarded by read on XORCISM.ASSET. CRUD is the schema-driven explorer.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { assetInventory } from "../assets";

const router = Router();

// GET /api/asset-management — asset inventory with governance findings
router.get("/asset-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(assetInventory(tenant));
});

export default router;
