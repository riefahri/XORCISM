/** slsa.ts (routes) — SLSA supply-chain level tracker (/slsa). Read-only posture; RBAC read XORCISM.ASSET. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { slsaTracker } from "../slsa";

const router = Router();

router.get("/slsa", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(slsaTracker(tenant)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
