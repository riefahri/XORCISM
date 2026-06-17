/**
 * ransomware.ts (routes) — Ransomware-to-$ scenario simulator. Read-only;
 * guarded by read on XORCISM.ASSET (it quantifies the asset estate).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { ransomwareGroups, ransomwareScenario } from "../ransomware";

const router = Router();
function guard(req: Request, res: Response): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, "read", "XORCISM", "ASSET")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
}
function tenantOf(req: Request): number | null { return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null); }

// GET /api/ransomware/groups — ATT&CK ransomware-capable groups (use T1486)
router.get("/ransomware/groups", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  res.json(ransomwareGroups());
});

// GET /api/ransomware/scenario?group=Gxxxx — quantified scenario for a group
router.get("/ransomware/scenario", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  const group = req.query.group ? String(req.query.group) : null;
  res.json(ransomwareScenario(tenantOf(req), group));
});

export default router;
