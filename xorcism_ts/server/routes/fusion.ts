/**
 * fusion.ts (routes) — Exploitability & relevance fusion score / prioritized
 * exposure worklist. Read-only; guarded by read on XVULNERABILITY.VULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { topExposures, fusionForVuln, assetsForVuln } from "../fusion";

const router = Router();
function guard(req: Request, res: Response): boolean {
  if (!req.user) { res.status(401).json({ error: "auth" }); return false; }
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY")) { res.status(403).json({ error: "forbidden" }); return false; }
  return true;
}
function tenantOf(req: Request): number | null {
  return req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null);
}

// GET /api/fusion/top?limit= — prioritized exposure worklist for the tenant
router.get("/fusion/top", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  res.json(topExposures(tenantOf(req), Number(req.query.limit) || 50));
});

// GET /api/fusion/vuln/:vid — fusion score + breakdown for one vulnerability
router.get("/fusion/vuln/:vid", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  const vid = Number(req.params.vid);
  if (!Number.isInteger(vid) || vid <= 0) return void res.status(400).json({ error: "invalid id" });
  const f = fusionForVuln(vid);
  if (!f) return void res.status(404).json({ error: "not found" });
  res.json(f);
});

// GET /api/fusion/vuln/:vid/assets — the in-scope assets impacted by this vulnerability
router.get("/fusion/vuln/:vid/assets", (req: Request, res: Response) => {
  if (!guard(req, res)) return;
  const vid = Number(req.params.vid);
  if (!Number.isInteger(vid) || vid <= 0) return void res.status(400).json({ error: "invalid id" });
  res.json({ assets: assetsForVuln(vid, tenantOf(req)) });
});

export default router;
