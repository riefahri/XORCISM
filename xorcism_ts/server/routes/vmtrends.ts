/** vmtrends.ts (routes) — VM executive report: risk & SLA trends + myth-busting briefing.
 *  RBAC: read XVULNERABILITY.VULNERABILITY. POST /snapshot force-captures today's posture. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { vmReport, captureVmSnapshot } from "../vmtrends";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY");

router.get("/vm-report", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(vmReport(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/vm-report/snapshot", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ ok: true, posture: captureVmSnapshot(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
