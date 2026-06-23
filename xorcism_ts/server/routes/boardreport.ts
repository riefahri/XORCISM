/** boardreport.ts (routes) — Board-ready cyber-risk report data (GET /api/board-report).
 *  RBAC: authenticated user; tenant-scoped (super-admin sees the whole estate). */
import { Router, Request, Response } from "express";
import { boardReport } from "../boardreport";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/board-report", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  try { res.json(boardReport(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
