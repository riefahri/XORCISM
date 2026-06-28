/** crq.ts (routes) — Cyber Risk Quantification decision support (/crq). Read-gated on the risk register. */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { crqDecisionSupport } from "../crq";

const router = Router();

router.get("/crq", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "RISKREGISTERENTRY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(crqDecisionSupport(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
