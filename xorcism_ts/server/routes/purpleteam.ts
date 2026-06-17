/**
 * purpleteam.ts (routes) — Purple-team detection-coverage of an attack-chain run +
 * Sigma rule generation for gaps. Mounted under /api (authenticated).
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { getRun } from "../chain";
import { getEngagement } from "../engagements";
import { chainCoverage, suggestSigma } from "../purpleteam";

const router = Router();

// GET /api/purple/chain/:runId — ATT&CK detection coverage of a chain run (vs Sigma library)
router.get("/purple/chain/:runId", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const runId = Number(req.params.runId);
  const run = Number.isInteger(runId) ? getRun(runId) : undefined;
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  if (!run || !getEngagement(run.AuditID, tenant)) return void res.status(404).json({ error: "run not found" });
  res.json(chainCoverage(runId));
});

// POST /api/purple/sigma-suggest { techId, techName } — draft a Sigma rule for a gap
router.post("/purple/sigma-suggest", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XTHREAT", "SIGMARULE")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as { techId?: unknown; techName?: unknown };
  const techId = String(b.techId ?? "").trim();
  if (!/^T\d{4}(\.\d{3})?$/i.test(techId)) return void res.status(400).json({ error: "valid ATT&CK technique id required" });
  try {
    res.json(await suggestSigma(techId.toUpperCase(), String(b.techName ?? techId).slice(0, 120)));
  } catch (e) {
    res.status(502).json({ error: String((e as Error).message || e) });
  }
});

export default router;
