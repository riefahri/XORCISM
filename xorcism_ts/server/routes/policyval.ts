/**
 * policyval.ts (routes) — Policy validation: extract requirements (local AI, human-approved) and validate
 * them against XORCISM's evidence (cloud CIS findings, asset/identity MFA, agentless host baseline).
 * RBAC on XORCISM.POLICY.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";
import { extractRequirements, validatePolicy, policyReport, setRequirement, deleteRequirement, listRequirements } from "../policyval";
import { dispatchEvent } from "../notifrules";

const router = Router();
const tenantOf = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

// GET /api/policy-validation?policy=<id> — report (requirements + latest validation) for one policy
router.get("/policy-validation", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const pid = Number(req.query.policy);
  if (!pid) return void res.status(400).json({ error: "policy id required" });
  res.json({ report: policyReport(pid, tenantOf(req)), requirements: listRequirements(pid, tenantOf(req)) });
});

// POST /api/policy-validation/extract { policyId } — AI extract requirements (saved as proposed/unapproved)
router.post("/policy-validation/extract", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const pid = Number((req.body || {}).policyId);
  if (!pid) return void res.status(400).json({ error: "policyId required" });
  try { res.json(await extractRequirements(pid, tenantOf(req))); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/policy-validation/validate { policyId } — run the approved requirements' collectors
router.post("/policy-validation/validate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const pid = Number((req.body || {}).policyId);
  if (!pid) return void res.status(400).json({ error: "policyId required" });
  const rep = validatePolicy(pid, tenantOf(req));
  // Alert on regression: any requirement that went pass→fail/partial since the last run.
  const regressed = rep.drift.filter((d) => d.dir === "down");
  if (regressed.length) {
    try {
      dispatchEvent("policy.regression", {
        userId: (req.user as { UserID?: number }).UserID ?? undefined, tenant: tenantOf(req), level: "warning",
        title: `Policy control regressed: ${rep.policyName}`,
        message: `${regressed.length} requirement(s) regressed — ${regressed.map((d) => d.name).slice(0, 3).join("; ")}. Compliance ${rep.compliancePct}%.`,
        link: "/policy-management",
      });
    } catch { /* alerting is best-effort */ }
  }
  res.json(rep);
});

// POST /api/policy-validation/requirement/:id { approved?, op?, value?, collectorKey? }
router.post("/policy-validation/requirement/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  res.json({ ok: setRequirement(Number(req.params.id), req.body || {}, tenantOf(req)) });
});

// DELETE /api/policy-validation/requirement/:id
router.delete("/policy-validation/requirement/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  deleteRequirement(Number(req.params.id));
  res.json({ ok: true });
});

export default router;
