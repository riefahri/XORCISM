/** questionnaires.ts (routes) — Guided questionnaire runner / journey. RBAC on XCOMPLIANCE.QUESTIONNAIRE. */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { questionnaireRunsDashboard, getRun, startRun, saveResponse, submitRun, deleteRun } from "../questionnaires";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));

router.get("/questionnaire-journeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(questionnaireRunsDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/questionnaire-journeys/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  const out = getRun(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  res.json(out);
});

router.post("/questionnaire-journeys", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const qid = Number(b.questionnaireId);
  if (!Number.isInteger(qid) || qid <= 0) return void res.status(400).json({ error: "questionnaireId required" });
  try {
    const out = startRun({
      questionnaireId: qid, name: b.name ? String(b.name) : undefined, subject: b.subject ? String(b.subject) : undefined,
      respondent: b.respondent ? String(b.respondent) : undefined, owner: b.owner ? String(b.owner) : undefined,
      targetDate: b.targetDate ? String(b.targetDate) : undefined,
    }, ten(req), req.user.Email ?? String(req.user.UserID ?? ""));
    xid.addAudit({ userId: req.user.UserID ?? null, action: "questionnaire_run_start", resourceType: "QUESTIONNAIRERUN", resourceKey: String(out.id), detail: String(qid), ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

router.post("/questionnaire-journeys/response/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = saveResponse(Number(req.params.id), {
    answer: b.answer != null ? String(b.answer) : undefined,
    comment: b.comment != null ? String(b.comment) : undefined,
    evidence: b.evidence != null ? String(b.evidence) : undefined,
  }, ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.post("/questionnaire-journeys/submit/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  const out = submitRun(Number(req.params.id), ten(req));
  if (!out) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "questionnaire_run_submit", resourceType: "QUESTIONNAIRERUN", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.delete("/questionnaire-journeys/item/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "delete", "XCOMPLIANCE", "QUESTIONNAIRE")) return void res.status(403).json({ error: "forbidden" });
  const ok = deleteRun(Number(req.params.id), ten(req));
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "questionnaire_run_delete", resourceType: "QUESTIONNAIRERUN", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

export default router;
