/**
 * ai.ts (routes) — local LLM (Ollama): "Ask the threat model" (RAG over XORCISM)
 * and OCIL answer suggestion. All the routes are authenticated (mounted under /api).
 */
import { Router, Request, Response } from "express";
import { askThreatModel, suggestOcilAnswer, ollamaStatus, enrichThreatReport, triageVulnerability, buildIntelBrief, analyzeAttackChain, exposureBrief, feedDigest, draftPolicy, boardNarrative, draftCrisisScenario } from "../ai";
import {
  draftThreatModel, suggestControlMappings, incidentCopilot, draftRisk, calibrateFair,
  draftControlImplementation, draftPoam, complianceGapAnalysis, remediationAdvice, draftDpia,
  assessBreach, draftPhishingTemplate, awarenessCoaching, socTriage, shiftHandover,
  synthesizeMalwareVerdict, osintGraphInsights, ovalRemediation,
  tprmVendorBrief, tprmReviewQuestionnaire, tprmDraftAnswers,
} from "../aiassist";
import { userCan } from "../auth";
import { getRun } from "../chain";
import { getEngagement } from "../engagements";

const router = Router();

function aiError(e: unknown): string {
  const m = String((e as Error)?.message || e);
  if (/ECONNREFUSED|fetch failed|ENOTFOUND|ETIMEDOUT/i.test(m)) {
    return `Local AI unreachable. Start Ollama (\`ollama serve\`) at ${process.env.OLLAMA_URL || "http://localhost:11434"} and pull a model.`;
  }
  return m;
}

// GET /api/ai/status — is the local AI reachable + available model(s)
router.get("/ai/status", async (_req: Request, res: Response) => {
  res.json(await ollamaStatus());
});

// POST /api/ai/ask { question } — "Ask the threat model" (RAG ATT&CK/KEV/asset + LLM)
router.post("/ai/ask", async (req: Request, res: Response) => {
  const q = String((req.body as { question?: unknown })?.question ?? "").trim();
  if (!q) return void res.status(400).json({ error: "question requise" });
  if (q.length > 2000) return void res.status(400).json({ error: "question trop longue" });
  try {
    res.json(await askThreatModel(q));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/suggest-answer { question, description? } — OCIL answer draft
router.post("/ai/suggest-answer", async (req: Request, res: Response) => {
  const body = req.body as { question?: unknown; description?: unknown };
  const q = String(body?.question ?? "").trim();
  const d = body?.description ? String(body.description) : undefined;
  if (!q) return void res.status(400).json({ error: "question requise" });
  try {
    res.json(await suggestOcilAnswer(q, d));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/enrich-report { reportId } — AI analyst note + CVE extraction for a THREATREPORT
router.post("/ai/enrich-report", async (req: Request, res: Response) => {
  const id = Number((req.body as { reportId?: unknown })?.reportId);
  if (!id) return void res.status(400).json({ error: "reportId requis" });
  try {
    res.json(await enrichThreatReport(id));
  } catch (e) {
    const m = aiError(e);
    res.status(/introuvable/.test(m) ? 404 : 502).json({ error: m });
  }
});

// POST /api/ai/triage-vuln { cve?, vulnerabilityId? } — vulnerability-triage agent
router.post("/ai/triage-vuln", async (req: Request, res: Response) => {
  const body = req.body as { cve?: unknown; vulnerabilityId?: unknown };
  const cve = body?.cve ? String(body.cve).trim() : undefined;
  const vulnerabilityId = body?.vulnerabilityId ? Number(body.vulnerabilityId) : undefined;
  if (!cve && !vulnerabilityId) return void res.status(400).json({ error: "cve ou vulnerabilityId requis" });
  try {
    res.json(await triageVulnerability({ cve, vulnerabilityId }));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/feed-digest { items:[{title,summary,source,date}], focus? } — summarize threat-feed items
router.post("/ai/feed-digest", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const body = req.body as { items?: unknown; focus?: unknown };
  const items = Array.isArray(body?.items) ? (body.items as Record<string, unknown>[]).slice(0, 80).map((i) => ({
    title: i?.title != null ? String(i.title) : "", summary: i?.summary != null ? String(i.summary) : "",
    source: i?.source != null ? String(i.source) : "", date: i?.date != null ? String(i.date) : "",
  })) : [];
  if (!items.length) return void res.status(400).json({ error: "items required" });
  try { res.json(await feedDigest(items, body?.focus ? String(body.focus).slice(0, 300) : undefined)); }
  catch (e) { res.status(502).json({ error: aiError(e) }); }
});

// POST /api/ai/brief { reportIds?, focus? } — intelligence-brief builder (Markdown)
router.post("/ai/brief", async (req: Request, res: Response) => {
  const body = req.body as { reportIds?: unknown; focus?: unknown };
  const reportIds = Array.isArray(body?.reportIds) ? body.reportIds.map(Number).filter((n) => Number.isFinite(n)) : [];
  const focus = body?.focus ? String(body.focus).slice(0, 500) : undefined;
  try {
    res.json(await buildIntelBrief(reportIds, focus));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/chain/:runId/analyze — AI red/blue analysis of a tool-chaining run
router.post("/ai/chain/:runId/analyze", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const runId = Number(req.params.runId);
  const run = Number.isInteger(runId) ? getRun(runId) : undefined;
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  if (!run || !getEngagement(run.AuditID, tenant)) return void res.status(404).json({ error: "run not found" });
  try {
    res.json(await analyzeAttackChain(runId));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/exposure-brief — AI CISO briefing over the fusion worklist + attack paths
router.post("/ai/exposure-brief", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    res.json(await exposureBrief(tenant));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/draft-policy { name?, description?, scope?, category?, framework? } — local-AI policy body (HTML)
router.post("/ai/draft-policy", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "POLICY")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as Record<string, unknown>;
  const str = (k: string): string | undefined => (b?.[k] != null ? String(b[k]).slice(0, 600) : undefined);
  try {
    res.json(await draftPolicy({ name: str("name"), description: str("description"), scope: str("scope"), category: str("category"), framework: str("framework") }));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/draft-crisis-scenario { name?, scenarioType?, severity?, objectives?, threatActor? } — local-AI scenario Description (HTML)
router.post("/ai/draft-crisis-scenario", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XCOMPLIANCE", "CRISISSCENARIO")) return void res.status(403).json({ error: "forbidden" });
  const b = req.body as Record<string, unknown>;
  const str = (k: string): string | undefined => (b?.[k] != null ? String(b[k]).slice(0, 600) : undefined);
  try {
    res.json(await draftCrisisScenario({ name: str("name"), scenarioType: str("scenarioType"), severity: str("severity"), objectives: str("objectives"), threatActor: str("threatActor") }));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// POST /api/ai/board-narrative — local-AI board-language exec read-out over the board report
router.post("/ai/board-narrative", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    res.json(await boardNarrative(tenant));
  } catch (e) {
    res.status(502).json({ error: aiError(e) });
  }
});

// ── aiassist: the second-wave copilots (advisory; all authed, all degrade offline) ──
const S = (b: any, k: string, max = 6000): string | undefined => (b?.[k] != null ? String(b[k]).slice(0, max) : undefined);
const N = (b: any, k: string): number | undefined => (b?.[k] != null && Number.isFinite(Number(b[k])) ? Number(b[k]) : undefined);
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
function aiRoute(path: string, fn: (req: Request) => Promise<unknown>): void {
  router.post(path, async (req: Request, res: Response) => {
    if (!req.user) return void res.status(401).json({ error: "auth" });
    try { res.json(await fn(req)); } catch (e) { res.status(502).json({ error: aiError(e) }); }
  });
}

aiRoute("/ai/threat-model", (r) => draftThreatModel({ name: S(r.body, "name"), system: S(r.body, "system"), assets: S(r.body, "assets"), dataFlows: S(r.body, "dataFlows"), scope: S(r.body, "scope"), tenant: ten(r) }));
aiRoute("/ai/control-mappings", (r) => suggestControlMappings({ sourceVocab: S(r.body, "sourceVocab") || "", targetVocab: S(r.body, "targetVocab") || "", max: N(r.body, "max"), tenant: ten(r) }));
aiRoute("/ai/incident-copilot", (r) => incidentCopilot({ incidentId: N(r.body, "incidentId"), mode: S(r.body, "mode"), tenant: ten(r) }));
aiRoute("/ai/draft-risk", (r) => draftRisk({ title: S(r.body, "title"), asset: S(r.body, "asset"), threat: S(r.body, "threat"), context: S(r.body, "context") }));
aiRoute("/ai/calibrate-fair", (r) => calibrateFair({ scenario: S(r.body, "scenario"), asset: S(r.body, "asset"), context: S(r.body, "context") }));
aiRoute("/ai/control-implementation", (r) => draftControlImplementation({ control: S(r.body, "control"), framework: S(r.body, "framework"), context: S(r.body, "context") }));
aiRoute("/ai/draft-poam", (r) => draftPoam({ weakness: S(r.body, "weakness"), control: S(r.body, "control"), severity: S(r.body, "severity"), context: S(r.body, "context") }));
aiRoute("/ai/gap-analysis", (r) => complianceGapAnalysis({ framework: S(r.body, "framework"), objective: S(r.body, "objective"), context: S(r.body, "context") }));
aiRoute("/ai/remediation", (r) => remediationAdvice({ cve: S(r.body, "cve"), component: S(r.body, "component"), version: S(r.body, "version"), asset: S(r.body, "asset"), context: S(r.body, "context") }));
aiRoute("/ai/draft-dpia", (r) => draftDpia({ processing: S(r.body, "processing"), dataCategories: S(r.body, "dataCategories"), context: S(r.body, "context") }));
aiRoute("/ai/assess-breach", (r) => assessBreach({ description: S(r.body, "description"), dataCategories: S(r.body, "dataCategories"), recordCount: N(r.body, "recordCount") }));
aiRoute("/ai/phishing-template", (r) => draftPhishingTemplate({ theme: S(r.body, "theme"), difficulty: S(r.body, "difficulty"), pretext: S(r.body, "pretext") }));
aiRoute("/ai/awareness-coaching", (r) => awarenessCoaching({ name: S(r.body, "name"), phishProne: N(r.body, "phishProne"), fails: N(r.body, "fails"), role: S(r.body, "role") }));
aiRoute("/ai/soc-triage", (r) => socTriage({ alerts: Array.isArray(r.body?.alerts) ? r.body.alerts : undefined, tenant: ten(r) }));
aiRoute("/ai/shift-handover", (r) => shiftHandover({ tenant: ten(r) }));
aiRoute("/ai/malware-verdict", (r) => synthesizeMalwareVerdict({ indicator: S(r.body, "indicator"), type: S(r.body, "type"), engines: Array.isArray(r.body?.engines) ? r.body.engines : undefined }));
aiRoute("/ai/osint-insights", (r) => osintGraphInsights({ tenant: ten(r) }));
aiRoute("/ai/oval-remediation", (r) => ovalRemediation({ check: S(r.body, "check"), result: S(r.body, "result"), platform: S(r.body, "platform") }));
aiRoute("/ai/tprm-vendor-brief", (r) => tprmVendorBrief({ name: S(r.body, "name"), services: S(r.body, "services"), domain: S(r.body, "domain"), dataSensitivity: S(r.body, "dataSensitivity"), businessCriticality: S(r.body, "businessCriticality"), tier: S(r.body, "tier"), postureScore: N(r.body, "postureScore"), postureGrade: S(r.body, "postureGrade"), conformance: N(r.body, "conformance"), residualTier: S(r.body, "residualTier"), usesAI: !!r.body?.usesAI, aiUse: S(r.body, "aiUse"), findings: Array.isArray(r.body?.findings) ? r.body.findings : undefined }));
aiRoute("/ai/tprm-review-questionnaire", (r) => tprmReviewQuestionnaire({ runId: N(r.body, "runId"), tenant: ten(r) }));
aiRoute("/ai/tprm-draft-answers", (r) => tprmDraftAnswers({ runId: N(r.body, "runId"), knowledge: S(r.body, "knowledge", 12000), max: N(r.body, "max"), tenant: ten(r) }));

export default router;
