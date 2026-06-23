/** croc.ts (routes) — Cyber Risk Operations Center / Continuous Defense Loop cockpit.
 *  RBAC: read XVULNERABILITY.VULNERABILITY (exposure data); pre-authorization policy mutations = admin
 *  (they decide which events auto-trigger actions — an org-level governance control). */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { crocDashboard, listPolicies, addPolicy, setPolicy, deletePolicy, riskHunting, escalateHunt } from "../croc";
import { redactTargets, addTarget, setTarget, deleteTarget, testTarget } from "../ticketing";
import { redactIamTargets, addIamTarget, setIamTarget, deleteIamTarget, testIamTarget } from "../iam";
import { redactSoar, addSoar, setSoar, deleteSoar, testSoar } from "../soar";
import { lifecycleReasoning } from "../ai";
import * as xid from "../xid";

const router = Router();
const ten = (req: Request): number | null => (req.user!.isSuperAdmin ? null : (req.user!.tenantId ?? null));
const rd = (req: Request) => userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY");
const admin = (req: Request) => !!(req.user && (req.user.isAdmin || req.user.isSuperAdmin));

router.get("/croc", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(crocDashboard(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.get("/croc/policies", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ policies: listPolicies(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc/policies", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.name ?? "").trim() || !String(b.action ?? "").trim()) return void res.status(400).json({ error: "name + action required" });
  const out = addPolicy(ten(req), {
    name: String(b.name), action: String(b.action),
    eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
    minSeverity: b.minSeverity ? String(b.minSeverity) : undefined,
    direction: b.direction ? String(b.direction) : undefined,
    description: b.description ? String(b.description) : undefined,
  });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_policy_add", resourceType: "LOOPPOLICY", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/croc/policies/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setPolicy(ten(req), Number(req.params.id), {
    enabled: b.enabled != null ? !!b.enabled : undefined,
    minSeverity: b.minSeverity ? String(b.minSeverity) : undefined,
    action: b.action ? String(b.action) : undefined,
    eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
  });
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/croc/policies/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  if (!deletePolicy(ten(req), Number(req.params.id))) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_policy_delete", resourceType: "LOOPPOLICY", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

// ── external ticketing targets (Jira / ServiceNow outbound) — secrets never returned to the client ──
router.get("/croc/ticketing", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ targets: redactTargets(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc/ticketing", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.baseUrl ?? "").trim() || !String(b.authSecret ?? "").trim()) return void res.status(400).json({ error: "baseUrl + authSecret required" });
  const out = addTarget(ten(req), {
    system: String(b.system || "jira"), name: b.name ? String(b.name) : undefined,
    baseUrl: String(b.baseUrl), authUser: b.authUser ? String(b.authUser) : undefined, authSecret: String(b.authSecret),
    project: b.project ? String(b.project) : undefined, issueType: b.issueType ? String(b.issueType) : undefined,
    minSeverity: b.minSeverity ? String(b.minSeverity) : undefined, eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
  });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_ticketing_add", resourceType: "TICKETINGTARGET", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/croc/ticketing/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setTarget(ten(req), Number(req.params.id), {
    enabled: b.enabled != null ? !!b.enabled : undefined,
    minSeverity: b.minSeverity ? String(b.minSeverity) : undefined,
    eventFilter: b.eventFilter !== undefined ? (b.eventFilter ? String(b.eventFilter) : null) : undefined,
    name: b.name ? String(b.name) : undefined, project: b.project ? String(b.project) : undefined,
    issueType: b.issueType ? String(b.issueType) : undefined, baseUrl: b.baseUrl ? String(b.baseUrl) : undefined,
    authUser: b.authUser !== undefined ? String(b.authUser) : undefined, authSecret: b.authSecret ? String(b.authSecret) : undefined,
  });
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/croc/ticketing/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  if (!deleteTarget(ten(req), Number(req.params.id))) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_ticketing_delete", resourceType: "TICKETINGTARGET", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

// Admin-initiated "Test" — posts one real ticket into the configured external system (like Teams' Test).
router.post("/croc/ticketing/:id/test", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = await testTarget(ten(req), Number(req.params.id));
    if (!r) return void res.status(404).json({ error: "not found" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_ticketing_test", resourceType: "TICKETINGTARGET", resourceKey: String(req.params.id), ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── IAM enforcement targets (Entra/Graph outbound) — the `constrain` teeth; secrets never returned ──
router.get("/croc/iam", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ targets: redactIamTargets(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc/iam", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.tenantRef ?? "").trim() || !String(b.clientId ?? "").trim() || !String(b.clientSecret ?? "").trim())
    return void res.status(400).json({ error: "tenantRef + clientId + clientSecret required" });
  const out = addIamTarget(ten(req), {
    name: b.name ? String(b.name) : undefined, tenantRef: String(b.tenantRef), clientId: String(b.clientId), clientSecret: String(b.clientSecret),
    mode: b.mode ? String(b.mode) : undefined, eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
    loginBase: b.loginBase ? String(b.loginBase) : undefined, graphBase: b.graphBase ? String(b.graphBase) : undefined,
  });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_iam_add", resourceType: "IAMTARGET", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/croc/iam/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setIamTarget(ten(req), Number(req.params.id), {
    enabled: b.enabled != null ? !!b.enabled : undefined, mode: b.mode ? String(b.mode) : undefined,
    eventFilter: b.eventFilter !== undefined ? (b.eventFilter ? String(b.eventFilter) : null) : undefined,
    name: b.name ? String(b.name) : undefined, tenantRef: b.tenantRef ? String(b.tenantRef) : undefined,
    clientId: b.clientId ? String(b.clientId) : undefined, clientSecret: b.clientSecret ? String(b.clientSecret) : undefined,
  });
  if (!ok) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_iam_set", resourceType: "IAMTARGET", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.delete("/croc/iam/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  if (!deleteIamTarget(ten(req), Number(req.params.id))) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_iam_delete", resourceType: "IAMTARGET", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

// Non-destructive credential probe (token + a single read) — never writes.
router.post("/croc/iam/:id/test", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = await testIamTarget(ten(req), Number(req.params.id));
    if (!r) return void res.status(404).json({ error: "not found" });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_iam_test", resourceType: "IAMTARGET", resourceKey: String(req.params.id), ip: clientIp(req) });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── SOAR / n8n automation webhooks (generic outbound glue) ──
router.get("/croc/soar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json({ webhooks: redactSoar(ten(req)) }); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

router.post("/croc/soar", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  if (!String(b.url ?? "").trim()) return void res.status(400).json({ error: "url required" });
  const out = addSoar(ten(req), {
    name: b.name ? String(b.name) : undefined, url: String(b.url), apiKey: b.apiKey ? String(b.apiKey) : undefined,
    minSeverity: b.minSeverity ? String(b.minSeverity) : undefined, eventFilter: b.eventFilter ? String(b.eventFilter) : undefined,
  });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_soar_add", resourceType: "SOARWEBHOOK", resourceKey: String(out.id), ip: clientIp(req) });
  res.json({ ok: true, ...out });
});

router.post("/croc/soar/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ok = setSoar(ten(req), Number(req.params.id), {
    enabled: b.enabled != null ? !!b.enabled : undefined, minSeverity: b.minSeverity ? String(b.minSeverity) : undefined,
    eventFilter: b.eventFilter !== undefined ? (b.eventFilter ? String(b.eventFilter) : null) : undefined,
    name: b.name ? String(b.name) : undefined, url: b.url ? String(b.url) : undefined, apiKey: b.apiKey ? String(b.apiKey) : undefined,
  });
  if (!ok) return void res.status(404).json({ error: "not found" });
  res.json({ ok: true });
});

router.delete("/croc/soar/:id", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  if (!deleteSoar(ten(req), Number(req.params.id))) return void res.status(404).json({ error: "not found" });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_soar_delete", resourceType: "SOARWEBHOOK", resourceKey: String(req.params.id), ip: clientIp(req) });
  res.json({ ok: true });
});

router.post("/croc/soar/:id/test", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!admin(req)) return void res.status(403).json({ error: "forbidden" });
  try {
    const r = await testSoar(ten(req), Number(req.params.id));
    if (!r) return void res.status(404).json({ error: "not found" });
    res.json(r);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── local-AI reasoning across the loop (detect→decide→act→learn); Ollama + offline fallback ──
router.get("/croc/reason", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(await lifecycleReasoning(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── cyber-risk hunting ("where could an adversary succeed?") ──
router.get("/cyber-risk-hunting", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  try { res.json(riskHunting(ten(req))); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// Escalate a hunting finding back into the loop (so the pre-authorization policies fire on it).
router.post("/cyber-risk-hunting/escalate", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!rd(req)) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const ref = String(b.ref ?? "").trim();
  if (!ref) return void res.status(400).json({ error: "ref required" });
  try {
    escalateHunt(ten(req), String(b.kind || "exposure"), ref, Number(b.priority) || 0);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "croc_hunt_escalate", resourceType: "LOOPEVENT", resourceKey: ref, ip: clientIp(req) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

export default router;
