/**
 * configuration.ts (routes) — Configuration Management inventory + governance worklist.
 * Read-only inventory; guarded by read on XOVAL.OVALDEFINITION. OVAL scans are launched
 * on enrolled XOR agents (localhost or remote) via the existing /api/agent-scan queue.
 */
import os from "os";
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { configurationInventory, cisBenchmarkInventory } from "../configuration";
import { listAgents, createAgentJob } from "../agents";
import { listOvalContent, ovalResultsView } from "../oval";
import { createSchedule, listSchedules } from "../jobs";
import * as xid from "../xid";

const router = Router();

const ONLINE_WINDOW_MS = 15 * 60 * 1000;
function isAgentOnline(lastSeen: unknown): boolean {
  const seen = lastSeen ? Date.parse(String(lastSeen).replace(" ", "T")) : NaN;
  return !Number.isNaN(seen) && Date.now() - seen < ONLINE_WINDOW_MS;
}

const OVAL_CLASSES = new Set(["all", "compliance", "vulnerability", "inventory", "patch"]);
const CRON_PRESETS: Record<string, string> = {
  hourly: "0 * * * *", daily: "0 2 * * *", weekly: "0 3 * * 1", monthly: "0 4 1 * *",
};

// GET /api/configuration-management — secure-configuration content library + verification worklist
router.get("/configuration-management", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  res.json(configurationInventory(tenant));
});

// GET /api/configuration/scan-targets — enrolled XOR agents an OVAL scan can be launched on
// (the local host is flagged so the UI can offer "localhost"). The launch itself reuses
// POST /api/agent-scan { agent, kind } — the agent runs it at its next check-in.
router.get("/configuration/scan-targets", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const localName = os.hostname();
  const ln = localName.toLowerCase();
  const now = Date.now();
  const agents = listAgents().map((a) => {
    const seen = a.last_seen ? Date.parse(String(a.last_seen).replace(" ", "T")) : NaN;
    const online = !Number.isNaN(seen) && now - seen < 15 * 60 * 1000;
    const cands = [a.name, a.asset_name, a.fqdn].filter(Boolean).map((v) => String(v).toLowerCase());
    const isLocal = cands.some((v) => v === ln || v.startsWith(ln + "."));
    return { name: a.name, asset: a.asset_name, os: a.os, platform: a.platform, lastSeen: a.last_seen, online, isLocal };
  });
  // local host first, then online, then by name
  agents.sort((x, y) => Number(y.isLocal) - Number(x.isLocal) || Number(y.online) - Number(x.online) || x.name.localeCompare(y.name));
  // existing recurring OVAL schedules (so the UI can show what's already scheduled)
  let scheduled: { id: number; agent: string; ovalClass: string; cron: string; lastRun: string | null }[] = [];
  try {
    for (const s of listSchedules()) {
      if (s.connector !== "agent-oval") continue;
      let p: { agent?: string; ovalClass?: string } = {};
      try { p = JSON.parse(s.params || "{}"); } catch { /* ignore */ }
      scheduled.push({ id: s.ScheduleID, agent: String(p.agent ?? ""), ovalClass: String(p.ovalClass ?? "all"), cron: s.cron, lastRun: s.last_run_at ?? null });
    }
  } catch { /* schedules unavailable */ }
  res.json({ localhost: localName, agents, scheduled, cronPresets: CRON_PRESETS });
});

// POST /api/configuration/schedule-scan { agent, ovalClass?, cron|preset } — schedule a RECURRING
// OVAL scan on an enrolled agent via XSCHEDULE. The scheduler queues an agent OVAL job each tick
// (connector 'agent-oval'); the agent runs it at its next check-in and posts results.
router.post("/configuration/schedule-scan", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XOVAL", "OVALRESULTS")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { agent?: unknown; ovalClass?: unknown; cron?: unknown; preset?: unknown };
  const agent = String(b.agent ?? "").trim();
  if (!agent) return void res.status(400).json({ error: "agent required" });
  const ovalClass = OVAL_CLASSES.has(String(b.ovalClass ?? "all")) ? String(b.ovalClass ?? "all") : "all";
  let cron = "";
  if (typeof b.preset === "string" && CRON_PRESETS[b.preset]) cron = CRON_PRESETS[b.preset];
  else if (typeof b.cron === "string" && b.cron.trim().split(/\s+/).length === 5) cron = b.cron.trim();
  else cron = CRON_PRESETS.daily;
  const scheduleId = createSchedule({ connector: "agent-oval", params: { agent, ovalClass }, target: null, engagementId: null, worker: null, cron, userId: req.user.UserID ?? 0 });
  xid.addAudit({ userId: req.user.UserID ?? null, action: "configuration_schedule_scan", resourceType: "schedule",
    resourceKey: String(scheduleId), detail: `agent=${agent} ovalClass=${ovalClass} cron=${cron}`, ip: clientIp(req) });
  res.json({ ok: true, scheduleId, agent, ovalClass, cron });
});

// GET /api/configuration/cis-benchmarks — CIS Benchmark catalogue + CIS-CAT pass/fail posture
router.get("/configuration/cis-benchmarks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try { res.json(cisBenchmarkInventory(tenant)); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// ── Deploy/enforce compliance policies via the agent fleet ───────────────────────
// The XOR agents already evaluate OVAL/SCAP compliance content (CIS benchmarks → CCE/CCSS
// checks) at check-in. These two endpoints turn that into a *fleet-wide policy deployment*:
// push a compliance baseline to every (or selected) online agent at once, and — with a
// recurrence — keep re-evaluating it on a cadence so configuration drift is caught
// continuously (enforcement = continuous assurance; results land in XOVAL.OVALRESULTS).

// GET /api/configuration/fleet-compliance — the fleet + the compliance content library
router.get("/configuration/fleet-compliance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  const agents = listAgents().map((a) => ({
    name: a.name, asset: a.asset_name, os: a.os, platform: a.platform,
    lastSeen: a.last_seen, online: isAgentOnline(a.last_seen),
  })).sort((x, y) => Number(y.online) - Number(x.online) || String(x.name).localeCompare(String(y.name)));
  // Compliance content available to push (OVAL/SCAP files in the content library).
  let baselines: { name: string; size: number }[] = [];
  try { baselines = listOvalContent(); } catch { /* content dir unavailable */ }
  // Recurring compliance enforcement already scheduled (connector 'agent-oval', class compliance/all).
  let enforcing: { id: number; agent: string; ovalClass: string; cron: string; lastRun: string | null }[] = [];
  try {
    for (const s of listSchedules()) {
      if (s.connector !== "agent-oval") continue;
      let p: { agent?: string; ovalClass?: string } = {};
      try { p = JSON.parse(s.params || "{}"); } catch { /* ignore */ }
      const cls = String(p.ovalClass ?? "all");
      if (cls !== "compliance" && cls !== "all") continue;
      enforcing.push({ id: s.ScheduleID, agent: String(p.agent ?? ""), ovalClass: cls, cron: s.cron, lastRun: s.last_run_at ?? null });
    }
  } catch { /* schedules unavailable */ }
  // Last compliance verification posture (pass/fail) from agent OVAL results.
  let results: { pass: number; fail: number; assets: number; passRate: number | null } | null = null;
  try {
    const v = ovalResultsView(tenant) as { summary?: { assets?: number; compliancePass?: number; complianceFail?: number; passRate?: number | null } };
    if (v && v.summary) results = { pass: v.summary.compliancePass ?? 0, fail: v.summary.complianceFail ?? 0, assets: v.summary.assets ?? 0, passRate: v.summary.passRate ?? null };
  } catch { /* no results yet */ }
  res.json({
    agents, online: agents.filter((a) => a.online).length, total: agents.length,
    baselines, enforcing, results,
  });
});

// POST /api/configuration/deploy-compliance { agents?, ovalClass?, preset? }
// Fan out a compliance OVAL evaluation to the fleet. `agents` selects specific hosts;
// omit it to target every ONLINE agent. With `preset` (hourly/daily/weekly/monthly) the
// deployment is also scheduled (continuous enforcement) for each target instead of a one-shot.
router.post("/configuration/deploy-compliance", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XOVAL", "OVALRESULTS")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { agents?: unknown; ovalClass?: unknown; preset?: unknown };
  const ovalClass = OVAL_CLASSES.has(String(b.ovalClass ?? "compliance")) ? String(b.ovalClass ?? "compliance") : "compliance";
  const all = listAgents();
  const byName = new Map(all.map((a) => [a.name, a]));
  // Resolve targets: explicit list (validated) or every online agent.
  let targets: string[];
  if (Array.isArray(b.agents) && b.agents.length) {
    targets = [...new Set(b.agents.map((x) => String(x)))].filter((n) => byName.has(n));
    if (!targets.length) return void res.status(400).json({ error: "none of the requested agents are enrolled" });
  } else {
    targets = all.filter((a) => isAgentOnline(a.last_seen)).map((a) => a.name);
    if (!targets.length) return void res.status(400).json({ error: "no online agents to deploy to" });
  }
  const preset = typeof b.preset === "string" && CRON_PRESETS[b.preset] ? b.preset : "";
  const userId = req.user.UserID ?? null;
  const jobIds: number[] = [];
  const scheduleIds: number[] = [];
  const params = ovalClass === "all" ? {} : { ovalClass };
  for (const agent of targets) {
    // Always queue an immediate evaluation so results start flowing now.
    jobIds.push(createAgentJob(agent, "oval", params, userId));
    // With a recurrence, also register a recurring enforcement schedule per host.
    if (preset) {
      try { scheduleIds.push(createSchedule({ connector: "agent-oval", params: { agent, ovalClass }, target: null, engagementId: null, worker: null, cron: CRON_PRESETS[preset], userId: userId ?? 0 })); }
      catch { /* schedule registration best-effort */ }
    }
  }
  xid.addAudit({ userId, action: "configuration_deploy_compliance", resourceType: "agent",
    resourceKey: targets.join(","), detail: `class=${ovalClass} agents=${targets.length} jobs=${jobIds.length}${preset ? ` enforce=${preset}` : ""}`, ip: clientIp(req) });
  res.json({ ok: true, deployed: targets.length, ovalClass, jobIds, targets, preset: preset || null, scheduleIds });
});

export default router;
