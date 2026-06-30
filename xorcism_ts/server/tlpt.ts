/**
 * tlpt.ts — Threat-Led Penetration Testing (TLPT) following the ECB TIBER-EU framework.
 *
 * TIBER-EU (Threat Intelligence-Based Ethical Red-teaming) is the European framework for controlled,
 * intelligence-led red-team tests against the live production systems of (critical) financial entities.
 * It is the methodology DORA points to for advanced / Threat-Led Penetration Testing. The process runs
 * in three phases — Preparation → Testing → Closure — each with canonical milestones/deliverables and
 * sign-offs; intelligence-led attack scenarios (from the Targeted Threat Intelligence report) are run by
 * the Red Team against "flags" (critical-function targets), and the test measures the entity's ability to
 * Prevent / Detect / Respond, feeding remediation, a Test Summary Report and an attestation to the authority.
 *
 * This module layers that on XCOMPLIANCE: TLPTENGAGEMENT + TLPTMILESTONE (3-phase workflow) + TLPTSCENARIO
 * + TLPTFLAG + TLPTFINDING + TLPTTEAM (White/Control/Blue/Red/TI/authority roster). Deterministic logic
 * computes the resilience scorecard; the local AI only narrates (with an offline fallback) — see ai.ts.
 *
 * Reference: ECB "TIBER-EU Framework" (European Central Bank) — official phase/role terminology; the
 * scenario/flag content here is original.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export const TLPT_PHASES = [
  { phase: 0, name: "Preparation" },
  { phase: 1, name: "Testing" },
  { phase: 2, name: "Closure" },
];

// Canonical TIBER-EU milestones / deliverables, grouped by phase (seeded per engagement on creation).
export const TLPT_MILESTONES: { phase: number; code: string; name: string; deliverable: string }[] = [
  { phase: 0, code: "PREP-1", name: "Engagement & onboarding", deliverable: "Engagement letter & project plan" },
  { phase: 0, code: "PREP-2", name: "Scoping", deliverable: "Scope specification document (critical functions & flags)" },
  { phase: 0, code: "PREP-3", name: "Procurement", deliverable: "TI & Red-Team provider contracts (due-diligence)" },
  { phase: 0, code: "PREP-4", name: "Generic Threat Landscape", deliverable: "GTL — jurisdiction-level threat reference" },
  { phase: 1, code: "TEST-1", name: "Targeted Threat Intelligence", deliverable: "TTI report — threat actors & attack scenarios" },
  { phase: 1, code: "TEST-2", name: "Red-Team test planning", deliverable: "Red-Team Test Plan (scenarios mapped to flags)" },
  { phase: 1, code: "TEST-3", name: "Red-Team active testing", deliverable: "Attack execution against the live environment" },
  { phase: 2, code: "CLOS-1", name: "Red-Team Test Report", deliverable: "Red-Team Test Report (findings & attack paths)" },
  { phase: 2, code: "CLOS-2", name: "Blue-Team review & replay", deliverable: "Blue-Team report / purple-teaming & 360° feedback" },
  { phase: 2, code: "CLOS-3", name: "Remediation planning", deliverable: "Remediation plan" },
  { phase: 2, code: "CLOS-4", name: "Test Summary Report", deliverable: "Test Summary Report" },
  { phase: 2, code: "CLOS-5", name: "Attestation & results sharing", deliverable: "Attestation shared with the authority" },
];

export const TLPT_TEAM_ROLES = [
  "White Team", "Control Team", "Blue Team", "Red Team (provider)",
  "Threat Intelligence (provider)", "TIBER Cyber Team (authority)",
];
export const TLPT_ACTOR_TYPES = ["Hacktivist", "Cyber-criminal", "Insider", "Nation-state", "Terrorist"];
export const TLPT_SCENARIO_STATUS = ["planned", "in-progress", "achieved", "detected", "blocked", "failed"];
export const TLPT_SEVERITY = ["Critical", "High", "Medium", "Low", "Info"];
export const MILESTONE_STATUS = ["pending", "in-progress", "completed"];

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const pct = (a: number, b: number): number => (b ? Math.round((a / b) * 100) : 0);
const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
function inScope(db: ReturnType<typeof getDb>, id: number, tenant: number | null): boolean {
  const r = db.prepare("SELECT TenantID FROM TLPTENGAGEMENT WHERE EngagementID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!r) return false;
  return tenant == null || r.TenantID == null || Number(r.TenantID) === tenant;
}

/** List TLPT engagements for a tenant (+ reference vocab). */
export function listEngagements(tenant: number | null): any {
  const db = getDb("XCOMPLIANCE");
  const ref = { phases: TLPT_PHASES, teamRoles: TLPT_TEAM_ROLES, actorTypes: TLPT_ACTOR_TYPES, scenarioStatus: TLPT_SCENARIO_STATUS, severity: TLPT_SEVERITY };
  if (!has(db, "TLPTENGAGEMENT")) return { ...ref, engagements: [] };
  const rows = (tenant != null
    ? db.prepare("SELECT * FROM TLPTENGAGEMENT WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY EngagementID DESC").all(tenant)
    : db.prepare("SELECT * FROM TLPTENGAGEMENT ORDER BY EngagementID DESC").all()) as any[];
  const engagements = rows.map((e) => {
    const id = Number(e.EngagementID);
    const ms = has(db, "TLPTMILESTONE") ? num((db.prepare("SELECT COUNT(*) n FROM TLPTMILESTONE WHERE EngagementID=?").get(id) as { n: number }).n) : 0;
    const msDone = has(db, "TLPTMILESTONE") ? num((db.prepare("SELECT COUNT(*) n FROM TLPTMILESTONE WHERE EngagementID=? AND Status='completed'").get(id) as { n: number }).n) : 0;
    const flags = has(db, "TLPTFLAG") ? num((db.prepare("SELECT COUNT(*) n FROM TLPTFLAG WHERE EngagementID=?").get(id) as { n: number }).n) : 0;
    return { id, name: String(e.Name ?? ""), entity: String(e.Entity ?? ""), authority: String(e.Authority ?? ""), framework: String(e.Framework ?? "TIBER-EU"), status: String(e.Status ?? ""), phase: num(e.Phase), milestones: ms, milestonesDone: msDone, flags, progress: pct(msDone, ms) };
  });
  return { ...ref, engagements };
}

/** Full engagement: header, milestones (by phase), scenarios, flags, findings, teams, scorecard. */
export function engagement(id: number, tenant: number | null): any {
  const db = getDb("XCOMPLIANCE");
  if (!has(db, "TLPTENGAGEMENT")) return null;
  const e = db.prepare("SELECT * FROM TLPTENGAGEMENT WHERE EngagementID = ?").get(id) as any;
  if (!e || !inScope(db, id, tenant)) return null;

  const milestones = (db.prepare("SELECT * FROM TLPTMILESTONE WHERE EngagementID=? ORDER BY SortOrder, MilestoneID").all(id) as any[])
    .map((m) => ({ id: Number(m.MilestoneID), phase: num(m.Phase), phaseName: String(m.PhaseName ?? ""), code: String(m.Code ?? ""), name: String(m.Name ?? ""), deliverable: String(m.Deliverable ?? ""), status: String(m.Status ?? "pending"), signedBy: String(m.SignedBy ?? ""), signedAt: String(m.SignedAt ?? ""), docLink: String(m.DocLink ?? "") }));
  const scenarios = (db.prepare("SELECT * FROM TLPTSCENARIO WHERE EngagementID=? ORDER BY ScenarioID").all(id) as any[])
    .map((s) => ({ id: Number(s.ScenarioID), name: String(s.Name ?? ""), threatActor: String(s.ThreatActor ?? ""), actorType: String(s.ActorType ?? ""), narrative: String(s.Narrative ?? ""), attackTags: String(s.AttackTags ?? ""), flagsTargeted: String(s.FlagsTargeted ?? ""), status: String(s.Status ?? "planned"), outcome: String(s.Outcome ?? "") }));
  const flags = (db.prepare("SELECT * FROM TLPTFLAG WHERE EngagementID=? ORDER BY FlagID").all(id) as any[])
    .map((f) => ({ id: Number(f.FlagID), name: String(f.Name ?? ""), criticalFunction: String(f.CriticalFunction ?? ""), description: String(f.Description ?? ""), reached: num(f.Reached) === 1, detected: num(f.Detected) === 1, prevented: num(f.Prevented) === 1, timeToDetectHours: f.TimeToDetectHours != null ? Number(f.TimeToDetectHours) : null, notes: String(f.Notes ?? "") }));
  const findings = (db.prepare("SELECT * FROM TLPTFINDING WHERE EngagementID=? ORDER BY CASE LOWER(IFNULL(Severity,'')) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, FindingID").all(id) as any[])
    .map((f) => ({ id: Number(f.FindingID), title: String(f.Title ?? ""), severity: String(f.Severity ?? ""), category: String(f.Category ?? ""), attackTags: String(f.AttackTags ?? ""), description: String(f.Description ?? ""), recommendation: String(f.Recommendation ?? ""), status: String(f.Status ?? "Open"), remediationOwner: String(f.RemediationOwner ?? ""), dueDate: String(f.DueDate ?? "") }));
  const teams = (db.prepare("SELECT * FROM TLPTTEAM WHERE EngagementID=? ORDER BY TeamMemberID").all(id) as any[])
    .map((m) => ({ id: Number(m.TeamMemberID), teamRole: String(m.TeamRole ?? ""), memberName: String(m.MemberName ?? ""), organisation: String(m.Organisation ?? ""), contact: String(m.Contact ?? ""), notes: String(m.Notes ?? "") }));

  return {
    engagement: { id: Number(e.EngagementID), name: String(e.Name ?? ""), entity: String(e.Entity ?? ""), authority: String(e.Authority ?? ""), framework: String(e.Framework ?? "TIBER-EU"), scope: String(e.Scope ?? ""), criticalFunctions: String(e.CriticalFunctions ?? ""), status: String(e.Status ?? ""), phase: num(e.Phase), startDate: String(e.StartDate ?? ""), endDate: String(e.EndDate ?? ""), whiteTeamLead: String(e.WhiteTeamLead ?? ""), controlTeamLead: String(e.ControlTeamLead ?? ""), tiProvider: String(e.TIProvider ?? ""), rtProvider: String(e.RTProvider ?? ""), notes: String(e.Notes ?? "") },
    phases: TLPT_PHASES, teamRoles: TLPT_TEAM_ROLES, actorTypes: TLPT_ACTOR_TYPES, scenarioStatus: TLPT_SCENARIO_STATUS, severity: TLPT_SEVERITY,
    milestones, scenarios, flags, findings, teams,
    scorecard: scorecard({ milestones, scenarios, flags, findings }),
  };
}

/** Resilience scorecard — TIBER measures Prevent / Detect / Respond, not just "did they get in". */
export function scorecard(pre: { milestones: any[]; scenarios: any[]; flags: any[]; findings: any[] }): any {
  const { milestones, scenarios, flags, findings } = pre;
  const msDone = milestones.filter((m) => m.status === "completed").length;
  const phaseProgress = TLPT_PHASES.map((p) => {
    const tot = milestones.filter((m) => m.phase === p.phase).length;
    const done = milestones.filter((m) => m.phase === p.phase && m.status === "completed").length;
    return { phase: p.phase, name: p.name, total: tot, done, pct: pct(done, tot) };
  });
  const reached = flags.filter((f) => f.reached).length;
  const detected = flags.filter((f) => f.reached && f.detected).length; // detection measured among REACHED flags
  const prevented = flags.filter((f) => f.prevented).length;
  // "effectively prevented" = explicitly prevented OR never reached by the red team (deduped)
  const preventedEff = flags.filter((f) => f.prevented || !f.reached).length;
  const sevCount = (s: string) => findings.filter((f) => f.severity.toLowerCase() === s).length;
  const openFindings = findings.filter((f) => !/closed|resolved|accepted/i.test(f.status)).length;
  const remediated = pct(findings.length - openFindings, findings.length || 1);

  // Resilience (0-100): detection of reached flags (35) + prevention (25) + remediation progress (20)
  // + process/milestone completion (20). A flag never reached by the red team counts as prevented.
  const detectRate = reached ? pct(detected, reached) : (flags.length ? 100 : 0);
  const preventRate = flags.length ? pct(preventedEff, flags.length) : 0;
  const milestonePct = pct(msDone, milestones.length || 1);
  const resilience = Math.round(detectRate * 0.35 + preventRate * 0.25 + remediated * 0.20 + milestonePct * 0.20);

  return {
    milestones: milestones.length, milestonesDone: msDone, milestonePct, phaseProgress,
    scenarios: scenarios.length, scenariosAchieved: scenarios.filter((s) => s.status === "achieved").length,
    scenariosDetected: scenarios.filter((s) => s.status === "detected").length,
    flags: flags.length, reached, detected, prevented, detectRate, preventRate,
    findings: findings.length, openFindings, remediated,
    critical: sevCount("critical"), high: sevCount("high"), medium: sevCount("medium"), low: sevCount("low"),
    resilience,
  };
}

// ── mutations ────────────────────────────────────────────────────────────────
/** Create a TLPT engagement (TIBER-EU) + seed the 3-phase milestone workflow. */
export function createEngagement(p: { name: string; entity?: string; authority?: string; scope?: string; criticalFunctions?: string; tiProvider?: string; rtProvider?: string; whiteTeamLead?: string; controlTeamLead?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE");
  const id = allocId(db, "TLPTENGAGEMENT", "EngagementID");
  db.prepare(`INSERT INTO TLPTENGAGEMENT (EngagementID, EngagementGUID, Name, Entity, Authority, Framework, Scope, CriticalFunctions,
      Status, Phase, WhiteTeamLead, ControlTeamLead, TIProvider, RTProvider, CreatedDate, TenantID)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), (p.name || "TLPT engagement").slice(0, 200), (p.entity || "").slice(0, 200), (p.authority || "").slice(0, 200), "TIBER-EU",
      (p.scope || "").slice(0, 2000), (p.criticalFunctions || "").slice(0, 1000), "Preparation", 0,
      (p.whiteTeamLead || "").slice(0, 120), (p.controlTeamLead || "").slice(0, 120), (p.tiProvider || "").slice(0, 120), (p.rtProvider || "").slice(0, 120), new Date().toISOString(), tenant);
  let mid = allocId(db, "TLPTMILESTONE", "MilestoneID");
  const ins = db.prepare("INSERT INTO TLPTMILESTONE (MilestoneID, EngagementID, Phase, PhaseName, Code, Name, Deliverable, Status, SortOrder, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)");
  TLPT_MILESTONES.forEach((m, i) => ins.run(mid++, id, m.phase, TLPT_PHASES[m.phase].name, m.code, m.name, m.deliverable, "pending", i, tenant));
  return { id };
}

export function deleteEngagement(id: number, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  if (!inScope(db, id, tenant)) return false;
  for (const t of ["TLPTMILESTONE", "TLPTSCENARIO", "TLPTFLAG", "TLPTFINDING", "TLPTTEAM"]) db.prepare(`DELETE FROM ${t} WHERE EngagementID=?`).run(id);
  db.prepare("DELETE FROM TLPTENGAGEMENT WHERE EngagementID=?").run(id);
  return true;
}

/** Update a milestone's status + sign-off; advances the engagement's overall phase to the lowest incomplete one. */
export function setMilestone(milestoneId: number, status: string, by: string, docLink: string | undefined, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT EngagementID FROM TLPTMILESTONE WHERE MilestoneID=?").get(milestoneId) as { EngagementID: number } | undefined;
  if (!row || !inScope(db, Number(row.EngagementID), tenant)) return false;
  const st = MILESTONE_STATUS.includes(status) ? status : "pending";
  const now = new Date().toISOString();
  db.prepare("UPDATE TLPTMILESTONE SET Status=?, SignedBy=?, SignedAt=?, DocLink=COALESCE(?, DocLink) WHERE MilestoneID=?")
    .run(st, st === "completed" ? by : null, st === "completed" ? now : null, docLink ?? null, milestoneId);
  // recompute engagement phase/status = the phase of the first not-completed milestone
  const eng = Number(row.EngagementID);
  const next = db.prepare("SELECT Phase FROM TLPTMILESTONE WHERE EngagementID=? AND Status!='completed' ORDER BY SortOrder LIMIT 1").get(eng) as { Phase: number } | undefined;
  const phase = next ? num(next.Phase) : 2;
  const allDone = !next;
  db.prepare("UPDATE TLPTENGAGEMENT SET Phase=?, Status=? WHERE EngagementID=?").run(phase, allDone ? "Completed" : TLPT_PHASES[phase].name, eng);
  return true;
}

const addChild = (table: string, idCol: string, engId: number, cols: string[], vals: unknown[], tenant: number | null): { id: number } | null => {
  const db = getDb("XCOMPLIANCE");
  if (!inScope(db, engId, tenant)) return null;
  const id = allocId(db, table, idCol);
  const allCols = [idCol, "EngagementID", ...cols, "CreatedDate", "TenantID"];
  db.prepare(`INSERT INTO ${table} (${allCols.join(",")}) VALUES (${allCols.map(() => "?").join(",")})`).run(id, engId, ...vals, new Date().toISOString(), tenant);
  return { id };
};
const delChild = (table: string, idCol: string, id: number, tenant: number | null): boolean => {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare(`SELECT EngagementID FROM ${table} WHERE ${idCol}=?`).get(id) as { EngagementID: number } | undefined;
  if (!row || !inScope(db, Number(row.EngagementID), tenant)) return false;
  db.prepare(`DELETE FROM ${table} WHERE ${idCol}=?`).run(id);
  return true;
};

export function addScenario(engId: number, p: any, tenant: number | null): { id: number } | null {
  const actorType = TLPT_ACTOR_TYPES.includes(String(p.actorType)) ? String(p.actorType) : "";
  const status = TLPT_SCENARIO_STATUS.includes(String(p.status)) ? String(p.status) : "planned";
  return addChild("TLPTSCENARIO", "ScenarioID", engId,
    ["Name", "ThreatActor", "ActorType", "Narrative", "AttackTags", "FlagsTargeted", "Status", "Outcome", "Notes"],
    [String(p.name || "Scenario").slice(0, 200), String(p.threatActor || "").slice(0, 160), actorType, String(p.narrative || "").slice(0, 4000), String(p.attackTags || "").slice(0, 400), String(p.flagsTargeted || "").slice(0, 400), status, String(p.outcome || "").slice(0, 1000), String(p.notes || "").slice(0, 2000)], tenant);
}
export const deleteScenario = (id: number, tenant: number | null) => delChild("TLPTSCENARIO", "ScenarioID", id, tenant);

export function addFlag(engId: number, p: any, tenant: number | null): { id: number } | null {
  return addChild("TLPTFLAG", "FlagID", engId,
    ["Name", "CriticalFunction", "Description", "Reached", "Detected", "Prevented", "TimeToDetectHours", "Notes"],
    [String(p.name || "Flag").slice(0, 200), String(p.criticalFunction || "").slice(0, 200), String(p.description || "").slice(0, 2000), p.reached ? 1 : 0, p.detected ? 1 : 0, p.prevented ? 1 : 0, p.timeToDetectHours != null && p.timeToDetectHours !== "" ? Number(p.timeToDetectHours) : null, String(p.notes || "").slice(0, 2000)], tenant);
}
export const deleteFlag = (id: number, tenant: number | null) => delChild("TLPTFLAG", "FlagID", id, tenant);

/** Update a flag's Prevent/Detect outcome (the heart of the TIBER resilience measurement). */
export function setFlagOutcome(id: number, p: { reached?: boolean; detected?: boolean; prevented?: boolean; timeToDetectHours?: number | null }, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT EngagementID, Reached FROM TLPTFLAG WHERE FlagID=?").get(id) as { EngagementID: number; Reached: number } | undefined;
  if (!row || !inScope(db, Number(row.EngagementID), tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (p.reached !== undefined) { sets.push("Reached=?", "ReachedDate=?"); vals.push(p.reached ? 1 : 0, p.reached ? new Date().toISOString() : null); }
  if (p.detected !== undefined) { sets.push("Detected=?"); vals.push(p.detected ? 1 : 0); }
  if (p.prevented !== undefined) { sets.push("Prevented=?"); vals.push(p.prevented ? 1 : 0); }
  if (p.timeToDetectHours !== undefined) { sets.push("TimeToDetectHours=?"); vals.push(p.timeToDetectHours == null || p.timeToDetectHours === ("" as any) ? null : Number(p.timeToDetectHours)); }
  if (!sets.length) return true;
  db.prepare(`UPDATE TLPTFLAG SET ${sets.join(", ")} WHERE FlagID=?`).run(...vals, id);
  return true;
}

export function addFinding(engId: number, p: any, tenant: number | null): { id: number } | null {
  const sev = TLPT_SEVERITY.find((s) => s.toLowerCase() === String(p.severity || "").toLowerCase()) || "Medium";
  return addChild("TLPTFINDING", "FindingID", engId,
    ["Title", "Severity", "Category", "AttackTags", "Description", "Recommendation", "Status", "RemediationOwner", "DueDate"],
    [String(p.title || "Finding").slice(0, 300), sev, String(p.category || "").slice(0, 120), String(p.attackTags || "").slice(0, 400), String(p.description || "").slice(0, 4000), String(p.recommendation || "").slice(0, 4000), String(p.status || "Open").slice(0, 40), String(p.remediationOwner || "").slice(0, 120), String(p.dueDate || "").slice(0, 30)], tenant);
}
export const deleteFinding = (id: number, tenant: number | null) => delChild("TLPTFINDING", "FindingID", id, tenant);
export function setFindingStatus(id: number, status: string, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT EngagementID FROM TLPTFINDING WHERE FindingID=?").get(id) as { EngagementID: number } | undefined;
  if (!row || !inScope(db, Number(row.EngagementID), tenant)) return false;
  db.prepare("UPDATE TLPTFINDING SET Status=? WHERE FindingID=?").run(String(status || "Open").slice(0, 40), id);
  return true;
}

export function addTeamMember(engId: number, p: any, tenant: number | null): { id: number } | null {
  const role = TLPT_TEAM_ROLES.includes(String(p.teamRole)) ? String(p.teamRole) : String(p.teamRole || "").slice(0, 60);
  return addChild("TLPTTEAM", "TeamMemberID", engId,
    ["TeamRole", "MemberName", "Organisation", "Contact", "Notes"],
    [role, String(p.memberName || "").slice(0, 160), String(p.organisation || "").slice(0, 160), String(p.contact || "").slice(0, 200), String(p.notes || "").slice(0, 1000)], tenant);
}
export const deleteTeamMember = (id: number, tenant: number | null) => delChild("TLPTTEAM", "TeamMemberID", id, tenant);

/** Seed a demo TIBER-EU engagement (idempotent: skips if one already exists for the tenant). */
export function seedDemo(tenant: number): { created: number } {
  const db = getDb("XCOMPLIANCE");
  if (db.prepare("SELECT 1 FROM TLPTENGAGEMENT WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };
  const { id } = createEngagement({ name: "TIBER-EU test — core payment services", entity: "Acme Bank N.V.", authority: "National Central Bank (TCT)", scope: "Production: payment authorisation, SWIFT gateway, internet banking.", criticalFunctions: "Payment processing; SWIFT messaging; customer authentication", tiProvider: "ThreatIntel Co.", rtProvider: "RedOps GmbH", whiteTeamLead: "CISO office", controlTeamLead: "Head of SecOps" }, tenant);
  addTeamMember(id, { teamRole: "White Team", memberName: "J. Doe", organisation: "Acme Bank", contact: "wt@acme.example" }, tenant);
  addTeamMember(id, { teamRole: "Red Team (provider)", memberName: "RedOps lead", organisation: "RedOps GmbH" }, tenant);
  addTeamMember(id, { teamRole: "Threat Intelligence (provider)", memberName: "TI analyst", organisation: "ThreatIntel Co." }, tenant);
  const f1 = addFlag(id, { name: "Initiate a fraudulent SWIFT payment (test marker)", criticalFunction: "SWIFT messaging", reached: true, detected: true, prevented: false, timeToDetectHours: 9.5 }, tenant);
  const f2 = addFlag(id, { name: "Exfiltrate customer auth database", criticalFunction: "Customer authentication", reached: false, detected: true, prevented: true }, tenant);
  addFlag(id, { name: "Tamper with payment authorisation limits", criticalFunction: "Payment processing", reached: true, detected: false, prevented: false, timeToDetectHours: null }, tenant);
  addScenario(id, { name: "Spear-phishing → workstation foothold → SWIFT operator", threatActor: "Carbanak-style financial crime group", actorType: "Cyber-criminal", narrative: "Targeted phishing of back-office staff, lateral movement to the SWIFT operator segment.", attackTags: "T1566, T1078, T1021, T1114", flagsTargeted: "SWIFT payment", status: "detected" }, tenant);
  addScenario(id, { name: "Malicious insider abuses privileged access", threatActor: "Disgruntled administrator", actorType: "Insider", narrative: "Privileged insider attempts to alter authorisation limits.", attackTags: "T1078.004, T1098", flagsTargeted: "Payment authorisation", status: "achieved" }, tenant);
  addFinding(id, { title: "No alerting on anomalous SWIFT operator logon", severity: "High", category: "Detection", attackTags: "T1078", description: "Logons to the SWIFT operator host from a new workstation did not raise an alert.", recommendation: "Add UEBA/conditional-access alerting for SWIFT operator hosts.", status: "Open", remediationOwner: "SecOps" }, tenant);
  addFinding(id, { title: "Flat network between back-office and payment segment", severity: "Critical", category: "Segmentation", attackTags: "T1021", description: "Lateral movement reached the payment segment without crossing a control boundary.", recommendation: "Enforce micro-segmentation + jump host to the payment zone.", status: "Open", remediationOwner: "Network" }, tenant);
  void f1; void f2;
  return { created: 1 };
}
