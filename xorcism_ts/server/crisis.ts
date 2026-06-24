/**
 * crisis.ts — Crisis management & tabletop-exercise (TTX) readiness inventory.
 *
 * Hybrid model (see ensureCrisisSchema in db.ts): a tabletop exercise IS an AUDIT row with
 * AuditType='Tabletop Exercise' — so it reuses AUDITFINDING (as exercise observations /
 * improvement actions) and AUDITDOCUMENT (the after-action report). On top of that, three
 * crisis tables add richer exercise facilitation:
 *   CRISISSCENARIO      reusable scenario templates (ransomware, breach, DDoS, insider…)
 *   EXERCISEINJECT      the timeline of injects (template = AuditID NULL; exercise = AuditID set)
 *   EXERCISEPARTICIPANT the people/roles taking part in an exercise
 *
 * This is the crisis-readiness counterpart of compliance.ts: one pane over the exercise
 * programme — each exercise's inject progress, participants and open improvement actions,
 * the worklist (overdue actions, scenarios never exercised, exercises with no after-action
 * report) and a 0-100 crisis-readiness score. Read-only; CRUD is the schema-driven explorer.
 */
import { getDb } from "./db";

export interface ExerciseRow {
  id: number;                 // AuditID
  name: string;
  scenario: string;           // linked scenario name / type
  type: string;
  status: string;
  date: string | null;
  completed: boolean;
  injects: number;
  injectsDone: number;
  participants: number;
  actions: number;            // open improvement actions (AUDITFINDING, open)
  highActions: number;
  overdue: number;
  hasAAR: boolean;            // after-action report present (AUDITDOCUMENT)
  score: number;              // 0-100 posture (higher = more outstanding gaps)
}
export interface ScenarioRow {
  id: number; name: string; type: string; severity: string; injects: number; exercised: boolean;
}
export interface CrisisFinding {
  id: number;
  exercise: string;
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  overdue: boolean;
  unassigned: boolean;
  kind: "action" | "scenario" | "exercise";
  label: string;
}
export interface CrisisInventory {
  rows: ExerciseRow[];
  findings: CrisisFinding[];
  scenarios: ScenarioRow[];
  summary: {
    exercises: number; planned: number; inProgress: number; completed: number; completionRate: number | null;
    scenarios: number; scenariosNeverExercised: number; scenarioCoverage: number;
    openActions: number; highActions: number; overdueActions: number; participants: number; withoutAAR: number;
    readinessScore: number;
    byType: Record<string, number>; byStatus: Record<string, number>;
  };
}

const EMPTY: CrisisInventory = {
  rows: [], findings: [], scenarios: [],
  summary: {
    exercises: 0, planned: 0, inProgress: 0, completed: 0, completionRate: null,
    scenarios: 0, scenariosNeverExercised: 0, scenarioCoverage: 0,
    openActions: 0, highActions: 0, overdueActions: 0, participants: 0, withoutAAR: 0,
    readinessScore: 0, byType: {}, byStatus: {},
  },
};

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 18, medium: 8, low: 3, info: 1 };
const CLOSED = /closed|clos[eé]|resolv|remediat|done|accepted|accept[eé]|fixed|terminé|fermé/i;
const DONE_INJECT = /done|complet|respond|résolu|terminé|closed|fermé|played|injected/i;
const HIGH = /high|critical/i;
const TTX = /tabletop|table-top|exercise|exercice|crisis|crise|simulation|drill|ttx|war.?game/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(dbName: string, table: string): boolean {
  try { return !!getDb(dbName).prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); }
  catch { return false; }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const normSev = (s: string): CrisisFinding["severity"] => {
  const v = String(s || "").toLowerCase();
  return v.includes("crit") ? "Critical" : v.includes("high") ? "High" : v.includes("med") ? "Medium" : v.includes("info") ? "Info" : "Low";
};

/** Full crisis-management inventory: tabletop exercises + scenario library + worklist. */
export function crisisInventory(tenant: number | null): CrisisInventory {
  if (!has("XCOMPLIANCE", "AUDIT")) return { ...EMPTY };
  const cc = getDb("XCOMPLIANCE");
  const ac = cols("XCOMPLIANCE", "AUDIT");
  const tw = tenant != null && ac.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const allAudits = cc.prepare(`SELECT * FROM AUDIT ${tw}`).all() as Record<string, unknown>[];
  // only the tabletop / crisis exercises
  const audits = allAudits.filter((a) => TTX.test(`${a.AuditType ?? ""} ${a.AuditCategory ?? ""} ${a.AuditName ?? ""}`));

  // ── scenario template library ──────────────────────────────────────────────
  const scenarios: ScenarioRow[] = [];
  let exercisedScenarioIds = new Set<number>();
  const injectsByAudit = new Map<number, { total: number; done: number }>();
  const injectsByScenarioTpl = new Map<number, number>();
  if (has("XCOMPLIANCE", "EXERCISEINJECT")) {
    const itw = tenant != null && cols("XCOMPLIANCE", "EXERCISEINJECT").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const inj of cc.prepare(`SELECT AuditID, ScenarioID, Status FROM EXERCISEINJECT ${itw}`).all() as { AuditID: number | null; ScenarioID: number | null; Status: string }[]) {
      if (inj.AuditID != null) {
        const agg = injectsByAudit.get(Number(inj.AuditID)) ?? { total: 0, done: 0 };
        agg.total++; if (DONE_INJECT.test(String(inj.Status ?? ""))) agg.done++;
        injectsByAudit.set(Number(inj.AuditID), agg);
        if (inj.ScenarioID != null) exercisedScenarioIds.add(Number(inj.ScenarioID));
      } else if (inj.ScenarioID != null) {
        injectsByScenarioTpl.set(Number(inj.ScenarioID), (injectsByScenarioTpl.get(Number(inj.ScenarioID)) ?? 0) + 1);
      }
    }
  }
  if (has("XCOMPLIANCE", "CRISISSCENARIO")) {
    const stw = tenant != null && cols("XCOMPLIANCE", "CRISISSCENARIO").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const s of cc.prepare(`SELECT ScenarioID, ScenarioName, ScenarioType, Severity FROM CRISISSCENARIO ${stw}`).all() as { ScenarioID: number; ScenarioName: string; ScenarioType: string; Severity: string }[]) {
      scenarios.push({
        id: Number(s.ScenarioID), name: String(s.ScenarioName || `Scenario #${s.ScenarioID}`),
        type: String(s.ScenarioType || "—"), severity: String(s.Severity || "—"),
        injects: injectsByScenarioTpl.get(Number(s.ScenarioID)) ?? 0,
        exercised: exercisedScenarioIds.has(Number(s.ScenarioID)),
      });
    }
  }

  // participants per exercise
  const participantsByAudit = new Map<number, number>();
  if (has("XCOMPLIANCE", "EXERCISEPARTICIPANT")) {
    const ptw = tenant != null && cols("XCOMPLIANCE", "EXERCISEPARTICIPANT").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const p of cc.prepare(`SELECT AuditID FROM EXERCISEPARTICIPANT ${ptw}`).all() as { AuditID: number }[])
      if (p.AuditID != null) participantsByAudit.set(Number(p.AuditID), (participantsByAudit.get(Number(p.AuditID)) ?? 0) + 1);
  }

  const auditName = new Map<number, string>();
  for (const a of audits) auditName.set(Number(a.AuditID), String(a.AuditName ?? "").trim() || `Exercise #${a.AuditID}`);

  // ── improvement actions (AUDITFINDING for these exercises) ──────────────────
  const fc = cols("XCOMPLIANCE", "AUDITFINDING");
  const actionsByAudit = new Map<number, { open: number; high: number; overdue: number; unassigned: number; total: number }>();
  const worklist: CrisisFinding[] = [];
  if (fc.size && auditName.size) {
    const ids = [...auditName.keys()];
    const ph = ids.map(() => "?").join(",") || "NULL";
    const all = cc.prepare(`SELECT * FROM AUDITFINDING WHERE AuditID IN (${ph})`).all(...ids) as Record<string, unknown>[];
    for (const f of all) {
      const aid = Number(f.AuditID);
      const agg = actionsByAudit.get(aid) ?? { open: 0, high: 0, overdue: 0, unassigned: 0, total: 0 };
      agg.total++;
      const open = !CLOSED.test(`${f.FindingStatus ?? ""} ${f.WorkflowStatus ?? ""}`);
      const sev = normSev(String(f.Severity ?? f.FindingCriticity ?? ""));
      const dueIn = daysUntil(f.DueDate ? String(f.DueDate) : null);
      const overdue = open && dueIn != null && dueIn < 0;
      const unassigned = open && f.RemediationOwnerPersonID == null && !String(f.FindingStakeholder ?? "").trim();
      if (open) {
        agg.open++;
        if (HIGH.test(sev)) agg.high++;
        if (overdue) agg.overdue++;
        if (unassigned) agg.unassigned++;
        const name = String(f.FindingName ?? "").trim() || `Action #${f.AuditFindingID}`;
        const tags = [overdue ? "overdue" : "", unassigned ? "no owner" : ""].filter(Boolean);
        worklist.push({
          id: Number(f.AuditFindingID), exercise: auditName.get(aid) || `#${aid}`, name, severity: sev,
          overdue, unassigned, kind: "action",
          label: `${name}${tags.length ? ` (${tags.join(", ")})` : ""}`,
        });
      }
      actionsByAudit.set(aid, agg);
    }
  }

  // after-action report present? (AUDITDOCUMENT linked to the exercise audit)
  const aarAudits = new Set<number>();
  if (has("XCOMPLIANCE", "AUDITDOCUMENT"))
    for (const d of cc.prepare("SELECT DISTINCT AuditID FROM AUDITDOCUMENT").all() as { AuditID: number }[])
      if (d.AuditID != null) aarAudits.add(Number(d.AuditID));

  // ── rows ────────────────────────────────────────────────────────────────────
  const rows: ExerciseRow[] = audits.map((a) => {
    const id = Number(a.AuditID);
    const act = actionsByAudit.get(id) ?? { open: 0, high: 0, overdue: 0, unassigned: 0, total: 0 };
    const inj = injectsByAudit.get(id) ?? { total: 0, done: 0 };
    const status = String(a.AuditStatus ?? "").trim() || "Planned";
    const completed = /complet|clos|done|terminé|fermé|conduct|delivered/i.test(status) || !!a.AuditClosureDate;
    const hasAAR = aarAudits.has(id);
    let score = act.overdue * 10 + act.unassigned * 3 + (completed && !hasAAR ? 8 : 0);
    for (const w of worklist) if (w.kind === "action" && w.exercise === auditName.get(id)) score += SEV_WEIGHT[w.severity.toLowerCase()] ?? 3;
    return {
      id, name: auditName.get(id)!,
      scenario: String(a.AuditScope ?? "").trim() || String(a.AuditCategory ?? "").trim() || "—",
      type: String(a.AuditType ?? "").trim() || "Tabletop Exercise", status,
      date: a.AuditDate ? String(a.AuditDate).slice(0, 10) : null, completed,
      injects: inj.total, injectsDone: inj.done, participants: participantsByAudit.get(id) ?? 0,
      actions: act.open, highActions: act.high, overdue: act.overdue, hasAAR,
      score: Math.min(100, score),
    };
  });

  // ── extra worklist items: scenarios never exercised, planned exercises overdue, no AAR ──
  const neverExercised = scenarios.filter((s) => !s.exercised);
  for (const s of neverExercised.slice(0, 30))
    worklist.push({ id: s.id, exercise: "Scenario library", name: s.name, severity: s.severity.toLowerCase().includes("crit") ? "High" : "Medium", overdue: false, unassigned: false, kind: "scenario", label: `Scenario never exercised: ${s.name} (${s.type})` });
  const today = new Date().toISOString().slice(0, 10);
  for (const r of rows) {
    const dueIn = daysUntil(r.date);
    if (!r.completed && r.date && r.date < today && dueIn != null && dueIn < 0)
      worklist.push({ id: r.id, exercise: r.name, name: r.name, severity: "Medium", overdue: true, unassigned: false, kind: "exercise", label: `Exercise overdue: ${r.name} planned ${-dueIn}d ago, not yet conducted` });
    if (r.completed && !r.hasAAR)
      worklist.push({ id: r.id, exercise: r.name, name: r.name, severity: "Low", overdue: false, unassigned: false, kind: "exercise", label: `No after-action report: ${r.name} was conducted but has no AAR document` });
  }

  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  worklist.sort((a, b) => (SEV_RANK[a.severity.toLowerCase()] - SEV_RANK[b.severity.toLowerCase()]) || (a.overdue === b.overdue ? 0 : a.overdue ? -1 : 1) || a.exercise.localeCompare(b.exercise));

  // ── summary + readiness score ───────────────────────────────────────────────
  const completed = rows.filter((r) => r.completed).length;
  const openActions = worklist.filter((w) => w.kind === "action").length;
  const overdueActions = worklist.filter((w) => w.kind === "action" && w.overdue).length;
  const completionRate = rows.length ? Math.round((completed / rows.length) * 100) : null;
  const scenarioCoverage = scenarios.length ? Math.round((scenarios.filter((s) => s.exercised).length / scenarios.length) * 100) : 0;
  // readiness (higher = better): half exercise completion, half scenario coverage, minus overdue penalties.
  const readinessScore = Math.max(0, Math.min(100, Math.round(
    (completionRate ?? 0) * 0.5 + scenarioCoverage * 0.5 - overdueActions * 5 - worklist.filter((w) => w.kind === "exercise" && w.overdue).length * 5,
  )));

  const byType: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const r of rows) { byType[r.type] = (byType[r.type] || 0) + 1; byStatus[r.status] = (byStatus[r.status] || 0) + 1; }

  return {
    rows, findings: worklist, scenarios: scenarios.sort((a, b) => Number(a.exercised) - Number(b.exercised) || a.name.localeCompare(b.name)),
    summary: {
      exercises: rows.length,
      planned: rows.filter((r) => /plan|scheduled|prévu/i.test(r.status)).length,
      inProgress: rows.filter((r) => /progress|cours|ongoing/i.test(r.status)).length,
      completed, completionRate,
      scenarios: scenarios.length,
      scenariosNeverExercised: neverExercised.length,
      scenarioCoverage,
      openActions,
      highActions: worklist.filter((w) => w.kind === "action" && HIGH.test(w.severity)).length,
      overdueActions,
      participants: [...participantsByAudit.values()].reduce((s, n) => s + n, 0),
      withoutAAR: rows.filter((r) => r.completed && !r.hasAAR).length,
      readinessScore,
      byType, byStatus,
    },
  };
}

/** Launch a tabletop exercise from a scenario template: create the AUDIT (AuditType=
 *  'Tabletop Exercise'), copy the scenario's template injects into EXERCISEINJECT with the
 *  new AuditID, and return the new exercise's id. Returns {auditId, injects}. */
export function launchExercise(scenarioId: number, opts: { name?: string; date?: string; tenant: number | null }): { auditId: number; injects: number; scenario: string } {
  const cc = getDb("XCOMPLIANCE");
  const sc = cc.prepare("SELECT * FROM CRISISSCENARIO WHERE ScenarioID = ?").get(scenarioId) as Record<string, unknown> | undefined;
  if (!sc) throw new Error("scenario not found");
  const now = new Date().toISOString();
  const date = opts.date || now.slice(0, 10);
  const name = (opts.name || `Tabletop Exercise — ${sc.ScenarioName} — ${date}`).slice(0, 300);
  const ac = cols("XCOMPLIANCE", "AUDIT");
  const tenantCol = ac.has("TenantID");

  const tx = cc.transaction(() => {
    const r = cc.prepare(
      `INSERT INTO AUDIT (AuditGUID, AuditName, AuditDate, AuditStatus, AuditDescription, AuditCategory, AuditScope, AuditType${tenantCol ? ", TenantID" : ""})
       VALUES (?,?,?,?,?,?,?,?${tenantCol ? ",?" : ""})`,
    ).run(
      randomGuid(), name, date, "Planned",
      `Tabletop exercise driving the "${sc.ScenarioName}" crisis scenario (${sc.ScenarioType}). Objectives: ${String(sc.Objectives ?? "").slice(0, 500)}`,
      "Crisis Management", String(sc.ScenarioName ?? ""), "Tabletop Exercise",
      ...(tenantCol ? [opts.tenant] : []),
    );
    const auditId = Number(r.lastInsertRowid);
    // copy template injects (AuditID NULL, ScenarioID = scenario) → new exercise injects
    const tpl = cc.prepare("SELECT * FROM EXERCISEINJECT WHERE ScenarioID = ? AND AuditID IS NULL ORDER BY COALESCE(StepOrder, InjectID)").all(scenarioId) as Record<string, unknown>[];
    const injCol = cols("XCOMPLIANCE", "EXERCISEINJECT");
    const ins = cc.prepare(
      `INSERT INTO EXERCISEINJECT (InjectGUID, AuditID, ScenarioID, StepOrder, InjectTime, OffsetMinutes, Channel, Sender, Recipients, Subject, Title, Description, InjectType, ExpectedAction, Status, CreatedDate${injCol.has("TenantID") ? ", TenantID" : ""})
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?${injCol.has("TenantID") ? ",?" : ""})`,
    );
    let n = 0;
    for (const t of tpl) {
      ins.run(
        randomGuid(), auditId, scenarioId, t.StepOrder ?? ++n, t.InjectTime ?? null,
        t.OffsetMinutes ?? null, t.Channel ?? null, t.Sender ?? null, t.Recipients ?? null, t.Subject ?? null,
        t.Title ?? null, t.Description ?? null, t.InjectType ?? null, t.ExpectedAction ?? null,
        "Pending", now, ...(injCol.has("TenantID") ? [opts.tenant] : []),
      );
      n++;
    }
    return { auditId, injects: tpl.length, scenario: String(sc.ScenarioName ?? "") };
  });
  return tx();
}

function randomGuid(): string {
  // crypto.randomUUID is available in Node 16+; keep a tiny local helper to avoid an import churn.
  return (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  OpenAEV-style exercise RUNTIME: play a scenario as a timeline of multi-channel
//  injects (email / SMS / WhatsApp / phone / media …) and record timestamped
//  reactions / decisions in EXERCISELOG. All read/write stays in XCOMPLIANCE and
//  is tenant-checked via the parent AUDIT.
// ─────────────────────────────────────────────────────────────────────────────
type CC = ReturnType<typeof getDb>;
const CHANNEL_LABEL: Record<string, string> = { email: "Email", sms: "SMS", whatsapp: "WhatsApp", phone: "Phone call", media: "Media", technical: "Technical alert", decision: "Decision", manual: "Manual inject" };
function channelLabel(ch: string): string { return CHANNEL_LABEL[ch] || ch; }
function deriveChannel(injectType: unknown, fallback = "manual"): string {
  const s = String(injectType ?? "").toLowerCase();
  if (/mail/.test(s)) return "email";
  if (/\bsms\b|text/.test(s)) return "sms";
  if (/whatsapp|signal|telegram/.test(s)) return "whatsapp";
  if (/phone|call|voice/.test(s)) return "phone";
  if (/media|news|press|social/.test(s)) return "media";
  if (/tech|system|siem|alert|log/.test(s)) return "technical";
  if (/decision|escalat/.test(s)) return "decision";
  return fallback;
}
function nowIso(): string { return new Date().toISOString(); }
function nextId(cc: CC, table: string, pk: string): number {
  return (cc.prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n;
}
function insertByCols(cc: CC, table: string, rec: Record<string, unknown>, present: Set<string>): void {
  const keys = Object.keys(rec).filter((k) => present.has(k));
  cc.prepare(`INSERT INTO ${table} (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
}
function ownExercise(cc: CC, auditId: number, tenant: number | null): Record<string, unknown> | null {
  const where = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  return (cc.prepare(`SELECT * FROM AUDIT WHERE AuditID = ? ${where}`).get(...(tenant != null ? [auditId, tenant] : [auditId])) as Record<string, unknown> | undefined) ?? null;
}
function logEvent(cc: CC, o: { auditId: number; injectId?: number | null; participantId?: number | null; eventType: string; channel?: string | null; message?: string | null; loggedAt: string; byUser?: string | null; tenant: number | null }): number {
  if (!has("XCOMPLIANCE", "EXERCISELOG")) return 0;
  const rec: Record<string, unknown> = {
    LogID: nextId(cc, "EXERCISELOG", "LogID"), LogGUID: randomGuid(), AuditID: o.auditId,
    InjectID: o.injectId ?? null, ParticipantID: o.participantId ?? null, EventType: o.eventType,
    Channel: o.channel ?? null, Message: o.message ?? null, LoggedAt: o.loggedAt, ByUser: o.byUser ?? null,
    CreatedDate: nowIso(), TenantID: o.tenant,
  };
  insertByCols(cc, "EXERCISELOG", rec, cols("XCOMPLIANCE", "EXERCISELOG"));
  return Number(rec.LogID);
}
function startedEndedAt(cc: CC, auditId: number): { startedAt: string | null; endedAt: string | null } {
  if (!has("XCOMPLIANCE", "EXERCISELOG")) return { startedAt: null, endedAt: null };
  const s = cc.prepare("SELECT LoggedAt FROM EXERCISELOG WHERE AuditID=? AND EventType='start' ORDER BY LogID DESC LIMIT 1").get(auditId) as { LoggedAt?: string } | undefined;
  const e = cc.prepare("SELECT LoggedAt FROM EXERCISELOG WHERE AuditID=? AND EventType='end' ORDER BY LogID DESC LIMIT 1").get(auditId) as { LoggedAt?: string } | undefined;
  return { startedAt: s?.LoggedAt ?? null, endedAt: e?.LoggedAt ?? null };
}

/** Full runtime view of one exercise: timeline of injects + participants + the timestamped reaction log. */
export function exerciseDetail(auditId: number, tenant: number | null): any | null {
  const cc = getDb("XCOMPLIANCE");
  const a = ownExercise(cc, auditId, tenant);
  if (!a) return null;
  const { startedAt, endedAt } = startedEndedAt(cc, auditId);
  const startMs = startedAt ? Date.parse(startedAt) : null;
  const injRows = cc.prepare(
    "SELECT * FROM EXERCISEINJECT WHERE AuditID=? ORDER BY COALESCE(OffsetMinutes, StepOrder*15, 99999), COALESCE(StepOrder, InjectID), InjectID",
  ).all(auditId) as Record<string, unknown>[];
  const injects = injRows.map((i) => {
    const offset = i.OffsetMinutes != null && i.OffsetMinutes !== "" ? Number(i.OffsetMinutes) : (i.StepOrder != null ? Number(i.StepOrder) * 15 : null);
    const status = String(i.Status ?? "Pending");
    const delivered = i.DeliveredDate != null || /deliver|sent|played|done|respond/i.test(status);
    return {
      id: Number(i.InjectID), stepOrder: i.StepOrder != null ? Number(i.StepOrder) : null,
      title: String(i.Title ?? ""), description: String(i.Description ?? ""),
      channel: (String(i.Channel ?? "").trim() || deriveChannel(i.InjectType)),
      injectType: String(i.InjectType ?? ""), offsetMinutes: offset,
      sender: String(i.Sender ?? ""), recipients: String(i.Recipients ?? ""), subject: String(i.Subject ?? ""),
      expectedAction: String(i.ExpectedAction ?? ""), actualResponse: String(i.ActualResponse ?? ""),
      status, delivered, deliveredDate: i.DeliveredDate ? String(i.DeliveredDate) : null,
      scheduledAt: startMs != null && offset != null ? new Date(startMs + offset * 60000).toISOString() : null,
    };
  });
  const participants = (cc.prepare("SELECT * FROM EXERCISEPARTICIPANT WHERE AuditID=? ORDER BY ParticipantID").all(auditId) as Record<string, unknown>[]).map((p) => ({
    id: Number(p.ParticipantID), name: String(p.ParticipantName ?? ""), role: String(p.CrisisRole ?? ""),
    team: String(p.Team ?? ""), email: String(p.Email ?? ""), phone: String(p.Phone ?? ""),
    attended: !!p.Attended, personId: p.PersonID != null ? Number(p.PersonID) : null,
  }));
  let log: any[] = [];
  try {
    log = (cc.prepare("SELECT * FROM EXERCISELOG WHERE AuditID=? ORDER BY LogID").all(auditId) as Record<string, unknown>[]).map((l) => ({
      id: Number(l.LogID), injectId: l.InjectID != null ? Number(l.InjectID) : null,
      participantId: l.ParticipantID != null ? Number(l.ParticipantID) : null, eventType: String(l.EventType ?? "note"),
      channel: String(l.Channel ?? ""), message: String(l.Message ?? ""), loggedAt: String(l.LoggedAt ?? ""), byUser: String(l.ByUser ?? ""),
    }));
  } catch { log = []; }
  const delivered = injects.filter((i) => i.delivered).length;
  const reactions = log.filter((l) => ["response", "decision", "escalation", "acknowledge"].includes(l.eventType)).length;
  const durationMin = startedAt ? Math.max(0, Math.round(((endedAt ? Date.parse(endedAt) : Date.now()) - Date.parse(startedAt)) / 60000)) : null;
  return {
    exercise: {
      auditId, name: String(a.AuditName ?? ""), scenario: String(a.AuditScope ?? ""), status: String(a.AuditStatus ?? ""),
      date: a.AuditDate ? String(a.AuditDate).slice(0, 10) : null, startedAt, endedAt, durationMin, running: !!startedAt && !endedAt,
    },
    injects, participants, log,
    summary: { injects: injects.length, delivered, pending: injects.length - delivered, participants: participants.length, reactions, events: log.length, durationMin },
  };
}

export function startExercise(auditId: number, tenant: number | null, byUser?: string): { startedAt: string } {
  const cc = getDb("XCOMPLIANCE");
  if (!ownExercise(cc, auditId, tenant)) throw new Error("exercise not found");
  const at = nowIso();
  logEvent(cc, { auditId, eventType: "start", message: "Exercise started — the clock is running", loggedAt: at, byUser, tenant });
  try { cc.prepare("UPDATE AUDIT SET AuditStatus='In Progress' WHERE AuditID=?").run(auditId); } catch { /* status best-effort */ }
  return { startedAt: at };
}
export function endExercise(auditId: number, tenant: number | null, byUser?: string): { endedAt: string } {
  const cc = getDb("XCOMPLIANCE");
  if (!ownExercise(cc, auditId, tenant)) throw new Error("exercise not found");
  const at = nowIso();
  logEvent(cc, { auditId, eventType: "end", message: "Exercise ended", loggedAt: at, byUser, tenant });
  try { cc.prepare("UPDATE AUDIT SET AuditStatus='Completed' WHERE AuditID=?").run(auditId); } catch { /* status best-effort */ }
  return { endedAt: at };
}
/** "Send" an inject (records delivery + a timeline entry; real email/SMS delivery would be a connector). */
export function deliverInject(injectId: number, tenant: number | null, byUser?: string): { ok: true; deliveredDate: string; channel: string } {
  const cc = getDb("XCOMPLIANCE");
  const i = cc.prepare("SELECT * FROM EXERCISEINJECT WHERE InjectID=?").get(injectId) as Record<string, unknown> | undefined;
  if (!i || i.AuditID == null || !ownExercise(cc, Number(i.AuditID), tenant)) throw new Error("inject not found");
  const at = nowIso();
  cc.prepare("UPDATE EXERCISEINJECT SET Status='Delivered', DeliveredDate=? WHERE InjectID=?").run(at, injectId);
  const ch = String(i.Channel ?? "").trim() || deriveChannel(i.InjectType);
  const to = String(i.Recipients ?? "").trim();
  logEvent(cc, { auditId: Number(i.AuditID), injectId, eventType: "deliver", channel: ch, message: `📤 ${channelLabel(ch)} delivered: ${String(i.Subject || i.Title || "inject")}${to ? ` → ${to}` : ""}`, loggedAt: at, byUser, tenant });
  return { ok: true, deliveredDate: at, channel: ch };
}
/** Record a timestamped participant reaction / decision / note against the exercise (and optional inject). */
export function logExerciseEvent(auditId: number, p: { injectId?: number | null; participantId?: number | null; eventType?: string; message?: string; channel?: string }, tenant: number | null, byUser?: string): { id: number; loggedAt: string } {
  const cc = getDb("XCOMPLIANCE");
  if (!ownExercise(cc, auditId, tenant)) throw new Error("exercise not found");
  const et = ["response", "decision", "escalation", "acknowledge", "note", "media"].includes(String(p.eventType)) ? String(p.eventType) : "note";
  const at = nowIso();
  const id = logEvent(cc, { auditId, injectId: p.injectId ?? null, participantId: p.participantId ?? null, eventType: et, channel: p.channel ?? null, message: String(p.message ?? "").slice(0, 4000), loggedAt: at, byUser, tenant });
  // mirror a response back onto the inject so the /crisis-management progress bar reflects it
  if (p.injectId && (et === "response" || et === "decision")) {
    try { cc.prepare("UPDATE EXERCISEINJECT SET ActualResponse=?, Status='Responded' WHERE InjectID=? AND AuditID=?").run(String(p.message ?? "").slice(0, 2000), p.injectId, auditId); } catch { /* best-effort */ }
  }
  return { id, loggedAt: at };
}
export function addExerciseParticipant(auditId: number, p: { personId?: number | null; name?: string; role?: string; team?: string; email?: string; phone?: string; attended?: boolean }, tenant: number | null): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  if (!ownExercise(cc, auditId, tenant)) throw new Error("exercise not found");
  const rec: Record<string, unknown> = {
    ParticipantID: nextId(cc, "EXERCISEPARTICIPANT", "ParticipantID"), ParticipantGUID: randomGuid(), AuditID: auditId,
    PersonID: p.personId ?? null, ParticipantName: String(p.name ?? "").slice(0, 200), CrisisRole: p.role ?? null,
    Team: p.team ?? null, Email: p.email ?? null, Phone: p.phone ?? null, Attended: p.attended ? 1 : 0,
    CreatedDate: nowIso(), TenantID: tenant,
  };
  insertByCols(cc, "EXERCISEPARTICIPANT", rec, cols("XCOMPLIANCE", "EXERCISEPARTICIPANT"));
  return { id: Number(rec.ParticipantID) };
}
export function addExerciseInject(auditId: number, p: { title?: string; channel?: string; offsetMinutes?: number | null; sender?: string; recipients?: string; subject?: string; description?: string; injectType?: string; expectedAction?: string }, tenant: number | null): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  if (!ownExercise(cc, auditId, tenant)) throw new Error("exercise not found");
  const maxStep = (cc.prepare("SELECT COALESCE(MAX(StepOrder),0) m FROM EXERCISEINJECT WHERE AuditID=?").get(auditId) as { m: number }).m;
  const rec: Record<string, unknown> = {
    InjectID: nextId(cc, "EXERCISEINJECT", "InjectID"), InjectGUID: randomGuid(), AuditID: auditId, ScenarioID: null,
    StepOrder: maxStep + 1, OffsetMinutes: p.offsetMinutes ?? null, Channel: p.channel ?? "manual", Sender: p.sender ?? null,
    Recipients: p.recipients ?? null, Subject: p.subject ?? null, Title: String(p.title ?? "").slice(0, 300),
    Description: p.description ?? null, InjectType: p.injectType ?? null, ExpectedAction: p.expectedAction ?? null,
    Status: "Pending", CreatedDate: nowIso(), TenantID: tenant,
  };
  insertByCols(cc, "EXERCISEINJECT", rec, cols("XCOMPLIANCE", "EXERCISEINJECT"));
  return { id: Number(rec.InjectID) };
}
