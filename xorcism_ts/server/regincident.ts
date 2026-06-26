/**
 * regincident.ts — Regulatory incident-reporting obligations (/reg-incident-reporting).
 *
 * Given a cyber incident, which regulators must be notified, and by when? This engine reads the
 * incident queue (XINCIDENT.INCIDENT), derives the applicable regimes from each incident's attributes,
 * and computes the statutory reporting DEADLINES (clock from detection) for:
 *   - GDPR  (EU 2016/679, Art. 33/34) — personal-data breach: notify the supervisory authority in 72h.
 *   - NIS2  (EU 2022/2555, Art. 23)   — significant incident: early warning 24h, notification 72h, final 1mo.
 *   - DORA  (EU 2022/2554, Art. 19)   — major ICT incident: initial 24h (≈4h after classification), 72h, 1mo.
 *   - CRA   (EU 2024/2847, Art. 14)   — actively-exploited vuln / severe incident: early warning 24h, 72h, final report.
 *
 * Submissions are tracked in XINCIDENT.REGINCIDENTREPORT (mark each stage submitted). Compute-only
 * worklist (overdue / due-soon first) otherwise — mirrors the insurance / AOI lenses.
 */
import { getDb } from "./db";

const now = (): string => new Date().toISOString();
const HOUR = 3_600_000, DAY = 86_400_000;

interface Stage { stage: string; h?: number; d?: number; note?: string }
const REGIMES: Record<string, { label: string; appliesIf: string; stages: Stage[] }> = {
  GDPR: { label: "GDPR (EU 2016/679)", appliesIf: "personal data involved", stages: [
    { stage: "Notify supervisory authority", h: 72 },
    { stage: "Notify data subjects (if high risk)", h: 72, note: "without undue delay" }] },
  NIS2: { label: "NIS2 (EU 2022/2555)", appliesIf: "essential/important entity · significant incident", stages: [
    { stage: "Early warning", h: 24 }, { stage: "Incident notification", h: 72 }, { stage: "Final report", d: 30 }] },
  DORA: { label: "DORA (EU 2022/2554)", appliesIf: "financial entity · major ICT incident", stages: [
    { stage: "Initial notification", h: 24, note: "as early as 4h after classification" },
    { stage: "Intermediate report", h: 72 }, { stage: "Final report", d: 30 }] },
  CRA: { label: "Cyber Resilience Act (EU 2024/2847)", appliesIf: "manufacturer · actively-exploited vuln / severe incident", stages: [
    { stage: "Early warning (CSIRT/ENISA)", h: 24 }, { stage: "Notification", h: 72 }, { stage: "Final report", d: 14 }] },
};

export function ensureRegIncidentTables(): void {
  getDb("XINCIDENT").exec(`
    CREATE TABLE IF NOT EXISTS REGINCIDENTREPORT (
      ReportID INTEGER PRIMARY KEY, IncidentID INTEGER, TenantID INTEGER, Regulator TEXT, Stage TEXT,
      DueDate TEXT, Status TEXT DEFAULT 'pending', SubmittedDate TEXT, Reference TEXT, Notes TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_regincrep_inc ON REGINCIDENTREPORT(IncidentID);
    CREATE INDEX IF NOT EXISTS ix_regincrep_tenant ON REGINCIDENTREPORT(TenantID);
  `);
}

const cols = (t: string): Set<string> => { try { return new Set((getDb("XINCIDENT").prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } };

interface Obligation { incidentId: number; incident: string; severity: string; regulator: string; regLabel: string; appliesIf: string; stage: string; note: string; refDate: string; dueDate: string; daysLeft: number | null; status: string; submittedDate: string | null }

export function regIncidentObligations(tenant: number | null): any {
  ensureRegIncidentTables();
  const db = getDb("XINCIDENT");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) return { summary: { incidents: 0, obligations: 0, overdue: 0, dueSoon: 0, submitted: 0 }, worklist: [], byRegulator: {} };
  const ic = cols("INCIDENT");
  const tw = tenant != null && ic.has("TenantID") ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const incs = db.prepare(`SELECT * FROM INCIDENT ${tw} ORDER BY rowid DESC LIMIT 500`).all(...(tw ? [tenant] : [])) as Record<string, any>[];

  // tracked submissions
  const reports = new Map<string, any>();
  const rtw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  for (const r of db.prepare(`SELECT * FROM REGINCIDENTREPORT ${rtw}`).all(...(rtw ? [tenant] : [])) as any[]) reports.set(`${r.IncidentID}|${r.Regulator}|${r.Stage}`, r);

  const tNow = Date.now();
  const obligations: Obligation[] = [];
  for (const r of incs) {
    const id = Number(r.IncidentID ?? r.rowid);
    const name = String(r.summary ?? r.Title ?? r.IncidentName ?? `Incident #${id}`).slice(0, 120);
    const sev = String(r.Severity ?? r.Criticity ?? "").trim();
    const text = `${r.summary ?? ""} ${r.classification ?? ""} ${r.Title ?? ""}`.toLowerCase();
    const significant = /critical|high|major|significant/i.test(sev) || /major|significant/.test(text);
    const personalData = /personal data|pii|gdpr|data breach|breach of personal|customer data/.test(text);
    const exploited = /exploit|actively.?exploited|cve-|product|firmware|device/.test(text);
    const refRaw = r.detect_datetime || r.datetime_reported || r.start_datetime || r.CreatedDate;
    const refDate = refRaw ? new Date(refRaw).toISOString() : now();
    const refMs = Date.parse(refDate) || tNow;

    const regimes: string[] = [];
    if (personalData) regimes.push("GDPR");
    if (significant) { regimes.push("NIS2"); regimes.push("DORA"); }
    if (exploited) regimes.push("CRA");
    for (const reg of regimes) {
      const R = REGIMES[reg];
      for (const st of R.stages) {
        const dueMs = refMs + (st.h ? st.h * HOUR : (st.d || 0) * DAY);
        const tracked = reports.get(`${id}|${reg}|${st.stage}`);
        const submitted = tracked && /submit|done|sent|filed|n.?a/i.test(tracked.Status || "");
        const status = submitted ? (tracked.Status || "submitted") : dueMs < tNow ? "overdue" : (dueMs - tNow) < DAY ? "due-soon" : "pending";
        obligations.push({
          incidentId: id, incident: name, severity: sev || "Unrated", regulator: reg, regLabel: R.label, appliesIf: R.appliesIf,
          stage: st.stage, note: st.note || "", refDate, dueDate: new Date(dueMs).toISOString(),
          daysLeft: submitted ? null : Math.round((dueMs - tNow) / DAY),
          status, submittedDate: tracked?.SubmittedDate || null,
        });
      }
    }
  }
  const order = (s: string): number => (s === "overdue" ? 0 : s === "due-soon" ? 1 : s === "pending" ? 2 : 3);
  obligations.sort((a, b) => order(a.status) - order(b.status) || Date.parse(a.dueDate) - Date.parse(b.dueDate));
  const incidentsWithObl = new Set(obligations.map((o) => o.incidentId));
  const summary = {
    incidents: incidentsWithObl.size, obligations: obligations.length,
    overdue: obligations.filter((o) => o.status === "overdue").length,
    dueSoon: obligations.filter((o) => o.status === "due-soon").length,
    submitted: obligations.filter((o) => /submit|done|sent|filed|n.?a/i.test(o.status)).length,
  };
  const byRegulator: Record<string, number> = {};
  for (const o of obligations) byRegulator[o.regulator] = (byRegulator[o.regulator] || 0) + (o.status === "overdue" || o.status === "due-soon" || o.status === "pending" ? 1 : 0);
  return { summary, worklist: obligations.slice(0, 200), byRegulator };
}

/** Mark a reporting obligation submitted / N-A (upsert by incident+regulator+stage). */
export function markRegIncidentReport(tenant: number | null, p: { incidentId: number; regulator: string; stage: string; dueDate?: string; status?: string; submittedDate?: string; reference?: string; notes?: string }): { ok: boolean } {
  ensureRegIncidentTables();
  const db = getDb("XINCIDENT");
  const ex = db.prepare("SELECT ReportID FROM REGINCIDENTREPORT WHERE IncidentID=? AND Regulator=? AND Stage=? AND (TenantID=? OR TenantID IS NULL)").get(p.incidentId, p.regulator, p.stage, tenant) as { ReportID: number } | undefined;
  const vals = [p.dueDate ?? "", p.status ?? "submitted", p.submittedDate ?? now().slice(0, 10), p.reference ?? "", p.notes ?? ""];
  if (ex) db.prepare("UPDATE REGINCIDENTREPORT SET DueDate=?,Status=?,SubmittedDate=?,Reference=?,Notes=? WHERE ReportID=?").run(...vals, ex.ReportID);
  else {
    const id = (db.prepare("SELECT COALESCE(MAX(ReportID),0)+1 n FROM REGINCIDENTREPORT").get() as { n: number }).n;
    db.prepare("INSERT INTO REGINCIDENTREPORT (ReportID,IncidentID,TenantID,Regulator,Stage,DueDate,Status,SubmittedDate,Reference,Notes,CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)").run(id, p.incidentId, tenant, p.regulator, p.stage, ...vals, now());
  }
  return { ok: true };
}
