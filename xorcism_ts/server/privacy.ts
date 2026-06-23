/**
 * privacy.ts — GDPR / Data Privacy Officer (DPO) cockpit (/privacy).
 *
 * Operationalizes the DPO's core GDPR obligations over four registers (XCOMPLIANCE):
 *   - PRIVACYPROCESSING — Records of Processing Activities (RoPA, Art 30): purpose, legal basis,
 *     data categories/subjects, recipients, retention, cross-border transfers, security measures.
 *   - DSAR              — Data Subject Access Requests (Art 12/15-22) with the 1-month response clock.
 *   - DPIA              — Data Protection Impact Assessments (Art 35) for high-risk processing.
 *   - PRIVACYBREACH     — personal-data breach register (Art 33/34) with the 72-hour notification clock.
 *
 * The dashboard scores DPO posture and surfaces the worklist a DPO acts on first (overdue DSARs,
 * processing without a legal basis, high-risk processing missing an approved DPIA, breaches past 72h
 * not yet notified). Read-only aggregation + a couple of create paths; all per-tenant.
 */
import { getDb } from "./db";
import { randomUUID } from "crypto";

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const today = (): string => new Date().toISOString().slice(0, 10);
const CLOSED_RX = /complet|closed|done|resolv|fulfil|ferm|clos[eé]/i;

const LEGAL_BASES = ["Consent", "Contract", "Legal obligation", "Vital interests", "Public task", "Legitimate interests"];
const DSAR_TYPES = ["Access", "Rectification", "Erasure", "Restriction", "Portability", "Objection"];

/** Creates the four privacy registers in XCOMPLIANCE (idempotent). */
export function ensurePrivacyTables(): void {
  const db = getDb("XCOMPLIANCE");
  db.exec(`
    CREATE TABLE IF NOT EXISTS PRIVACYPROCESSING (
      ProcessingID INTEGER PRIMARY KEY, ProcessingGUID TEXT, Name TEXT, Purpose TEXT,
      LegalBasis TEXT, DataCategories TEXT, SpecialCategories INTEGER DEFAULT 0, DataSubjects TEXT,
      Recipients TEXT, RetentionPeriod TEXT, CrossBorderTransfer INTEGER DEFAULT 0, TransferSafeguard TEXT,
      SecurityMeasures TEXT, Controller TEXT, ProcessorName TEXT, RiskLevel TEXT, Status TEXT,
      OwnerPersonID INTEGER, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS DSAR (
      RequestID INTEGER PRIMARY KEY, RequestGUID TEXT, SubjectName TEXT, SubjectEmail TEXT,
      RequestType TEXT, ReceivedDate TEXT, DueDate TEXT, Status TEXT, Channel TEXT,
      AssignedTo TEXT, Notes TEXT, CompletedDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS DPIA (
      DpiaID INTEGER PRIMARY KEY, DpiaGUID TEXT, Name TEXT, ProcessingID INTEGER, RiskLevel TEXT,
      NecessityAssessment TEXT, Risks TEXT, Mitigations TEXT, ResidualRisk TEXT, Status TEXT,
      ConsultedDPO INTEGER DEFAULT 0, ReviewDate TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE TABLE IF NOT EXISTS PRIVACYBREACH (
      BreachID INTEGER PRIMARY KEY, BreachGUID TEXT, Title TEXT, Description TEXT, DetectedDate TEXT,
      ContainedDate TEXT, AffectedSubjects INTEGER, DataCategories TEXT, Severity TEXT, RiskToSubjects TEXT,
      NotifiedAuthority INTEGER DEFAULT 0, AuthorityNotifiedDate TEXT, NotifiedSubjects INTEGER DEFAULT 0,
      SubjectsNotifiedDate TEXT, Status TEXT, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_dsar_tenant ON DSAR(TenantID);
    CREATE INDEX IF NOT EXISTS ix_privproc_tenant ON PRIVACYPROCESSING(TenantID);
  `);
}

function nextId(table: string, pk: string): number {
  return (getDb("XCOMPLIANCE").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${table}`).get() as { n: number }).n;
}
const tw = (tenant: number | null): string => (tenant != null ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "");
const daysBetween = (a: string, b: string): number | null => {
  const ta = Date.parse(a), tb = Date.parse(b); if (!Number.isFinite(ta) || !Number.isFinite(tb)) return null;
  return Math.round((tb - ta) / 86400000);
};

export interface PrivacyWorkItem { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; ref: string }

/** The DPO dashboard: RoPA + DSAR + DPIA + breach posture, plus the prioritized worklist. */
export function privacyDashboard(tenant: number | null): any {
  ensurePrivacyTables();
  const db = getDb("XCOMPLIANCE");
  const t = today();
  const worklist: PrivacyWorkItem[] = [];

  // — RoPA —
  const proc = db.prepare(`SELECT ProcessingID, Name, Purpose, LegalBasis, SpecialCategories, CrossBorderTransfer, TransferSafeguard, RiskLevel, Status FROM PRIVACYPROCESSING ${tw(tenant)} ORDER BY Name`).all() as any[];
  const dpias = db.prepare(`SELECT DpiaID, Name, ProcessingID, RiskLevel, Status, ConsultedDPO FROM DPIA ${tw(tenant)}`).all() as any[];
  const dpiaByProc = new Map<number, any>(); for (const d of dpias) if (d.ProcessingID != null) dpiaByProc.set(num(d.ProcessingID), d);
  const procRows = proc.map((p) => {
    const legal = String(p.LegalBasis ?? "").trim();
    const high = /high|élev/i.test(String(p.RiskLevel ?? "")) || num(p.SpecialCategories) === 1;
    const dpia = dpiaByProc.get(num(p.ProcessingID));
    const dpiaApproved = dpia && /approv/i.test(String(dpia.Status ?? ""));
    if (!legal) worklist.push({ kind: "no-legal-basis", label: `Processing "${p.Name}" has no documented legal basis (GDPR Art 6)`, severity: "High", ref: `ProcessingID ${p.ProcessingID}` });
    if (high && !dpiaApproved) worklist.push({ kind: "missing-dpia", label: `High-risk processing "${p.Name}" lacks an approved DPIA (Art 35)`, severity: "High", ref: `ProcessingID ${p.ProcessingID}` });
    if (num(p.CrossBorderTransfer) === 1 && !String(p.TransferSafeguard ?? "").trim()) worklist.push({ kind: "transfer", label: `Cross-border transfer for "${p.Name}" has no documented safeguard (Ch. V)`, severity: "Medium", ref: `ProcessingID ${p.ProcessingID}` });
    return { id: num(p.ProcessingID), name: String(p.Name ?? ""), purpose: String(p.Purpose ?? ""), legalBasis: legal, special: num(p.SpecialCategories) === 1, crossBorder: num(p.CrossBorderTransfer) === 1, riskLevel: String(p.RiskLevel ?? ""), hasDpia: !!dpia, dpiaApproved: !!dpiaApproved, status: String(p.Status ?? "") };
  });

  // — DSAR (1-month clock) —
  const dsarRaw = db.prepare(`SELECT RequestID, SubjectName, RequestType, ReceivedDate, DueDate, Status, AssignedTo, CompletedDate FROM DSAR ${tw(tenant)} ORDER BY DueDate`).all() as any[];
  const dsars = dsarRaw.map((d) => {
    const closed = CLOSED_RX.test(String(d.Status ?? "")) || !!d.CompletedDate;
    const due = String(d.DueDate ?? "").slice(0, 10);
    const daysLeft = due ? daysBetween(t, due) : null;
    const overdue = !closed && due && due < t;
    if (overdue) worklist.push({ kind: "dsar-overdue", label: `${String(d.RequestType ?? "Request")} request from ${d.SubjectName || "a data subject"} is OVERDUE (due ${due})`, severity: "Critical", ref: `RequestID ${d.RequestID}` });
    else if (!closed && daysLeft != null && daysLeft <= 7) worklist.push({ kind: "dsar-due", label: `${String(d.RequestType ?? "Request")} request from ${d.SubjectName || "a data subject"} due in ${daysLeft}d`, severity: "Medium", ref: `RequestID ${d.RequestID}` });
    return { id: num(d.RequestID), subject: String(d.SubjectName ?? ""), type: String(d.RequestType ?? ""), received: String(d.ReceivedDate ?? "").slice(0, 10), due, status: String(d.Status ?? ""), assignedTo: String(d.AssignedTo ?? ""), closed, overdue: !!overdue, daysLeft };
  });

  // — Breaches (72-hour clock, Art 33) —
  const breachRaw = db.prepare(`SELECT BreachID, Title, DetectedDate, AffectedSubjects, Severity, RiskToSubjects, NotifiedAuthority, AuthorityNotifiedDate, NotifiedSubjects, Status FROM PRIVACYBREACH ${tw(tenant)} ORDER BY DetectedDate DESC`).all() as any[];
  const breaches = breachRaw.map((b) => {
    const detected = String(b.DetectedDate ?? "").slice(0, 10);
    const notified = num(b.NotifiedAuthority) === 1;
    const hoursSince = b.DetectedDate ? (Date.now() - Date.parse(String(b.DetectedDate))) / 3600000 : null;
    const open = !CLOSED_RX.test(String(b.Status ?? ""));
    const highRisk = /high|élev/i.test(String(b.RiskToSubjects ?? "")) || /high|crit/i.test(String(b.Severity ?? ""));
    const breach72 = open && !notified && hoursSince != null && hoursSince > 72;
    if (breach72) worklist.push({ kind: "breach-72h", label: `Breach "${b.Title}" past the 72-hour clock and NOT notified to the supervisory authority (Art 33)`, severity: "Critical", ref: `BreachID ${b.BreachID}` });
    else if (open && !notified && highRisk) worklist.push({ kind: "breach-notify", label: `High-risk breach "${b.Title}" — assess authority + data-subject notification (Art 33/34)`, severity: "High", ref: `BreachID ${b.BreachID}` });
    return { id: num(b.BreachID), title: String(b.Title ?? ""), detected, affected: num(b.AffectedSubjects), severity: String(b.Severity ?? ""), riskToSubjects: String(b.RiskToSubjects ?? ""), notifiedAuthority: notified, notifiedSubjects: num(b.NotifiedSubjects) === 1, status: String(b.Status ?? ""), hoursSinceDetected: hoursSince != null ? Math.round(hoursSince) : null, breached72: !!breach72 };
  });

  // — Posture score (0–100, higher = better) —
  const dsarOverdue = dsars.filter((d) => d.overdue).length;
  const procNoBasis = procRows.filter((p) => !p.legalBasis).length;
  const dpiaGaps = procRows.filter((p) => (/high/i.test(p.riskLevel) || p.special) && !p.dpiaApproved).length;
  const breach72 = breaches.filter((b) => b.breached72).length;
  let score = 100;
  score -= dsarOverdue * 12 + procNoBasis * 8 + dpiaGaps * 6 + breach72 * 20;
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  worklist.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  return {
    summary: {
      processing: procRows.length, processingNoBasis: procNoBasis,
      dsarTotal: dsars.length, dsarOpen: dsars.filter((d) => !d.closed).length, dsarOverdue,
      dpiaTotal: dpias.length, dpiaApproved: dpias.filter((d) => /approv/i.test(d.Status ?? "")).length, dpiaGaps,
      breaches: breaches.length, breachesUnnotified: breaches.filter((b) => !b.notifiedAuthority && !CLOSED_RX.test(b.status)).length, breach72,
      score, grade,
    },
    processing: procRows, dsars, dpias: dpias.map((d) => ({ id: num(d.DpiaID), name: String(d.Name ?? ""), processingId: d.ProcessingID != null ? num(d.ProcessingID) : null, riskLevel: String(d.RiskLevel ?? ""), status: String(d.Status ?? ""), consultedDpo: num(d.ConsultedDPO) === 1 })),
    breaches,
    worklist: worklist.slice(0, 40),
    legalBases: LEGAL_BASES, dsarTypes: DSAR_TYPES,
  };
}

export function createProcessing(p: { name: string; purpose?: string; legalBasis?: string; dataCategories?: string; specialCategories?: boolean; dataSubjects?: string; recipients?: string; retention?: string; crossBorder?: boolean; transferSafeguard?: string; riskLevel?: string; controller?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYPROCESSING", "ProcessingID");
  db.prepare(`INSERT INTO PRIVACYPROCESSING (ProcessingID, ProcessingGUID, Name, Purpose, LegalBasis, DataCategories, SpecialCategories, DataSubjects, Recipients, RetentionPeriod, CrossBorderTransfer, TransferSafeguard, RiskLevel, Controller, Status, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.name.trim(), (p.purpose || "").trim(), (p.legalBasis || "").trim(), (p.dataCategories || "").trim(), p.specialCategories ? 1 : 0, (p.dataSubjects || "").trim(), (p.recipients || "").trim(), (p.retention || "").trim(), p.crossBorder ? 1 : 0, (p.transferSafeguard || "").trim(), (p.riskLevel || "Medium").trim(), (p.controller || "").trim(), "Active", new Date().toISOString(), tenant);
  return { id };
}

export function createDsar(p: { subjectName: string; subjectEmail?: string; requestType?: string; receivedDate?: string; channel?: string; assignedTo?: string; notes?: string }, tenant: number | null): { id: number; dueDate: string } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("DSAR", "RequestID");
  const received = (p.receivedDate || today()).slice(0, 10);
  const due = new Date(Date.parse(received) + 30 * 86400000).toISOString().slice(0, 10); // GDPR: 1 month
  db.prepare(`INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, SubjectEmail, RequestType, ReceivedDate, DueDate, Status, Channel, AssignedTo, Notes, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.subjectName.trim(), (p.subjectEmail || "").trim(), (p.requestType || "Access").trim(), received, due, "New", (p.channel || "").trim(), (p.assignedTo || "").trim(), (p.notes || "").trim(), new Date().toISOString(), tenant);
  return { id, dueDate: due };
}

export function updateDsarStatus(id: number, status: string, tenant: number | null): boolean {
  const db = getDb("XCOMPLIANCE");
  const row = db.prepare("SELECT TenantID FROM DSAR WHERE RequestID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!row || (tenant != null && row.TenantID != null && num(row.TenantID) !== tenant)) return false;
  const completed = CLOSED_RX.test(status) ? today() : null;
  db.prepare("UPDATE DSAR SET Status = ?, CompletedDate = ? WHERE RequestID = ?").run(status, completed, id);
  return true;
}

export function recordBreach(p: { title: string; description?: string; detectedDate?: string; affectedSubjects?: number; dataCategories?: string; severity?: string; riskToSubjects?: string }, tenant: number | null): { id: number } {
  const db = getDb("XCOMPLIANCE"); const id = nextId("PRIVACYBREACH", "BreachID");
  db.prepare(`INSERT INTO PRIVACYBREACH (BreachID, BreachGUID, Title, Description, DetectedDate, AffectedSubjects, DataCategories, Severity, RiskToSubjects, NotifiedAuthority, NotifiedSubjects, Status, CreatedDate, TenantID)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, randomUUID(), p.title.trim(), (p.description || "").trim(), (p.detectedDate || new Date().toISOString()), num(p.affectedSubjects), (p.dataCategories || "").trim(), (p.severity || "Medium").trim(), (p.riskToSubjects || "").trim(), 0, 0, "Open", new Date().toISOString(), tenant);
  return { id };
}

/** Demo seed (tenant only) — a realistic RoPA + DSARs + a DPIA + a breach for the DPO cockpit. */
export function seedPrivacy(tenant: number): { processing: number; dsar: number; dpia: number; breach: number } {
  ensurePrivacyTables();
  const db = getDb("XCOMPLIANCE");
  const existing = num((db.prepare("SELECT COUNT(*) n FROM PRIVACYPROCESSING WHERE TenantID = ?").get(tenant) as { n: number }).n);
  if (existing) return { processing: 0, dsar: 0, dpia: 0, breach: 0 };
  const p1 = createProcessing({ name: "Customer CRM", purpose: "Manage customer relationships and orders", legalBasis: "Contract", dataCategories: "Name, email, phone, order history", dataSubjects: "Customers", recipients: "Sales, CRM SaaS processor", retention: "Account life + 3 years", riskLevel: "Medium", controller: "Acme Corp" }, tenant).id;
  const p2 = createProcessing({ name: "HR & payroll", purpose: "Employee administration and payroll", legalBasis: "Legal obligation", dataCategories: "Identity, bank details, health (sick leave)", specialCategories: true, dataSubjects: "Employees", retention: "Employment + 5 years", riskLevel: "High", controller: "Acme Corp" }, tenant).id;
  createProcessing({ name: "Website analytics", purpose: "Audience measurement", dataCategories: "IP, device, behavior", dataSubjects: "Website visitors", crossBorder: true, riskLevel: "Medium" }, tenant); // no legal basis + transfer → worklist
  // DSARs — one overdue, one due soon, one completed
  const back = (d: number): string => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
  db.prepare("INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, RequestType, ReceivedDate, DueDate, Status, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(nextId("DSAR", "RequestID"), randomUUID(), "Jane Doe", "Erasure", back(40), back(10), "InProgress", new Date().toISOString(), tenant); // overdue
  createDsar({ subjectName: "John Smith", requestType: "Access", receivedDate: back(25) }, tenant); // due in ~5d
  db.prepare("INSERT INTO DSAR (RequestID, RequestGUID, SubjectName, RequestType, ReceivedDate, DueDate, Status, CompletedDate, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(nextId("DSAR", "RequestID"), randomUUID(), "Marie Curie", "Portability", back(50), back(20), "Completed", back(22), new Date().toISOString(), tenant);
  // DPIA for the high-risk HR processing (draft → triggers no gap once approved; leave Draft to show the gap closing path)
  db.prepare("INSERT INTO DPIA (DpiaID, DpiaGUID, Name, ProcessingID, RiskLevel, Status, ConsultedDPO, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(nextId("DPIA", "DpiaID"), randomUUID(), "DPIA — HR & payroll (special category data)", p2, "High", "Approved", 1, new Date().toISOString(), tenant);
  // a breach within the 72h window (not yet past)
  recordBreach({ title: "Misdirected email with customer list", description: "An export was emailed to the wrong recipient.", detectedDate: new Date(Date.now() - 20 * 3600000).toISOString(), affectedSubjects: 240, dataCategories: "Name, email", severity: "Medium", riskToSubjects: "Low" }, tenant);
  void p1;
  return { processing: 3, dsar: 3, dpia: 1, breach: 1 };
}
