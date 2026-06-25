/**
 * riskregister.ts — Risk Register inventory + governance worklist.
 *
 * The risk-management counterpart of assets.ts / compliance.ts: one pane over the risk register
 * (XCOMPLIANCE.RISKREGISTERENTRY) — each risk's inherent → current → residual level, treatment
 * strategy/owner/review, and its CRQ/FAIR quantification (Annualized Loss Expectancy). The
 * worklist surfaces what matters: high/critical residual risks left untreated, risks accepted
 * without justification, overdue reviews, treatments past their target date and unowned risks.
 * Each risk gets a 0-100 priority score. Read-only; CRUD stays in the schema-driven explorer.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

export interface RiskRow {
  id: number;
  ref: string;
  title: string;
  category: string;
  owner: string | null;
  asset: string | null;
  status: string;
  open: boolean;
  inherent: string;
  current: string;
  residual: string;
  residualRank: number;       // 0 critical … 4 very-low, 5 unrated
  treatment: string;
  hasPlan: boolean;
  ale: number | null;
  sle: number | null;
  currency: string;
  reviewInDays: number | null;
  reviewOverdue: boolean;
  score: number;              // 0-100 priority (higher = worse)
  overAppetite: boolean;      // residual exceeds the category's risk appetite/tolerance
  measures: number;           // count of linked measures from the library
}
export interface RiskFinding {
  id: number; ref: string; title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  reason: string; kind: "untreated" | "accepted" | "review" | "target" | "owner" | "appetite";
  label: string;
}
export interface RiskInventory {
  rows: RiskRow[];
  findings: RiskFinding[];
  summary: {
    risks: number; open: number; closed: number; treatedRate: number | null;
    highCritical: number; untreated: number; accepted: number; overdueReview: number; noOwner: number;
    overAppetite: number;
    quantified: number; totalALE: number; currency: string;
    byLevel: Record<string, number>; byStatus: Record<string, number>; byTreatment: Record<string, number>; byCategory: Record<string, number>;
    riskScore: number;        // headline: threat-weighted residual posture (0-100, higher = worse)
  };
}

const EMPTY: RiskInventory = {
  rows: [], findings: [],
  summary: { risks: 0, open: 0, closed: 0, treatedRate: null, highCritical: 0, untreated: 0, accepted: 0, overdueReview: 0, noOwner: 0, overAppetite: 0, quantified: 0, totalALE: 0, currency: "EUR", byLevel: {}, byStatus: {}, byTreatment: {}, byCategory: {}, riskScore: 0 },
};

const CLOSED = /closed|clos[eé]|retir|done|accepted-closed|mitigated|termin[eé]|ferm[eé]/i;
const ACCEPT = /accept/i;
const LEVEL_RANK: Record<string, number> = { critical: 0, "very high": 0, severe: 0, high: 1, élevé: 1, medium: 2, moderate: 2, moyen: 2, low: 3, faible: 3, "very low": 4, "très faible": 4, minimal: 4, info: 4, informational: 4, négligeable: 4 };
const RANK_LABEL = ["Critical", "High", "Medium", "Low", "Very Low", "—"];

function cols(table: string): Set<string> {
  try { return new Set((getDb("XCOMPLIANCE").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date)); return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
const cap = (s: string): string => s.replace(/\b\w/g, (c) => c.toUpperCase());

/** Resolve a risk level to {label, rank} from a text level, else from probability × impact.
 *  rank: 0 critical … 4 very-low, 5 unrated. Shared with the enterprise risk-score formula. */
export function levelInfo(text: unknown, prob: unknown, impact: unknown): { label: string; rank: number } {
  const t = String(text ?? "").toLowerCase().trim();
  if (t && LEVEL_RANK[t] != null) return { label: cap(t), rank: LEVEL_RANK[t] };
  const fromScore = (s: number): { label: string; rank: number } => {
    if (s <= 5) { const r = [5, 4, 3, 2, 1, 0][Math.max(0, Math.min(5, Math.round(s)))]; return { label: RANK_LABEL[r], rank: r }; } // 1-5 single scale
    const r = s >= 20 ? 0 : s >= 12 ? 1 : s >= 6 ? 2 : s >= 3 ? 3 : 4;                                                              // 5×5 product
    return { label: RANK_LABEL[r], rank: r };
  };
  const n = Number(t);
  if (Number.isFinite(n) && n > 0) return fromScore(n);
  const p = Number(prob), i = Number(impact);
  if (Number.isFinite(p) && p > 0 && Number.isFinite(i) && i > 0) return fromScore(p * i);
  return { label: "—", rank: 5 };
}

/** Full risk-register inventory + treatment worklist. */
export function riskRegisterInventory(tenant: number | null): RiskInventory {
  const cc = getDb("XCOMPLIANCE");
  if (!cc.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='RISKREGISTERENTRY'").get()) return { ...EMPTY };
  const rc = cols("RISKREGISTERENTRY");
  const tw = tenant != null && rc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const entries = cc.prepare(`SELECT * FROM RISKREGISTERENTRY ${tw}`).all() as Record<string, unknown>[];
  if (!entries.length) return { ...EMPTY };

  // resolve owners (PERSON) + assets (ASSET), cross-DB best-effort
  const ownerName = new Map<number, string>();
  const assetName = new Map<number, string>();
  try {
    const xo = getDb("XORCISM");
    const oids = [...new Set(entries.map((e) => Number(e.RiskOwnerPersonID)).filter(Boolean))];
    if (oids.length) for (const r of xo.prepare(`SELECT PersonID, FullName FROM PERSON WHERE PersonID IN (${oids.map(() => "?").join(",")})`).all(...oids) as { PersonID: number; FullName: string }[]) ownerName.set(Number(r.PersonID), r.FullName);
    const aids = [...new Set(entries.map((e) => Number(e.AssetID)).filter(Boolean))];
    if (aids.length) for (const r of xo.prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${aids.map(() => "?").join(",")})`).all(...aids) as { AssetID: number; AssetName: string }[]) assetName.set(Number(r.AssetID), r.AssetName);
  } catch { /* PERSON/ASSET absent */ }

  // risk appetite per category (toleranceRank = worst residual rank still acceptable; 0 critical … 4 very-low)
  // and the count of library measures linked to each entry — both best-effort (tables may be absent).
  const appetite = new Map<string, number>();
  const measuresByEntry = new Map<number, number>();
  try {
    ensureRiskGovTables();
    const aw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
    for (const a of cc.prepare(`SELECT Category, ToleranceRank FROM RISKAPPETITE ${aw}`).all() as { Category: string; ToleranceRank: number }[])
      if (a.Category != null && a.ToleranceRank != null) appetite.set(String(a.Category).toLowerCase().trim(), Number(a.ToleranceRank));
    const lw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
    for (const m of cc.prepare(`SELECT RiskRegisterEntryID AS id, COUNT(*) AS n FROM RISKMEASURELINK ${lw} GROUP BY RiskRegisterEntryID`).all() as { id: number; n: number }[])
      measuresByEntry.set(Number(m.id), Number(m.n));
  } catch { /* governance tables not ready */ }

  const today = new Date().toISOString().slice(0, 10);
  const rows: RiskRow[] = [];
  const findings: RiskFinding[] = [];

  for (const e of entries) {
    const id = Number(e.RiskRegisterEntryID);
    const status = String(e.Status ?? "").trim() || "Open";
    const open = !CLOSED.test(status) && !e.ClosedDate;
    const inh = levelInfo(e.InherentRiskLevel, e.InherentProbability, e.InherentImpact);
    const cur = levelInfo(e.CurrentRiskLevel, e.CurrentProbability, e.CurrentImpact);
    // residual falls back to current, then inherent, if not rated
    let res = levelInfo(e.ResidualRiskLevel, e.ResidualProbability, e.ResidualImpact);
    if (res.rank === 5) res = cur.rank !== 5 ? cur : inh;
    const treatment = String(e.TreatmentStrategy ?? "").trim() || "—";
    const hasPlan = !!String(e.TreatmentPlan ?? "").trim();
    const owner = e.RiskOwnerPersonID != null ? (ownerName.get(Number(e.RiskOwnerPersonID)) ?? `Person #${e.RiskOwnerPersonID}`) : null;
    const asset = e.AssetID != null ? (assetName.get(Number(e.AssetID)) ?? null) : null;
    const ale = e.AnnualizedLossExpectancy != null && e.AnnualizedLossExpectancy !== "" ? Number(e.AnnualizedLossExpectancy) : null;
    const sle = e.SingleLossExpectancy != null && e.SingleLossExpectancy !== "" ? Number(e.SingleLossExpectancy) : null;
    const reviewInDays = daysUntil(e.ReviewDate ? String(e.ReviewDate) : null);
    const reviewOverdue = open && reviewInDays != null && reviewInDays < 0 && String(e.ReviewDate).slice(0, 10) < today;
    const targetOverdue = open && e.TargetDate != null && String(e.TargetDate).slice(0, 10) < today;

    // priority score (higher = worse): residual severity + ALE + risk-management gaps
    let score = (5 - res.rank) * 10;                                  // critical 50 … very-low 10 … unrated 0
    if (ale != null && Number.isFinite(ale)) score += Math.min(20, ale / 100_000);
    if (reviewOverdue) score += 10;
    if (open && res.rank <= 1 && !hasPlan && !ACCEPT.test(treatment)) score += 15;
    if (open && !owner) score += 5;
    // over appetite: residual is MORE severe (lower rank) than the category's tolerance allows
    const tol = appetite.get(String(e.Category ?? "").toLowerCase().trim());
    const overAppetite = open && tol != null && res.rank <= 4 && res.rank < tol;
    if (overAppetite) score += 12;
    if (!open) score = Math.round(score * 0.3);                        // closed risks de-prioritised
    score = Math.max(0, Math.min(100, Math.round(score)));

    rows.push({
      id, ref: String(e.Ref ?? "").trim() || `R-${id}`, title: String(e.Title ?? "").trim() || `Risk #${id}`,
      category: String(e.Category ?? "").trim() || "—", owner, asset, status, open,
      inherent: inh.label, current: cur.label, residual: res.label, residualRank: res.rank,
      treatment, hasPlan, ale, sle, currency: String(e.Currency ?? "EUR"),
      reviewInDays, reviewOverdue, score,
      overAppetite, measures: measuresByEntry.get(id) ?? 0,
    });

    if (overAppetite)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank === 0 ? "Critical" : "High", reason: "over-appetite", kind: "appetite", label: `Residual ${res.label} exceeds the risk appetite for "${String(e.Category ?? "—")}"` });

    // worklist
    if (open && res.rank <= 1 && !hasPlan && !ACCEPT.test(treatment))
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank === 0 ? "Critical" : "High", reason: "untreated", kind: "untreated", label: `${res.label} residual risk with no treatment plan` });
    if (open && ACCEPT.test(treatment) && !String(e.Justification ?? "").trim())
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: res.rank <= 1 ? "High" : "Medium", reason: "accepted-no-justification", kind: "accepted", label: `Risk accepted without documented justification (${res.label})` });
    if (reviewOverdue)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Medium", reason: "overdue-review", kind: "review", label: `Review overdue by ${-(reviewInDays ?? 0)}d` });
    if (targetOverdue && hasPlan)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Medium", reason: "treatment-overdue", kind: "target", label: `Treatment past its target date, risk still open` });
    if (open && !owner)
      findings.push({ id, ref: String(e.Ref ?? `R-${id}`), title: String(e.Title ?? ""), severity: "Low", reason: "no-owner", kind: "owner", label: `No risk owner assigned` });
  }

  const SEV: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  rows.sort((a, b) => b.score - a.score || a.residualRank - b.residualRank || a.ref.localeCompare(b.ref));
  findings.sort((a, b) => SEV[a.severity] - SEV[b.severity] || a.ref.localeCompare(b.ref));

  const openRows = rows.filter((r) => r.open);
  const byLevel: Record<string, number> = {}, byStatus: Record<string, number> = {}, byTreatment: Record<string, number> = {}, byCategory: Record<string, number> = {};
  for (const r of rows) {
    if (r.open) byLevel[r.residual] = (byLevel[r.residual] || 0) + 1;
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    if (r.treatment !== "—") byTreatment[r.treatment] = (byTreatment[r.treatment] || 0) + 1;
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  }
  const treated = openRows.filter((r) => r.hasPlan || ACCEPT.test(r.treatment)).length;
  // headline residual posture: weight open risks by severity (critical 100 … very-low 20), averaged
  const wScore = openRows.length ? Math.round(openRows.reduce((s, r) => s + (r.residualRank <= 4 ? (5 - r.residualRank) * 20 : 0), 0) / openRows.length) : 0;

  return {
    rows, findings,
    summary: {
      risks: rows.length, open: openRows.length, closed: rows.length - openRows.length,
      treatedRate: openRows.length ? Math.round((treated / openRows.length) * 100) : null,
      highCritical: openRows.filter((r) => r.residualRank <= 1).length,
      untreated: findings.filter((f) => f.kind === "untreated").length,
      accepted: findings.filter((f) => f.kind === "accepted").length,
      overdueReview: findings.filter((f) => f.kind === "review").length,
      noOwner: findings.filter((f) => f.kind === "owner").length,
      overAppetite: rows.filter((r) => r.overAppetite).length,
      quantified: rows.filter((r) => r.ale != null).length,
      totalALE: Math.round(openRows.reduce((s, r) => s + (r.ale ?? 0), 0)),
      currency: rows[0]?.currency ?? "EUR",
      byLevel, byStatus, byTreatment, byCategory,
      riskScore: wScore,
    },
  };
}

/**
 * Create a RISKREGISTERENTRY from a guided form — the friendly path that replaces dumping the
 * user into the raw explorer insert. Captures the essentials (title, category, owner, asset,
 * inherent likelihood × impact, treatment, status, dates), computes InherentRiskLevel = P×I so
 * the posture rolls up immediately (residual falls back to inherent until assessed). Column-aware
 * INSERT + GUID + tenant. RiskRegisterEntryID is a real INTEGER PRIMARY KEY (lastInsertRowid).
 */
export function createRiskRegisterEntry(
  p: { title: string; description?: string; category?: string; ref?: string;
       ownerPersonId?: number | null; assetId?: number | null; probability?: number | null;
       impact?: number | null; treatment?: string; status?: string; reviewDate?: string; targetDate?: string },
  tenant: number | null,
): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  const rc = cols("RISKREGISTERENTRY");
  if (!rc.size) throw new Error("RISKREGISTERENTRY table not available");
  const clamp = (v: unknown): number | null => {
    const n = Math.round(Number(v));
    return Number.isFinite(n) && n >= 1 && n <= 5 ? n : null;
  };
  const prob = clamp(p.probability), impact = clamp(p.impact);
  const now = new Date().toISOString();
  const candidate: Record<string, unknown> = {
    RiskRegisterEntryGUID: randomUUID(),
    Ref: p.ref ? String(p.ref).slice(0, 60) : null,
    Title: (p.title || "Untitled risk").slice(0, 300),
    Description: p.description ? String(p.description).slice(0, 4000) : null,
    Category: p.category ? String(p.category).slice(0, 120) : null,
    RiskOwnerPersonID: p.ownerPersonId ?? null,
    AssetID: p.assetId ?? null,
    InherentProbability: prob, InherentImpact: impact,
    InherentRiskLevel: prob != null && impact != null ? prob * impact : null,
    TreatmentStrategy: p.treatment ? String(p.treatment).slice(0, 60) : null,
    Status: (p.status || "Open").slice(0, 60),
    IdentifiedDate: now.slice(0, 10),
    ReviewDate: p.reviewDate || null,
    TargetDate: p.targetDate || null,
    CreatedDate: now,
    TenantID: tenant,
  };
  const keys = Object.keys(candidate).filter((k) => rc.has(k));
  const sql = `INSERT INTO RISKREGISTERENTRY (${keys.map((k) => `"${k}"`).join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`;
  const r = cc.prepare(sql).run(...keys.map((k) => candidate[k]));
  return { id: Number(r.lastInsertRowid) };
}

// ════════════════════════════════════════════════════════════════════════════════
//  Risk-management strategy & appetite (RISKSTRATEGY / RISKAPPETITE) + a reusable
//  library of risk measures (RISKMEASURE) linkable to register entries (RISKMEASURELINK).
// ════════════════════════════════════════════════════════════════════════════════
export const APPETITE_LEVELS = ["Averse", "Minimal", "Cautious", "Open", "Flexible"] as const;
export const MEASURE_TYPES = ["Preventive", "Detective", "Corrective", "Directive", "Compensating"] as const;
export const MEASURE_STATUSES = ["Proposed", "Approved", "Implemented", "Verified", "Retired"] as const;
export const LINK_STATUSES = ["Planned", "In progress", "Implemented", "Verified"] as const;
/** Tolerance ranks the worklist compares against (0 critical … 4 very-low). */
export const TOLERANCE_RANKS = [
  { rank: 0, label: "Critical" }, { rank: 1, label: "High" }, { rank: 2, label: "Medium" }, { rank: 3, label: "Low" }, { rank: 4, label: "Very Low" },
];

export function ensureRiskGovTables(): void {
  getDb("XCOMPLIANCE").exec(`
    CREATE TABLE IF NOT EXISTS RISKSTRATEGY(
      RiskStrategyID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER,
      Statement TEXT, Objectives TEXT, Methodology TEXT, RiskScale TEXT,
      ReviewCadenceMonths INTEGER, Owner TEXT, ApprovedBy TEXT, ApprovedDate TEXT, UpdatedDate TEXT);
    CREATE TABLE IF NOT EXISTS RISKAPPETITE(
      RiskAppetiteID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, Category TEXT, AppetiteLevel TEXT, ToleranceRank INTEGER, Rationale TEXT);
    CREATE TABLE IF NOT EXISTS RISKMEASURE(
      RiskMeasureID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, Ref TEXT, Name TEXT NOT NULL, Description TEXT,
      MeasureType TEXT, Category TEXT, ControlRef TEXT, Effectiveness TEXT, Cost TEXT,
      Status TEXT, CreatedDate TEXT);
    CREATE TABLE IF NOT EXISTS RISKMEASURELINK(
      LinkID INTEGER PRIMARY KEY AUTOINCREMENT,
      TenantID INTEGER, RiskRegisterEntryID INTEGER, RiskMeasureID INTEGER,
      ImplementationStatus TEXT, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_riskappetite_tn ON RISKAPPETITE(TenantID, Category);
    CREATE INDEX IF NOT EXISTS ix_riskmeasure_tn ON RISKMEASURE(TenantID, RiskMeasureID);
    CREATE INDEX IF NOT EXISTS ix_riskmeasurelink_entry ON RISKMEASURELINK(RiskRegisterEntryID);
  `);
}

const tw = (tenant: number | null): string => (tenant != null ? `WHERE TenantID = ${tenant}` : "");

/** The strategy + appetite + measures-library payload for the /risk-register page. */
export function getRiskGovernance(tenant: number | null): {
  strategy: Record<string, unknown> | null;
  appetite: Record<string, unknown>[];
  measures: Record<string, unknown>[];
  options: { appetiteLevels: readonly string[]; measureTypes: readonly string[]; measureStatuses: readonly string[]; linkStatuses: readonly string[]; toleranceRanks: { rank: number; label: string }[] };
} {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const strategy = (cc.prepare(`SELECT * FROM RISKSTRATEGY ${tw(tenant)} ORDER BY RiskStrategyID DESC LIMIT 1`).get() as Record<string, unknown>) ?? null;
  const appetite = cc.prepare(`SELECT * FROM RISKAPPETITE ${tw(tenant)} ORDER BY Category`).all() as Record<string, unknown>[];
  // measures with a usage count (how many register entries reference each)
  const measures = cc.prepare(`
    SELECT m.*, (SELECT COUNT(*) FROM RISKMEASURELINK l WHERE l.RiskMeasureID = m.RiskMeasureID) AS usage
    FROM RISKMEASURE m ${tw(tenant)} ORDER BY m.Status, m.Name`).all() as Record<string, unknown>[];
  return { strategy, appetite, measures, options: {
    appetiteLevels: APPETITE_LEVELS, measureTypes: MEASURE_TYPES, measureStatuses: MEASURE_STATUSES, linkStatuses: LINK_STATUSES, toleranceRanks: TOLERANCE_RANKS,
  } };
}

/** Upsert the (single) risk-management strategy for the tenant and replace its appetite rows. */
export function saveRiskStrategy(
  tenant: number | null,
  p: { statement?: string; objectives?: string; methodology?: string; riskScale?: string; reviewCadenceMonths?: number | null;
       owner?: string; approvedBy?: string; approvedDate?: string;
       appetite?: { category: string; appetiteLevel?: string; toleranceRank?: number | null; rationale?: string }[] },
): { ok: true } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const now = new Date().toISOString();
  const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
  const existing = cc.prepare(`SELECT RiskStrategyID FROM RISKSTRATEGY ${tw(tenant)} ORDER BY RiskStrategyID DESC LIMIT 1`).get() as { RiskStrategyID: number } | undefined;
  const fields = {
    Statement: s(p.statement), Objectives: s(p.objectives), Methodology: s(p.methodology, 200), RiskScale: s(p.riskScale, 60),
    ReviewCadenceMonths: p.reviewCadenceMonths != null && String(p.reviewCadenceMonths) !== "" ? Math.max(1, Math.min(120, Math.round(Number(p.reviewCadenceMonths)))) : null,
    Owner: s(p.owner, 200), ApprovedBy: s(p.approvedBy, 200), ApprovedDate: s(p.approvedDate, 30), UpdatedDate: now,
  };
  if (existing) {
    cc.prepare(`UPDATE RISKSTRATEGY SET Statement=@Statement, Objectives=@Objectives, Methodology=@Methodology, RiskScale=@RiskScale,
      ReviewCadenceMonths=@ReviewCadenceMonths, Owner=@Owner, ApprovedBy=@ApprovedBy, ApprovedDate=@ApprovedDate, UpdatedDate=@UpdatedDate
      WHERE RiskStrategyID=@id`).run({ ...fields, id: existing.RiskStrategyID });
  } else {
    cc.prepare(`INSERT INTO RISKSTRATEGY (TenantID, Statement, Objectives, Methodology, RiskScale, ReviewCadenceMonths, Owner, ApprovedBy, ApprovedDate, UpdatedDate)
      VALUES (@TenantID,@Statement,@Objectives,@Methodology,@RiskScale,@ReviewCadenceMonths,@Owner,@ApprovedBy,@ApprovedDate,@UpdatedDate)`).run({ ...fields, TenantID: tenant });
  }
  if (Array.isArray(p.appetite)) {
    cc.prepare(`DELETE FROM RISKAPPETITE ${tw(tenant)}`).run();
    const ins = cc.prepare(`INSERT INTO RISKAPPETITE (TenantID, Category, AppetiteLevel, ToleranceRank, Rationale) VALUES (?, ?, ?, ?, ?)`);
    for (const a of p.appetite) {
      const cat = s(a.category, 120); if (!cat) continue;
      const rank = a.toleranceRank != null && String(a.toleranceRank) !== "" ? Math.max(0, Math.min(4, Math.round(Number(a.toleranceRank)))) : null;
      ins.run(tenant, cat, s(a.appetiteLevel, 40), rank, s(a.rationale, 1000));
    }
  }
  return { ok: true };
}

/** Create a measure in the library. */
export function createMeasure(
  tenant: number | null,
  p: { name: string; ref?: string; description?: string; measureType?: string; category?: string; controlRef?: string; effectiveness?: string; cost?: string; status?: string },
): { id: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const s = (v: unknown, n = 4000): string | null => (v != null && String(v).trim() !== "" ? String(v).slice(0, n) : null);
  const r = cc.prepare(`INSERT INTO RISKMEASURE (TenantID, Ref, Name, Description, MeasureType, Category, ControlRef, Effectiveness, Cost, Status, CreatedDate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    tenant, s(p.ref, 60), (p.name || "Untitled measure").slice(0, 300), s(p.description), s(p.measureType, 40), s(p.category, 120),
    s(p.controlRef, 120), s(p.effectiveness, 40), s(p.cost, 60), s(p.status, 40) || "Proposed", new Date().toISOString());
  return { id: Number(r.lastInsertRowid) };
}

/** Patch a measure (status / fields). */
export function updateMeasure(tenant: number | null, id: number, patch: Record<string, unknown>): { ok: true } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const map: Record<string, string> = { status: "Status", name: "Name", description: "Description", measureType: "MeasureType", category: "Category", controlRef: "ControlRef", effectiveness: "Effectiveness", cost: "Cost", ref: "Ref" };
  const sets: string[] = []; const vals: unknown[] = [];
  for (const [k, col] of Object.entries(map)) if (k in patch) { sets.push(`"${col}" = ?`); vals.push(patch[k] != null ? String(patch[k]).slice(0, 4000) : null); }
  if (!sets.length) return { ok: true };
  const guard = tenant != null ? ` AND TenantID = ${tenant}` : "";
  cc.prepare(`UPDATE RISKMEASURE SET ${sets.join(", ")} WHERE RiskMeasureID = ?${guard}`).run(...vals, id);
  return { ok: true };
}

/** Measures linked to a register entry (the entry's treatment as concrete measures). */
export function entryMeasures(tenant: number | null, entryId: number): Record<string, unknown>[] {
  ensureRiskGovTables();
  return getDb("XCOMPLIANCE").prepare(`
    SELECT l.LinkID, l.ImplementationStatus, m.RiskMeasureID, m.Ref, m.Name, m.MeasureType, m.Effectiveness, m.Status
    FROM RISKMEASURELINK l JOIN RISKMEASURE m ON m.RiskMeasureID = l.RiskMeasureID
    WHERE l.RiskRegisterEntryID = ?${tenant != null ? ` AND l.TenantID = ${tenant}` : ""} ORDER BY m.Name`).all(entryId) as Record<string, unknown>[];
}

export function linkMeasure(tenant: number | null, entryId: number, measureId: number, status?: string): { id: number } {
  ensureRiskGovTables();
  const cc = getDb("XCOMPLIANCE");
  const dup = cc.prepare(`SELECT LinkID FROM RISKMEASURELINK WHERE RiskRegisterEntryID = ? AND RiskMeasureID = ?`).get(entryId, measureId) as { LinkID: number } | undefined;
  if (dup) return { id: dup.LinkID };
  const r = cc.prepare(`INSERT INTO RISKMEASURELINK (TenantID, RiskRegisterEntryID, RiskMeasureID, ImplementationStatus, CreatedDate) VALUES (?, ?, ?, ?, ?)`)
    .run(tenant, entryId, measureId, (status && String(status).slice(0, 40)) || "Planned", new Date().toISOString());
  return { id: Number(r.lastInsertRowid) };
}

export function unlinkMeasure(tenant: number | null, linkId: number): { ok: true } {
  ensureRiskGovTables();
  getDb("XCOMPLIANCE").prepare(`DELETE FROM RISKMEASURELINK WHERE LinkID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""}`).run(linkId);
  return { ok: true };
}

export function setLinkStatus(tenant: number | null, linkId: number, status: string): { ok: true } {
  ensureRiskGovTables();
  getDb("XCOMPLIANCE").prepare(`UPDATE RISKMEASURELINK SET ImplementationStatus = ? WHERE LinkID = ?${tenant != null ? ` AND TenantID = ${tenant}` : ""}`).run(String(status).slice(0, 40), linkId);
  return { ok: true };
}
