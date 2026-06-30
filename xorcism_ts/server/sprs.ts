/**
 * sprs.ts — SPRS / NIST SP 800-171 Rev 2 self-assessment score.
 *
 * Computes the DoD Supplier Performance Risk System (SPRS) score for the 110 NIST 800-171 requirements:
 * start at 110, subtract a requirement's weight for each NOT-MET requirement (a POA&M item still counts
 * as not-met until closed), partial implementation gives partial credit, N/A is excluded. The catalogue +
 * weights are in data/sprs800171.ts (weights editable per requirement). Complements the CMMC journey and
 * the Audit & Accreditation package (OSCAL SSP/POA&M).
 */
import { allocId, getDb } from "./db";
import { SPRS_REQUIREMENTS, SPRS_FAMILIES, SPRS_MAX, SprsReq } from "./data/sprs800171";

export const SPRS_STATUSES = ["implemented", "partial", "not-implemented", "na", "poam"];
const has = (db: ReturnType<typeof getDb>, t: string): boolean => { try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; } };
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

interface StatusRow { Status: string; WeightOverride: number | null; Notes: string | null; }
function statusMap(tenant: number | null): Map<string, StatusRow> {
  const db = getDb("XCOMPLIANCE");
  const m = new Map<string, StatusRow>();
  if (!has(db, "SPRSSTATUS")) return m;
  const rows = (tenant != null
    ? db.prepare("SELECT ReqID, Status, WeightOverride, Notes FROM SPRSSTATUS WHERE TenantID = ? OR TenantID IS NULL").all(tenant)
    : db.prepare("SELECT ReqID, Status, WeightOverride, Notes FROM SPRSSTATUS").all()) as any[];
  for (const r of rows) m.set(String(r.ReqID), { Status: String(r.Status || "not-implemented"), WeightOverride: r.WeightOverride != null ? num(r.WeightOverride) : null, Notes: r.Notes ?? null });
  return m;
}

/** Deduction for one requirement given its status + effective weight (partial = partial credit). */
function deduction(status: string, weight: number): number {
  if (status === "implemented" || status === "na") return 0;
  if (status === "partial") return weight >= 5 ? 3 : weight >= 3 ? 1 : 0; // partial credit (DoD-style)
  return weight; // not-implemented OR poam (a POA&M item still counts as not-met until closed)
}

/** Full SPRS assessment: per-requirement rows, per-family rollup, the score and the methodology floor. */
export function sprsAssessment(tenant: number | null): any {
  const sm = statusMap(tenant);
  let totalWeight = 0, deducted = 0, met = 0, naCount = 0, poam = 0, partial = 0;
  const famAgg: Record<string, { name: string; total: number; met: number; deducted: number; weight: number }> = {};
  for (const f of SPRS_FAMILIES) famAgg[f.code] = { name: f.name, total: 0, met: 0, deducted: 0, weight: 0 };

  const requirements = SPRS_REQUIREMENTS.map((r: SprsReq) => {
    const st = sm.get(r.id);
    const status = st ? st.Status : "not-implemented";
    const weight = st && st.WeightOverride != null ? st.WeightOverride : r.weight;
    const ded = deduction(status, weight);
    totalWeight += weight; deducted += ded;
    if (status === "implemented") met++; if (status === "na") naCount++; if (status === "poam") poam++; if (status === "partial") partial++;
    const fa = famAgg[r.family]; fa.total++; fa.weight += weight; fa.deducted += ded; if (status === "implemented" || status === "na") fa.met++;
    return { id: r.id, family: r.family, familyName: r.familyName, weight, status, deduction: ded, notes: st?.Notes ?? "" };
  });

  const floor = SPRS_MAX - totalWeight; // self-consistent floor from the live weights (official = −203)
  const score = SPRS_MAX - deducted;
  const assessable = SPRS_REQUIREMENTS.length - naCount;
  const families = SPRS_FAMILIES.map((f) => ({ code: f.code, name: f.name, total: famAgg[f.code].total, met: famAgg[f.code].met, deducted: famAgg[f.code].deducted, metPct: famAgg[f.code].total ? Math.round((famAgg[f.code].met / famAgg[f.code].total) * 100) : 0 }));

  return {
    statuses: SPRS_STATUSES,
    summary: {
      score, max: SPRS_MAX, floor, deducted, totalWeight,
      requirements: SPRS_REQUIREMENTS.length, met, partial, notImplemented: SPRS_REQUIREMENTS.length - met - naCount - poam - partial,
      poam, na: naCount, assessable,
      metPct: assessable ? Math.round((met / assessable) * 100) : 0,
      // SPRS uses the raw score; "implementation %" is the share of assessable requirements met.
      level: met === assessable && assessable > 0 ? "Met (110)" : score >= 88 ? "Strong" : score >= 0 ? "Partial" : "Early",
    },
    families, requirements,
  };
}

/** Set (upsert) the status / weight override / notes of one requirement. */
export function setSprsStatus(reqId: string, p: { status?: string; weightOverride?: number | null; notes?: string }, tenant: number | null): boolean {
  if (!SPRS_REQUIREMENTS.some((r) => r.id === reqId)) return false;
  const db = getDb("XCOMPLIANCE");
  const status = p.status && SPRS_STATUSES.includes(p.status) ? p.status : undefined;
  const existing = db.prepare("SELECT SprsStatusID FROM SPRSSTATUS WHERE ReqID=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(reqId, tenant) as { SprsStatusID: number } | undefined;
  const now = new Date().toISOString();
  if (existing) {
    const sets: string[] = [], vals: unknown[] = [];
    if (status !== undefined) { sets.push("Status=?"); vals.push(status); }
    if (p.weightOverride !== undefined) { sets.push("WeightOverride=?"); vals.push(p.weightOverride == null || (p.weightOverride as any) === "" ? null : num(p.weightOverride)); }
    if (p.notes !== undefined) { sets.push("Notes=?"); vals.push(String(p.notes).slice(0, 2000)); }
    if (!sets.length) return true;
    sets.push("UpdatedDate=?"); vals.push(now);
    db.prepare(`UPDATE SPRSSTATUS SET ${sets.join(", ")} WHERE SprsStatusID=?`).run(...vals, existing.SprsStatusID);
  } else {
    const id = allocId(db, "SPRSSTATUS", "SprsStatusID");
    db.prepare("INSERT INTO SPRSSTATUS (SprsStatusID, ReqID, Status, WeightOverride, Notes, UpdatedDate, TenantID) VALUES (?,?,?,?,?,?,?)")
      .run(id, reqId, status || "not-implemented", p.weightOverride != null && (p.weightOverride as any) !== "" ? num(p.weightOverride) : null, p.notes != null ? String(p.notes).slice(0, 2000) : null, now, tenant);
  }
  return true;
}

/** Seed a demo profile (idempotent): mark a realistic subset implemented so the score is illustrative. */
export function seedDemo(tenant: number): { created: number } {
  const db = getDb("XCOMPLIANCE");
  if (db.prepare("SELECT 1 FROM SPRSSTATUS WHERE IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };
  // implement ~70% of requirements; leave a few high-weight ones as POA&M / not-implemented
  const poamSet = new Set(["3.5.3", "3.13.11", "3.13.16", "3.14.6", "3.4.9"]);
  SPRS_REQUIREMENTS.forEach((r, i) => {
    const status = poamSet.has(r.id) ? "poam" : (i % 10 < 7 ? "implemented" : "not-implemented");
    setSprsStatus(r.id, { status }, tenant);
  });
  return { created: 1 };
}
