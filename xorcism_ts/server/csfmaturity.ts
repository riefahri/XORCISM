/**
 * csfmaturity.ts — NIST CSF 2.0 maturity self-assessment.
 *
 * Scores every one of the 106 CSF 2.0 subcategories (across the 6 functions GOVERN/IDENTIFY/
 * PROTECT/DETECT/RESPOND/RECOVER and 22 categories) on a 5-level CMMI-style maturity scale
 * (1 Performed → 5 Optimizing), tracking current vs target maturity with comments, and rolling
 * up to per-function and overall maturity, a gap worklist and a board-ready maturity score.
 * Catalogue + the 5 reference levels are seeded at boot (db.ensureCsfMaturityTables); the score
 * write is a dedicated endpoint. Complements governance.ts (the Govern-only status register) and
 * the framework CONTROL vocabulary.
 */
import { allocId, getDb } from "./db";

const FUNCTION_ORDER = ["GV", "ID", "PR", "DE", "RS", "RC"];
const FUNCTION_NAME: Record<string, string> = { GV: "GOVERN", ID: "IDENTIFY", PR: "PROTECT", DE: "DETECT", RS: "RESPOND", RC: "RECOVER" };

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const r1 = (x: number | null): number | null => (x == null ? null : Math.round(x * 10) / 10);
const clamp = (v: unknown): number | null => { if (v == null || v === "") return null; const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(0, Math.min(5, n)) : null; };

export interface CsfLevelRow { score: number; name: string; description: string; }

export function csfLevels(): CsfLevelRow[] {
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return []; }
  if (!has(cc, "CSFMATURITYLEVEL")) return [];
  return cc.prepare("SELECT Score AS score, Name AS name, Description AS description FROM CSFMATURITYLEVEL ORDER BY Score").all() as CsfLevelRow[];
}

/** Full CSF 2.0 maturity inventory: the model + every subcategory with current/target + rollups + worklist. */
export function csfMaturityInventory(tenant: number | null): any {
  const levels = csfLevels();
  const empty = { levels, functions: [], rows: [], worklist: [], summary: { subcategories: 0, scored: 0, coverage: 0, overallCurrent: null, overallTarget: null, maturityScore: 0, belowTarget: 0, gaps: 0, withTarget: 0 } };
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return empty; }
  if (!has(cc, "CSFSUBCATEGORY")) return empty;

  const subs = cc.prepare("SELECT SubID, FunctionCode, FunctionName, CategoryCode, CategoryName, SubCode, Outcome FROM CSFSUBCATEGORY ORDER BY SortOrder").all() as any[];
  const scoreBy = new Map<number, any>();
  for (const s of (tenant != null ? cc.prepare("SELECT * FROM CSFMATURITYSCORE WHERE (TenantID = ? OR TenantID IS NULL)").all(tenant) : cc.prepare("SELECT * FROM CSFMATURITYSCORE").all()) as any[])
    scoreBy.set(Number(s.SubID), s);

  const rows = subs.map((it) => {
    const s = scoreBy.get(Number(it.SubID));
    const current = s ? clamp(s.CurrentLevel) : null;
    const target = s ? clamp(s.TargetLevel) : null;
    const gap = current != null && target != null ? Math.max(0, target - current) : 0;
    return {
      id: Number(it.SubID), functionCode: String(it.FunctionCode), functionName: String(it.FunctionName),
      categoryCode: String(it.CategoryCode), categoryName: String(it.CategoryName), sub: String(it.SubCode), outcome: String(it.Outcome ?? ""),
      current, target, gap, notes: s ? String(s.Notes ?? "") : "",
    };
  });

  // per-function rollup (average of scored subcategories)
  const functions = FUNCTION_ORDER.map((fc) => {
    const list = rows.filter((r) => r.functionCode === fc);
    const cur = list.filter((r) => r.current != null);
    const tgt = list.filter((r) => r.target != null);
    const avgCur = cur.length ? cur.reduce((a, r) => a + (r.current || 0), 0) / cur.length : null;
    const avgTgt = tgt.length ? tgt.reduce((a, r) => a + (r.target || 0), 0) / tgt.length : null;
    // categories within the function
    const catCodes = [...new Set(list.map((r) => r.categoryCode))];
    const categories = catCodes.map((cc2) => {
      const cl = list.filter((r) => r.categoryCode === cc2);
      const cs = cl.filter((r) => r.current != null);
      return { code: cc2, name: cl[0]?.categoryName ?? "", subs: cl.length, scored: cs.length, current: r1(cs.length ? cs.reduce((a, r) => a + (r.current || 0), 0) / cs.length : null) };
    });
    return { code: fc, name: FUNCTION_NAME[fc] || fc, subs: list.length, scored: cur.length, current: r1(avgCur), target: r1(avgTgt), gap: r1(avgTgt != null && avgCur != null ? Math.max(0, avgTgt - avgCur) : 0), categories };
  });

  const scored = rows.filter((r) => r.current != null);
  const withTarget = rows.filter((r) => r.target != null);
  const overallCurrent = scored.length ? scored.reduce((a, r) => a + (r.current || 0), 0) / scored.length : null;
  const overallTarget = withTarget.length ? withTarget.reduce((a, r) => a + (r.target || 0), 0) / withTarget.length : null;

  // worklist: biggest current↔target gaps, then unscored high-value (GOVERN/RESPOND/RECOVER) subcategories
  const worklist = rows.filter((r) => r.gap > 0)
    .sort((a, b) => b.gap - a.gap || (a.current ?? 0) - (b.current ?? 0))
    .map((r) => ({ id: r.id, sub: r.sub, functionCode: r.functionCode, outcome: r.outcome, current: r.current, target: r.target, gap: r.gap, severity: r.gap >= 3 ? "High" : r.gap === 2 ? "Medium" : "Low" }))
    .slice(0, 40);

  return {
    levels, functions, rows, worklist,
    summary: {
      subcategories: rows.length, scored: scored.length,
      coverage: rows.length ? Math.round((scored.length / rows.length) * 100) : 0,
      overallCurrent: r1(overallCurrent), overallTarget: r1(overallTarget),
      maturityScore: overallCurrent != null ? Math.round((overallCurrent / 5) * 100) : 0,
      belowTarget: rows.filter((r) => r.gap > 0).length, gaps: rows.filter((r) => r.gap > 0).length, withTarget: withTarget.length,
    },
  };
}

/** Create or update the current/target maturity for one CSF subcategory (per tenant). */
export function saveCsfScore(subId: number, p: { currentLevel?: number; targetLevel?: number; notes?: string; ownerPersonId?: number }, tenant: number | null): boolean {
  const cc = getDb("XCOMPLIANCE");
  if (!cc.prepare("SELECT 1 FROM CSFSUBCATEGORY WHERE SubID = ?").get(subId)) return false;
  const now = new Date().toISOString();
  const cur = clamp(p.currentLevel);
  const tgt = clamp(p.targetLevel);
  const ex = cc.prepare("SELECT ScoreID FROM CSFMATURITYSCORE WHERE SubID = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(subId, tenant) as { ScoreID: number } | undefined;
  if (ex) {
    const sets: string[] = ["AssessedDate = ?"]; const vals: unknown[] = [now];
    if (p.currentLevel !== undefined) { sets.push("CurrentLevel = ?"); vals.push(cur); }
    if (p.targetLevel !== undefined) { sets.push("TargetLevel = ?"); vals.push(tgt); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
    if (p.ownerPersonId != null) { sets.push("OwnerPersonID = ?"); vals.push(p.ownerPersonId); }
    vals.push(ex.ScoreID);
    cc.prepare(`UPDATE CSFMATURITYSCORE SET ${sets.join(", ")} WHERE ScoreID = ?`).run(...vals);
  } else {
    const id = allocId(cc, "CSFMATURITYSCORE", "ScoreID");
    cc.prepare("INSERT INTO CSFMATURITYSCORE (ScoreID, SubID, CurrentLevel, TargetLevel, Notes, OwnerPersonID, TenantID, AssessedDate) VALUES (?,?,?,?,?,?,?,?)")
      .run(id, subId, cur, tgt, String(p.notes ?? "").slice(0, 1000), p.ownerPersonId ?? null, tenant, now);
  }
  return true;
}

/** Seed a realistic demo maturity profile for a tenant (idempotent: skips if any scores exist). */
export function seedCsfMaturity(tenant: number): { scores: number } {
  const cc = getDb("XCOMPLIANCE");
  if (!has(cc, "CSFSUBCATEGORY")) return { scores: 0 };
  if ((cc.prepare("SELECT COUNT(*) n FROM CSFMATURITYSCORE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { scores: 0 };
  // function-level baseline maturity (Detect/Respond a touch lower, Govern mid) — a believable mid-maturity org
  const base: Record<string, number> = { GV: 3, ID: 3, PR: 3, DE: 2, RS: 2, RC: 2 };
  const subs = cc.prepare("SELECT SubID, FunctionCode FROM CSFSUBCATEGORY ORDER BY SortOrder").all() as any[];
  let n = 0;
  for (const s of subs) {
    const cur = Math.max(1, Math.min(5, (base[s.FunctionCode] ?? 2) + ((Number(s.SubID) * 7) % 3) - 1));
    saveCsfScore(Number(s.SubID), { currentLevel: cur, targetLevel: 4 }, tenant); n++;
  }
  return { scores: n };
}
