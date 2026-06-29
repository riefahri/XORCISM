/**
 * bia.ts — Business Impact Analysis computation.
 *
 * Derives a criticality tier and suggested recovery objectives (RTO/RPO/MTD) for each asset
 * from data XORCISM already holds — the asset's own business/financial value, its risk score,
 * exposure flags (public-facing, mission/defense-critical), and its dependency centrality
 * (how many network connections reference it). Deterministic; no AI.
 *
 * This complements manually-authored BIAENTRY rows: where a human BIA exists it stays
 * authoritative; computeBia() produces a data-driven first draft / gap-filler so that every
 * high-value or heavily-depended-upon asset has recovery objectives even before a human sits down
 * to do the formal analysis. Each row carries the drivers that put the asset in its tier, so the
 * suggestion is traceable rather than a black box.
 */
import { getDb } from "./db";
import { assetDependencyDegree } from "./assetdeps";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const colset = (db: ReturnType<typeof getDb>, t: string): Set<string> => {
  try { return new Set((db.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
};

export interface BiaTier { label: string; rto: string; rpo: string; mtd: string; min: number; }
// Tier → suggested recovery objectives. Tighter objectives for higher business impact.
export const BIA_TIERS: BiaTier[] = [
  { label: "Critical", min: 75, rto: "4h", rpo: "1h", mtd: "8h" },
  { label: "High", min: 50, rto: "24h", rpo: "4h", mtd: "48h" },
  { label: "Medium", min: 25, rto: "72h", rpo: "24h", mtd: "1 week" },
  { label: "Low", min: 0, rto: "1 week", rpo: "72h", mtd: "2 weeks" },
];
function tierFor(score: number): BiaTier { return BIA_TIERS.find((t) => score >= t.min) || BIA_TIERS[BIA_TIERS.length - 1]; }

// Textual criticality / value levels → 0..1 (so BusinessValue / AssetCriticalityLevel stored as words still score).
function levelToUnit(v: unknown): number | null {
  const s = String(v ?? "").toLowerCase().trim();
  if (!s) return null;
  if (/(very[ -]?high|critical|severe)/.test(s)) return 1;
  if (/high/.test(s)) return 0.8;
  if (/(medium|moderate)/.test(s)) return 0.5;
  if (/(very[ -]?low|negligible|minimal)/.test(s)) return 0.1;
  if (/low/.test(s)) return 0.25;
  return null;
}
// Numeric coercion that tolerates "", "12 345", currency text.
function num(v: unknown): number { const n = Number(String(v ?? "").replace(/[^0-9.\-]/g, "")); return Number.isFinite(n) ? n : 0; }
function truthy(v: unknown): boolean { const s = String(v ?? "").toLowerCase().trim(); return s === "1" || s === "true" || s === "yes" || s === "y"; }

export interface BiaComputedRow {
  assetId: number; asset: string; criticality: string; score: number;
  rto: string; rpo: string; mtd: string; drivers: string[]; source: "computed";
}
export interface BiaComputed { rows: BiaComputedRow[]; total: number; critical: number; }

/**
 * Compute a BIA draft for every asset that has at least one impact signal.
 * Score (0..100) is a weighted blend, each component normalised against the tenant's own maximum so
 * the analysis is relative to this estate, not absolute currency amounts.
 */
export function computeBia(tenant: number | null, limit = 200): BiaComputed {
  const xo = getDb("XORCISM");
  if (!has(xo, "ASSET")) return { rows: [], total: 0, critical: 0 };
  const cols = colset(xo, "ASSET");
  const pick = (...c: string[]): string[] => c.filter((x) => cols.has(x));
  const want = pick("AssetID", "AssetName", "AssetCriticalityLevel", "BusinessValue", "FinancialValue",
    "RiskScore", "PublicFacing", "DefenseCriticalAsset", "TaskCriticalAsset", "SLAResolutionHours");
  if (!want.includes("AssetID") || !want.includes("AssetName")) return { rows: [], total: 0, critical: 0 };
  const tw = tenant != null && cols.has("TenantID") ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
  const assets = xo.prepare(`SELECT ${want.join(",")} FROM ASSET ${tw}`).all(...(tw ? [tenant] : [])) as Record<string, unknown>[];
  if (!assets.length) return { rows: [], total: 0, critical: 0 };

  // dependency centrality: prefer true asset→asset in-degree (how many assets depend ON this one); if no
  // such edges have been derived yet, fall back to the network-connection-count proxy.
  let depCount = new Map<number, number>();
  let depKind: "edges" | "connections" = "connections";
  try {
    const deg = assetDependencyDegree(tenant);
    if (deg.size) { depCount = deg; depKind = "edges"; }
    else if (has(xo, "CONNECTIONFORASSET")) {
      for (const r of xo.prepare("SELECT AssetID, COUNT(*) n FROM CONNECTIONFORASSET GROUP BY AssetID").all() as { AssetID: number; n: number }[])
        depCount.set(Number(r.AssetID), Number(r.n));
    }
  } catch { /* */ }

  // tenant maxima for normalisation
  let maxFin = 0, maxBiz = 0, maxRisk = 0, maxDep = 0;
  for (const a of assets) {
    maxFin = Math.max(maxFin, num(a.FinancialValue));
    const bizUnit = levelToUnit(a.BusinessValue); maxBiz = Math.max(maxBiz, bizUnit != null ? 0 : num(a.BusinessValue));
    maxRisk = Math.max(maxRisk, num(a.RiskScore));
    maxDep = Math.max(maxDep, depCount.get(Number(a.AssetID)) || 0);
  }
  const norm = (v: number, max: number): number => (max > 0 ? Math.min(1, v / max) : 0);

  const rows: BiaComputedRow[] = [];
  for (const a of assets) {
    const id = Number(a.AssetID);
    const drivers: string[] = [];
    // business value: textual level OR numeric (normalised)
    const bizUnit = levelToUnit(a.BusinessValue);
    const biz = bizUnit != null ? bizUnit : norm(num(a.BusinessValue), maxBiz);
    if (biz >= 0.5) drivers.push(bizUnit != null ? `business value ${String(a.BusinessValue)}` : "high business value");
    const fin = norm(num(a.FinancialValue), maxFin);
    if (fin >= 0.5 && num(a.FinancialValue) > 0) drivers.push(`high financial value`);
    const risk = norm(num(a.RiskScore), maxRisk);
    if (risk >= 0.5) drivers.push(`elevated risk score`);
    const dep = norm(depCount.get(id) || 0, maxDep);
    const dn = depCount.get(id) || 0;
    if (dn >= 1 && dep >= 0.4) drivers.push(depKind === "edges" ? `${dn} dependent asset${dn === 1 ? "" : "s"}` : `${dn} network connection${dn === 1 ? "" : "s"}`);
    let flags = 0;
    if (truthy(a.PublicFacing)) { flags += 1; drivers.push("public-facing"); }
    if (truthy(a.DefenseCriticalAsset)) { flags += 1; drivers.push("defense-critical"); }
    if (truthy(a.TaskCriticalAsset)) { flags += 1; drivers.push("mission-critical"); }
    const flagUnit = Math.min(1, flags / 2);

    let score = 100 * (0.30 * biz + 0.25 * fin + 0.20 * risk + 0.15 * dep + 0.10 * flagUnit);
    // explicit criticality acts as a floor — never rank an asset the owner called Critical below that tier.
    const explicit = levelToUnit(a.AssetCriticalityLevel);
    if (explicit != null) { score = Math.max(score, explicit * 100 - 1); if (explicit >= 0.8) drivers.unshift(`tagged ${String(a.AssetCriticalityLevel)}`); }
    score = Math.round(Math.max(0, Math.min(100, score)));
    if (score <= 0 && !drivers.length) continue; // asset has no impact signal at all — skip

    const tier = tierFor(score);
    // if the asset already carries an SLA resolution target, surface it as the operative RTO.
    let rto = tier.rto;
    const sla = num(a.SLAResolutionHours);
    if (sla > 0) { rto = `${sla}h`; drivers.push(`SLA ${sla}h`); }
    rows.push({ assetId: id, asset: String(a.AssetName || ""), criticality: tier.label, score, rto, rpo: tier.rpo, mtd: tier.mtd, drivers, source: "computed" });
  }
  rows.sort((x, y) => y.score - x.score);
  const critical = rows.filter((r) => r.criticality === "Critical" || r.criticality === "High").length;
  return { rows: rows.slice(0, limit), total: rows.length, critical };
}
