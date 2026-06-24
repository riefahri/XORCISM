/**
 * threatlevel.ts — global cyber threat-level gauge (DEFCON / national-advisory style).
 *
 * Aggregates recent threat signals into a single 0-100 condition score and a 1-5 level
 * (LOW → GUARDED → ELEVATED → HIGH → SEVERE) for the dashboard gauge. This is the
 * "global threat-level" indicator XORCISM was missing (the AEGIS gauge equivalent).
 *
 * The model is deliberately weighted toward *actively-exploited* signals (freshly added /
 * updated KEV entries, high-EPSS CVEs) and *your own* open high/critical incidents and
 * KEV-unpatched exposure, with CTI ingestion volume (threat reports / intel) as a minor
 * contributor — so the gauge tracks real change rather than pegging on archive size.
 *
 * Read-only; every query is wrapped defensively (tolerates missing tables/columns), so it
 * never throws on a partially-seeded instance.
 */
import { getDb } from "./db";

const KEV_WINDOW_DAYS = 14;   // "fresh" actively-exploited window
const CTI_WINDOW_DAYS = 30;   // CTI activity window

export interface ThreatContributor { key: string; label: string; count: number; points: number; }
export interface ThreatLevel {
  level: 1 | 2 | 3 | 4 | 5;
  label: "LOW" | "GUARDED" | "ELEVATED" | "HIGH" | "SEVERE";
  score: number;            // 0-100
  color: string;            // gauge colour
  windowDays: number;
  signals: {
    kevRecent: number; epssRecent: number; threatReports: number;
    intel: number; incidentsOpen: number; kevUnpatched: number;
  };
  contributors: ThreatContributor[]; // sorted by points desc
  asOf: string;
}

const LEVELS: { min: number; level: 1 | 2 | 3 | 4 | 5; label: ThreatLevel["label"]; color: string }[] = [
  { min: 80, level: 5, label: "SEVERE",   color: "#ef4444" },
  { min: 60, level: 4, label: "HIGH",     color: "#fb923c" },
  { min: 40, level: 3, label: "ELEVATED", color: "#facc15" },
  { min: 20, level: 2, label: "GUARDED",  color: "#38bdf8" },
  { min: 0,  level: 1, label: "LOW",      color: "#22c55e" },
];

function sinceISO(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}
function safe(fn: () => number): number { try { return fn() || 0; } catch { return 0; } }
/** capped logarithmic contribution: 0 → 0, grows fast then flattens at `cap`. */
function logPts(count: number, mult: number, cap: number): number {
  if (count <= 0) return 0;
  return Math.min(cap, Math.round(mult * Math.log10(1 + count)));
}

/**
 * Compute the current threat level. `ctx.kevUnpatched` (KEV vulns unpatched on the tenant's
 * own assets) is injected by the caller — it already computes it for the KPI strip — so we
 * avoid a heavy cross-database join here.
 */
export function threatLevel(tenant: number | null, ctx?: { kevUnpatched?: number }): ThreatLevel {
  const kevSince = sinceISO(KEV_WINDOW_DAYS);
  const ctiSince = sinceISO(CTI_WINDOW_DAYS);

  // 1) Freshly added/updated KEV entries — actively exploited in the wild.
  const kevRecent = safe(() => (getDb("XVULNERABILITY")
    .prepare("SELECT COUNT(*) n FROM VULNERABILITY WHERE KEV=1 AND substr(VULModifiedDate,1,10) >= ?")
    .get(kevSince) as { n: number }).n);

  // 2) Fresh high-EPSS CVEs (>= 50% exploitation probability).
  const epssRecent = safe(() => (getDb("XVULNERABILITY")
    .prepare("SELECT COUNT(*) n FROM VULNERABILITY WHERE CAST(EPSS AS REAL) >= 0.5 AND substr(VULModifiedDate,1,10) >= ?")
    .get(kevSince) as { n: number }).n);

  // 3) Recent CTI threat reports.
  const threatReports = safe(() => (getDb("XTHREAT")
    .prepare("SELECT COUNT(*) n FROM THREATREPORT WHERE substr(COALESCE(NULLIF(ValidFrom,''),CreatedDate),1,10) >= ?")
    .get(ctiSince) as { n: number }).n);

  // 4) Recent intel-exchange items (pulses, IOCs, advisories).
  const intel = safe(() => (getDb("XTHREAT")
    .prepare("SELECT COUNT(*) n FROM INTELEXCHANGE WHERE substr(COALESCE(NULLIF(IntelDate,''),CreatedDate),1,10) >= ?")
    .get(ctiSince) as { n: number }).n);

  // 5) Your own open high/critical alerts (tenant-scoped where available).
  const incidentsOpen = safe(() => {
    const db = getDb("XINCIDENT");
    const sev = "LOWER(COALESCE(Severity,'')) IN ('high','critical')";
    const open = "LOWER(COALESCE(Status,'')) NOT IN ('resolved','closed','dismissed')";
    if (tenant == null) {
      return (db.prepare(`SELECT COUNT(*) n FROM ALERT WHERE ${sev} AND ${open} AND substr(CreatedDate,1,10) >= ?`)
        .get(sinceISO(KEV_WINDOW_DAYS)) as { n: number }).n;
    }
    return (db.prepare(`SELECT COUNT(*) n FROM ALERT WHERE TenantID=? AND ${sev} AND ${open} AND substr(CreatedDate,1,10) >= ?`)
      .get(tenant, sinceISO(KEV_WINDOW_DAYS)) as { n: number }).n;
  });

  const kevUnpatched = Math.max(0, Number(ctx?.kevUnpatched) || 0);

  const contributors: ThreatContributor[] = [
    { key: "kevRecent",     label: `Newly exploited (KEV, ${KEV_WINDOW_DAYS}d)`, count: kevRecent,     points: logPts(kevRecent, 14, 35) },
    { key: "incidentsOpen", label: "Open high/critical alerts",                  count: incidentsOpen, points: Math.min(25, incidentsOpen * 6) },
    { key: "epssRecent",    label: `High-EPSS CVEs (${KEV_WINDOW_DAYS}d)`,        count: epssRecent,    points: logPts(epssRecent, 7, 20) },
    { key: "kevUnpatched",  label: "KEV unpatched on your assets",               count: kevUnpatched,  points: logPts(kevUnpatched, 7, 20) },
    { key: "threatReports", label: `CTI reports (${CTI_WINDOW_DAYS}d)`,           count: threatReports, points: logPts(threatReports, 4, 12) },
    { key: "intel",         label: `Intel items (${CTI_WINDOW_DAYS}d)`,           count: intel,         points: logPts(intel, 4, 8) },
  ].sort((a, b) => b.points - a.points);

  const score = Math.max(0, Math.min(100, contributors.reduce((s, c) => s + c.points, 0)));
  const band = LEVELS.find((l) => score >= l.min)!;

  return {
    level: band.level, label: band.label, score, color: band.color,
    windowDays: KEV_WINDOW_DAYS,
    signals: { kevRecent, epssRecent, threatReports, intel, incidentsOpen, kevUnpatched },
    contributors,
    asOf: new Date().toISOString(),
  };
}
