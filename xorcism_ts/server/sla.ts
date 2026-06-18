/**
 * sla.ts — SLA definitions on ASSET, reused to measure incident response.
 *
 * - ASSET (XORCISM) gains SLA target columns: SLAResponseHours / SLAResolutionHours.
 * - INCIDENT (XINCIDENT) gains a Duration column (hours to resolve).
 * - incidentSlaView() joins incidents to their assets (INCIDENTFORASSET) and
 *   measures each incident's duration against the affected asset's resolution SLA,
 *   flagging breaches. Cross-database join (XINCIDENT ↔ XORCISM) done in JS.
 *
 * All read-only and idempotent. See [[xorcism-legacy-tables]] (ALTER, don't recreate).
 */
import { getDb } from "./db";

/** Adds the SLA columns to ASSET (XORCISM) and Duration to INCIDENT (XINCIDENT). Idempotent. */
export function ensureSlaColumns(): void {
  try {
    const xo = getDb("XORCISM");
    if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSET'").get()) {
      const cols = new Set((xo.prepare(`PRAGMA table_info("ASSET")`).all() as { name: string }[]).map((c) => c.name));
      for (const [n, t] of [["SLAResponseHours", "REAL"], ["SLAResolutionHours", "REAL"]]) {
        if (!cols.has(n)) xo.exec(`ALTER TABLE "ASSET" ADD COLUMN "${n}" ${t}`);
      }
    }
  } catch { /* best-effort */ }
  try {
    const xi = getDb("XINCIDENT");
    if (xi.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='INCIDENT'").get()) {
      const cols = new Set((xi.prepare(`PRAGMA table_info("INCIDENT")`).all() as { name: string }[]).map((c) => c.name));
      if (!cols.has("Duration")) xi.exec(`ALTER TABLE "INCIDENT" ADD COLUMN "Duration" REAL`);
    }
  } catch { /* best-effort */ }
}

export type SlaStatus = "met" | "breached" | "no-target" | "no-duration";

/** Compares an incident duration to a single target (asset SLA or BIA RTO). */
function evalTarget(duration: number | null, target: number | null): { status: SlaStatus; overage: number | null } {
  if (target == null || target <= 0) return { status: "no-target", overage: null };
  if (duration == null) return { status: "no-duration", overage: null };
  return { status: duration > target ? "breached" : "met", overage: duration - target };
}

export interface SlaRow {
  incidentId: number;
  incidentName: string;
  severity: string | null;
  assetId: number;
  assetName: string;
  duration: number | null;     // hours (stored, or derived from start/end)
  slaHours: number | null;      // asset resolution SLA target (hours)
  slaStatus: SlaStatus;
  slaOverage: number | null;    // duration - sla (hours); >0 = late
  rtoHours: number | null;      // BIA Recovery Time Objective (hours)
  rtoStatus: SlaStatus;
  rtoOverage: number | null;    // duration - rto (hours); >0 = past RTO
}

interface TargetSummary { evaluated: number; met: number; breached: number; breachRate: number; noTarget: number; }

export interface SlaView {
  rows: SlaRow[];
  summary: {
    links: number;
    noDuration: number;
    avgDuration: number | null;
    sla: TargetSummary & { avg: number | null };
    rto: TargetSummary & { avg: number | null };
  };
}

function cols(dbName: string, table: string): Set<string> {
  try {
    return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name));
  } catch { return new Set(); }
}

/** Hours between two ISO/SQL datetimes, or null if unparseable / negative. */
function hoursBetween(a?: string | null, b?: string | null): number | null {
  if (!a || !b) return null;
  const ta = Date.parse(String(a)), tb = Date.parse(String(b));
  if (Number.isNaN(ta) || Number.isNaN(tb) || tb < ta) return null;
  return (tb - ta) / 3_600_000;
}

const numOf = (v: unknown): number | null => (v == null || v === "" ? null : Number.isNaN(Number(v)) ? null : Number(v));

/**
 * Incidents measured against TWO recovery targets per affected asset:
 *  - the asset's resolution SLA (ASSET.SLAResolutionHours), and
 *  - the Recovery Time Objective from the asset's BIA entry (BIAENTRY.RTO).
 * Both in hours; an incident breaches a target when its Duration exceeds it.
 */
export function incidentSlaView(tenant: number | null): SlaView {
  const xi = getDb("XINCIDENT");
  const xo = getDb("XORCISM");
  const empty: TargetSummary & { avg: number | null } = { evaluated: 0, met: 0, breached: 0, breachRate: 0, noTarget: 0, avg: null };
  const ic = cols("XINCIDENT", "INCIDENT");
  if (!ic.size || !cols("XINCIDENT", "INCIDENTFORASSET").size) {
    return { rows: [], summary: { links: 0, noDuration: 0, avgDuration: null, sla: { ...empty }, rto: { ...empty } } };
  }
  const sel = (c: string, alias: string): string => (ic.has(c) ? `i."${c}"` : "NULL") + ` AS ${alias}`;
  const links = xi.prepare(`
    SELECT fa.AssetID AS aid, i.IncidentID AS iid,
           ${sel("IncidentName", "name")}, ${sel("Severity", "sev")},
           ${sel("Duration", "dur")}, ${sel("start_datetime", "st")}, ${sel("end_datetime", "en")},
           ${sel("TenantID", "tid")}
    FROM INCIDENTFORASSET fa JOIN INCIDENT i ON i.IncidentID = fa.IncidentID
    WHERE fa.AssetID IS NOT NULL
  `).all() as Record<string, unknown>[];

  const ac = cols("XORCISM", "ASSET");
  const slaCol = ac.has("SLAResolutionHours") ? `"SLAResolutionHours"` : "NULL";
  const assets = xo.prepare(`SELECT AssetID AS aid, AssetName AS name, ${slaCol} AS sla, TenantID AS tid FROM ASSET`).all() as Record<string, unknown>[];
  const aMap = new Map(assets.map((a) => [Number(a.aid), a]));

  // BIA RTO (hours) per asset, keyed by AssetID and by AssetName (BIAENTRY may link by either).
  // Strictest (minimum positive) RTO wins when several BIA entries cover the same asset.
  const rtoById = new Map<number, number>();
  const rtoByName = new Map<string, number>();
  if (cols("XORCISM", "BIAENTRY").size) {
    const bias = xo.prepare(`SELECT AssetID AS aid, AssetName AS name, RTO AS rto FROM BIAENTRY`).all() as Record<string, unknown>[];
    for (const b of bias) {
      const rto = numOf(b.rto);
      if (rto == null || rto <= 0) continue;
      if (b.aid != null) { const k = Number(b.aid); rtoById.set(k, Math.min(rtoById.get(k) ?? Infinity, rto)); }
      if (b.name) { const k = String(b.name).toLowerCase(); rtoByName.set(k, Math.min(rtoByName.get(k) ?? Infinity, rto)); }
    }
  }

  const rows: SlaRow[] = [];
  for (const l of links) {
    if (tenant != null && numOf(l.tid) !== tenant) continue; // tenant isolation (legacy null-tenant only to super-admin)
    const a = aMap.get(Number(l.aid));
    const assetName = (a?.name as string) || `#${l.aid}`;
    let dur = numOf(l.dur);
    if (dur == null) dur = hoursBetween(l.st as string, l.en as string); // fallback: end − start
    const sla = a ? numOf(a.sla) : null;
    const rto = rtoById.get(Number(l.aid)) ?? rtoByName.get(assetName.toLowerCase()) ?? null;
    const s = evalTarget(dur, sla);
    const r = evalTarget(dur, rto);
    rows.push({
      incidentId: Number(l.iid),
      incidentName: (l.name as string) || `#${l.iid}`,
      severity: (l.sev as string) ?? null,
      assetId: Number(l.aid),
      assetName,
      duration: dur,
      slaHours: sla, slaStatus: s.status, slaOverage: s.overage,
      rtoHours: rto, rtoStatus: r.status, rtoOverage: r.overage,
    });
  }
  // worst first: a breach on either target floats to the top (by largest overage)
  const sev = (st: SlaStatus): number => (st === "breached" ? 0 : st === "no-duration" ? 1 : st === "no-target" ? 2 : 3);
  rows.sort((x, y) =>
    (Math.min(sev(x.slaStatus), sev(x.rtoStatus)) - Math.min(sev(y.slaStatus), sev(y.rtoStatus)))
    || (Math.max(y.slaOverage ?? -1e9, y.rtoOverage ?? -1e9) - Math.max(x.slaOverage ?? -1e9, x.rtoOverage ?? -1e9)));

  const avg = (xs: number[]): number | null => (xs.length ? xs.reduce((s, v) => s + v, 0) / xs.length : null);
  const summarize = (get: (r: SlaRow) => { status: SlaStatus; target: number | null }): TargetSummary & { avg: number | null } => {
    const ev = rows.filter((r) => { const s = get(r).status; return s === "met" || s === "breached"; });
    const breached = ev.filter((r) => get(r).status === "breached").length;
    return {
      evaluated: ev.length, met: ev.length - breached, breached,
      breachRate: ev.length ? breached / ev.length : 0,
      noTarget: rows.filter((r) => get(r).status === "no-target").length,
      avg: avg(ev.map((r) => get(r).target!).filter((v) => v != null)),
    };
  };
  return {
    rows,
    summary: {
      links: rows.length,
      noDuration: rows.filter((r) => r.duration == null).length,
      avgDuration: avg(rows.filter((r) => r.duration != null).map((r) => r.duration!)),
      sla: summarize((r) => ({ status: r.slaStatus, target: r.slaHours })),
      rto: summarize((r) => ({ status: r.rtoStatus, target: r.rtoHours })),
    },
  };
}
