/**
 * riskscore.ts — Periodic computation of the per-ASSET risk score.
 *
 * A loop (every 30 s) recomputes each ASSET's RiskScore, updates
 * ASSET.RiskScore and logs the change in ASSETRISKSCORE (a record is
 * added at the first evaluation then on every value CHANGE — this avoids
 * filling the history table with an identical row every 30 s).
 *
 * Scoring (integer, default 0, never negative):
 *   • If the asset has ≥ 1 uncorrected ASSETVULNERABILITY (AssetVulnerabilityStatusID = 0):
 *       – per vulnerability: +5 ; +10 if VULNERABILITY.KEV > 0 ; +50 if Exploited = 1 ;
 *         +10 if EasilyExploitable = 1 ; +50 if ASSETVULNERABILITY.TotalControl = 1
 *       – asset factors × criticality value (AssetCriticalityLevel → 0.5/0.7/1/2/3/5):
 *         +10× TaskCriticalAsset, +50× PublicFacing, +10× DefenseCriticalAsset,
 *         +10× managedbythirdparty, +10× hostedbythirdparty
 *       – +10 if isEncrypted = 0 ; + 0.01 × FinancialValue
 *   • Hardened (ASSETOVALDEFINITION.Status ∈ {Applied,Patched,Hardened,Compliant}) ...... −10
 *   • per valid ASSETTHREAT (ValidFrom/ValidUntil window) ........... + Criticity × 5
 *   • per "Unresolved/Open" and valid ASSETAUDITFINDING ............ + Criticity × 5
 *   • per open INCIDENTFORASSET (Status ∉ {Closed, Resolved}, XINCIDENT database):
 *         + Criticity × 3 ; +20 if Compromised = 1
 *   • if ASSET.PersonID > 0: per "Completed" and valid TRAININGFORPERSON .. −5
 *
 * Validity window: a NULL/empty bound is treated as "unbounded"
 * (empty ValidFrom = already started; empty ValidUntil = no expiry). Date
 * comparisons use the current date (ISO 'YYYY-MM-DD').
 */
import { getDb } from "./db";
import * as xid from "./xid";

const nowTs = (): string => new Date().toISOString().replace("T", " ").slice(0, 19);
const today = (): string => new Date().toISOString().slice(0, 10);

/** Robust conversion to number (NULL / non-numeric text → 0). */
function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Numeric criticality value of an asset (exposure multiplier), based on
 * ASSET.AssetCriticalityLevel (text label or numeric value 0..5). Default 0.
 */
function criticalityValue(raw: unknown): number {
  switch (String(raw ?? "").trim().toLowerCase()) {
    case "very low": case "0": return 0.5;
    case "low": case "1": return 0.7;
    case "medium": case "moderate": case "2": return 1;
    case "high": case "3": return 2;
    case "very high": case "4": return 3;
    case "critical": case "5": return 5;
    default: return 0;
  }
}

export interface RiskComponents {
  vulnerabilities: number; // +5/vuln + KEV/Exploited/EasilyExploitable/TotalControl
  assetFactors: number;    // criticality × exposure + encryption + financial value
  hardening: number;       // −10 if hardened (ASSETOVALDEFINITION)
  threats: number;
  findings: number;
  incidents: number;
  training: number;
  total: number;           // integer, ≥ 0
}

export class AssetRiskScoreCalculator {
  /**
   * Computes (without writing anything) an asset's risk score and the breakdown by
   * category. `d` = current date (ISO); lets you pin the reference for a batch.
   */
  compute(assetId: number, d: string = today()): RiskComponents {
    const xo = getDb("XORCISM");
    const asset = xo
      .prepare(
        'SELECT AssetCriticalityLevel, TaskCriticalAsset, DefenseCriticalAsset, ' +
          'managedbythirdparty, hostedbythirdparty, isEncrypted, PublicFacing, ' +
          'PersonID, FinancialValue FROM "ASSET" WHERE AssetID = ?'
      )
      .get(assetId) as Record<string, unknown> | undefined;

    const c: RiskComponents = {
      vulnerabilities: 0, assetFactors: 0, hardening: 0,
      threats: 0, findings: 0, incidents: 0, training: 0, total: 0,
    };
    if (!asset) return c;

    // — Uncorrected vulnerabilities (AssetVulnerabilityStatusID = 0 ; NULL treated
    //   as uncorrected) — XORCISM ↔ XVULNERABILITY join —
    const unpatched = xo
      .prepare(
        'SELECT VulnerabilityID, TotalControl FROM "ASSETVULNERABILITY" ' +
          'WHERE AssetID = ? AND COALESCE(CAST(AssetVulnerabilityStatusID AS INTEGER), 0) = 0'
      )
      .all(assetId) as { VulnerabilityID: number; TotalControl: unknown }[];

    if (unpatched.length) {
      const xv = getDb("XVULNERABILITY");
      const getVuln = xv.prepare(
        'SELECT KEV, Exploited, EasilyExploitable FROM "VULNERABILITY" WHERE VulnerabilityID = ?'
      );
      for (const av of unpatched) {
        c.vulnerabilities += 5; // each uncorrected vulnerability
        const v = getVuln.get(av.VulnerabilityID) as
          | { KEV: unknown; Exploited: unknown; EasilyExploitable: unknown }
          | undefined;
        if (v) {
          if (num(v.KEV) > 0) c.vulnerabilities += 10; // KEV catalogue
          if (num(v.Exploited) === 1) c.vulnerabilities += 50; // exploited
          if (num(v.EasilyExploitable) === 1) c.vulnerabilities += 10; // easily exploitable
        }
        if (num(av.TotalControl) === 1) c.vulnerabilities += 50; // total control
      }

      // — Asset factors (applied only if ≥ 1 uncorrected vulnerability) —
      const crit = criticalityValue(asset.AssetCriticalityLevel);
      if (num(asset.TaskCriticalAsset) === 1) c.assetFactors += 10 * crit;
      if (num(asset.PublicFacing) === 1) c.assetFactors += 50 * crit;
      if (num(asset.DefenseCriticalAsset) === 1) c.assetFactors += 10 * crit;
      if (num(asset.managedbythirdparty) === 1) c.assetFactors += 10 * crit;
      if (num(asset.hostedbythirdparty) === 1) c.assetFactors += 10 * crit;
      if (num(asset.isEncrypted) === 0) c.assetFactors += 10; // not encrypted
      const fv = num(asset.FinancialValue);
      if (asset.FinancialValue != null && fv !== 0) c.assetFactors += 0.01 * fv;
    }

    // — Hardening: −10 if ≥ 1 OVAL definition applied/patched/hardened/compliant —
    const hardened = xo
      .prepare(
        'SELECT 1 FROM "ASSETOVALDEFINITION" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) IN ('applied', 'patched', 'hardened', 'compliant') LIMIT 1"
      )
      .get(assetId);
    if (hardened) c.hardening -= 10;

    // — Active threats (validity window) — + Criticity × 5 per row —
    const threats = xo
      .prepare(
        'SELECT Criticity FROM "ASSETTHREAT" WHERE AssetID = ? ' +
          "AND (ValidFrom IS NULL OR ValidFrom = '' OR ValidFrom < ?) " +
          "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
      )
      .all(assetId, d, d) as { Criticity: unknown }[];
    for (const t of threats) c.threats += num(t.Criticity) * 5;

    // — Open/unresolved and valid audit findings — + Criticity × 5 per row —
    const findings = xo
      .prepare(
        'SELECT Criticity FROM "ASSETAUDITFINDING" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) IN ('unresolved', 'open') " +
          "AND (ValidFrom IS NULL OR ValidFrom = '' OR ValidFrom < ?) " +
          "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
      )
      .all(assetId, d, d) as { Criticity: unknown }[];
    for (const f of findings) c.findings += num(f.Criticity) * 5;

    // — Open incidents (XINCIDENT database) — + Criticity × 3 ; +20 if compromised —
    const incidents = getDb("XINCIDENT")
      .prepare(
        'SELECT Criticity, Compromised FROM "INCIDENTFORASSET" WHERE AssetID = ? ' +
          "AND LOWER(COALESCE(Status, '')) NOT IN ('closed', 'resolved')"
      )
      .all(assetId) as { Criticity: unknown; Compromised: unknown }[];
    for (const inc of incidents) {
      c.incidents += num(inc.Criticity) * 3;
      if (num(inc.Compromised) === 1) c.incidents += 20; // compromised asset
    }

    // — "Completed" and valid trainings of the responsible person (reduce) —
    const personId = num(asset.PersonID);
    if (personId > 0) {
      const completed = xo
        .prepare(
          'SELECT COUNT(*) AS n FROM "TRAININGFORPERSON" WHERE PersonID = ? ' +
            "AND LOWER(COALESCE(Status, '')) = 'completed' " +
            "AND (ValidUntil IS NULL OR ValidUntil = '' OR ValidUntil > ?)"
        )
        .get(personId, d) as { n: number };
      c.training -= num(completed.n) * 5;
    }

    const raw =
      c.vulnerabilities + c.assetFactors + c.hardening +
      c.threats + c.findings + c.incidents + c.training;
    c.total = Math.max(0, Math.round(raw)); // integer, never negative
    return c;
  }

  /**
   * Computes the score, updates ASSET.RiskScore and adds a row to
   * ASSETRISKSCORE (at the first evaluation then on every value change).
   * Returns the RiskScore.
   */
  computeAndRecord(assetId: number, d: string = today()): number {
    const score = this.compute(assetId, d).total;
    const xo = getDb("XORCISM");

    xo.prepare('UPDATE "ASSET" SET RiskScore = ? WHERE AssetID = ?').run(score, assetId);

    const last = xo
      .prepare(
        'SELECT RiskScore FROM "ASSETRISKSCORE" WHERE AssetID = ? ORDER BY AssetRiskScoreID DESC LIMIT 1'
      )
      .get(assetId) as { RiskScore: unknown } | undefined;

    if (!last || num(last.RiskScore) !== score) {
      const maxId = (
        xo.prepare('SELECT COALESCE(MAX(AssetRiskScoreID), 0) AS m FROM "ASSETRISKSCORE"').get() as {
          m: number;
        }
      ).m;
      xo.prepare(
        'INSERT INTO "ASSETRISKSCORE" (AssetRiskScoreID, AssetID, RiskScore, Date, ConfidenceLevel, TrustLevel) ' +
          "VALUES (?, ?, ?, ?, 3, 4)"
      ).run(maxId + 1, assetId, score, nowTs());
    }
    return score;
  }

  /** Recomputes all ASSETs (a single reference date for the batch). */
  recomputeAll(): number {
    const xo = getDb("XORCISM");
    const ids = (xo.prepare('SELECT AssetID FROM "ASSET"').all() as { AssetID: number }[]).map(
      (r) => r.AssetID
    );
    const d = today();
    let n = 0;
    const tx = xo.transaction(() => {
      for (const id of ids) {
        this.computeAndRecord(id, d);
        n++;
      }
    });
    tx();
    return n;
  }
}

export const riskScoreCalculator = new AssetRiskScoreCalculator();

// ── EnterpriseRiskScore (risk score aggregated per tenant) ────────────────────
//
// EnterpriseRiskScore (integer, default 0) for the current tenant:
//   • per finished AUDIT (AuditStatus ∈ {Completed, Closed, Finished}) ...... −5
//   • per tenant TRAININGFORPERSON .................................... −0.5
//   • + the latest RiskScore (most recent) of each tenant ASSET
//
// The fractional total (the −0.5s) is rounded to the nearest integer.

/** Computes (without writing anything) a tenant's EnterpriseRiskScore. */
export function computeEnterpriseRiskScore(tenantId: number | null): number {
  if (tenantId == null) return 0;
  let score = 0;

  // — Finished AUDITs (XCOMPLIANCE database): −5 each —
  const audits = getDb("XCOMPLIANCE")
    .prepare(
      'SELECT COUNT(*) AS n FROM "AUDIT" WHERE TenantID = ? ' +
        "AND LOWER(COALESCE(AuditStatus, '')) IN ('completed', 'closed', 'finished')"
    )
    .get(tenantId) as { n: number };
  score += num(audits.n) * -5;

  const xo = getDb("XORCISM");

  // — Tenant trainings (TRAININGFORPERSON): −0.5 each —
  const trainings = xo
    .prepare('SELECT COUNT(*) AS n FROM "TRAININGFORPERSON" WHERE TenantID = ?')
    .get(tenantId) as { n: number };
  score += num(trainings.n) * -0.5;

  // — Sum of the latest RiskScore (most recent) of each tenant ASSET —
  const assetSum = xo
    .prepare(
      'SELECT COALESCE(SUM(ars.RiskScore), 0) AS s FROM "ASSETRISKSCORE" ars ' +
        'JOIN "ASSET" a ON a.AssetID = ars.AssetID ' +
        'WHERE a.TenantID = ? AND ars.AssetRiskScoreID = ' +
        '(SELECT MAX(x.AssetRiskScoreID) FROM "ASSETRISKSCORE" x WHERE x.AssetID = ars.AssetID)'
    )
    .get(tenantId) as { s: number };
  score += num(assetSum.s);

  return Math.round(score);
}

/**
 * Computes a tenant's EnterpriseRiskScore and records its history in RISKSCORE
 * (at the first evaluation then on every value change). Returns the score.
 */
export function recordEnterpriseRiskScore(tenantId: number): number {
  const score = computeEnterpriseRiskScore(tenantId);
  const xo = getDb("XORCISM");
  const last = xo
    .prepare('SELECT RiskScore FROM "RISKSCORE" WHERE TenantID = ? ORDER BY RiskScoreID DESC LIMIT 1')
    .get(tenantId) as { RiskScore: unknown } | undefined;
  if (!last || num(last.RiskScore) !== score) {
    const maxId = (
      xo.prepare('SELECT COALESCE(MAX(RiskScoreID), 0) AS m FROM "RISKSCORE"').get() as { m: number }
    ).m;
    xo.prepare(
      'INSERT INTO "RISKSCORE" (RiskScoreID, RiskScore, Date, TenantID, ConfidenceLevel) VALUES (?, ?, ?, ?, 3)'
    ).run(maxId + 1, score, nowTs(), tenantId);
  }
  return score;
}

/** Recomputes the EnterpriseRiskScore of all tenants. */
function recomputeAllEnterprise(): void {
  for (const t of xid.listTenants()) {
    try {
      recordEnterpriseRiskScore(t.TenantID);
    } catch (e) {
      console.warn(`[riskscore] tenant ${t.TenantID}: ${(e as Error).message}`);
    }
  }
}

let timer: NodeJS.Timeout | null = null;

/** Starts the recompute loop (every 30 s). Idempotent. */
export function startRiskScoreLoop(): void {
  if (timer) return;
  const tick = () => {
    try {
      riskScoreCalculator.recomputeAll(); // ASSETs first (fresh scores)
      recomputeAllEnterprise(); // then the per-tenant aggregate (reads ASSET scores)
    } catch (e) {
      console.warn(`[riskscore] tick: ${(e as Error).message}`);
    }
  };
  tick(); // first computation at startup
  timer = setInterval(tick, 30_000);
  if (typeof timer.unref === "function") timer.unref();
  console.log(
    "[riskscore] boucle démarrée (ASSET.RiskScore + EnterpriseRiskScore toutes les 30 s)"
  );
}
