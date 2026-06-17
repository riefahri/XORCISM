/**
 * ransomware.ts — Ransomware-to-$ scenario simulator (the security↔business bridge).
 *
 * Replays a real ATT&CK ransomware group's TTPs against the asset estate and the
 * kill chain, then quantifies the dollar impact with a transparent FAIR-style model:
 *   SLE = primary loss (business value at risk) + ransom demand + recovery/IR cost
 *   ALE = SLE × ARO (annual rate, bumped by internet exposure + KEV-listed exposures)
 *   residual SLE = with offline backups + segmentation (don't pay, contain the blast radius)
 * Plus the D3FEND countermeasures that break the group's techniques. Every number is
 * shown with its assumption so it's defensible to a CFO.
 */
import { getDb } from "./db";
import { killChainGraph } from "./db";
import { topExposures } from "./fusion";

export interface RansomGroup { attackId: string; name: string; techniques: number }

/** ATT&CK groups that wield T1486 (Data Encrypted for Impact) — ransomware-capable adversaries. */
export function ransomwareGroups(): RansomGroup[] {
  try {
    const xt = getDb("XTHREAT");
    return xt.prepare(
      `SELECT g.AttackID attackId, g.Name name, COUNT(DISTINCT te.AttackID) techniques
       FROM ATTACKGROUP g
       JOIN ATTACKRELATIONSHIP r ON r.SourceStixID=g.StixID
       JOIN ATTACKTECHNIQUE te ON te.StixID=r.TargetStixID
       WHERE g.StixID IN (
         SELECT g2.StixID FROM ATTACKGROUP g2
         JOIN ATTACKRELATIONSHIP r2 ON r2.SourceStixID=g2.StixID
         JOIN ATTACKTECHNIQUE te2 ON te2.StixID=r2.TargetStixID
         WHERE te2.AttackID LIKE 'T1486%')
       GROUP BY g.AttackID, g.Name ORDER BY techniques DESC LIMIT 30`
    ).all() as RansomGroup[];
  } catch { return []; }
}

export interface RansomScenario {
  group: { attackId: string; name: string } | null;
  techniques: number; hasEncryption: boolean; hasInhibitRecovery: boolean;
  phases: { name: string; covered: boolean }[]; phasesCovered: number; phasesTotal: number;
  impacted: { assetId: number; name: string; value: number }[];
  currency: string;
  primaryLoss: number; ransom: number; recovery: number; sle: number; aro: number; ale: number; residualSle: number;
  controls: { name: string; source: string; effect: string }[];
  assumptions: string[];
}

function groupUsesTechnique(attackId: string, pattern: string): boolean {
  try {
    const xt = getDb("XTHREAT");
    return !!xt.prepare(
      `SELECT 1 FROM ATTACKGROUP g JOIN ATTACKRELATIONSHIP r ON r.SourceStixID=g.StixID
       JOIN ATTACKTECHNIQUE te ON te.StixID=r.TargetStixID
       WHERE g.AttackID=? AND te.AttackID LIKE ? LIMIT 1`
    ).get(attackId, pattern);
  } catch { return false; }
}

function d3fendControls(attackId: string): { name: string; source: string; effect: string }[] {
  try {
    const xt = getDb("XTHREAT");
    const rows = xt.prepare(
      `SELECT DISTINCT dt.Name name FROM ATTACKGROUP g
       JOIN ATTACKRELATIONSHIP r ON r.SourceStixID=g.StixID
       JOIN ATTACKTECHNIQUE te ON te.StixID=r.TargetStixID
       JOIN D3FENDATTACKMAP m ON m.AttackID = te.AttackID
       JOIN D3FENDTECHNIQUE dt ON dt.D3FENDID = m.D3FENDID
       WHERE g.AttackID=? AND dt.Name IS NOT NULL AND dt.Name<>'' LIMIT 6`
    ).all(attackId) as { name: string }[];
    return rows.map((r) => ({ name: r.name, source: "D3FEND", effect: "counters a technique this group uses" }));
  } catch { return []; }
}

const money = (n: number) => Math.round(n);

export function ransomwareScenario(tenant: number | null, groupRef?: string | null): RansomScenario {
  const xo = getDb("XORCISM");
  // resolve the group via the kill-chain engine (reused) — default to the richest ransomware group
  let ref = groupRef && groupRef.trim() ? groupRef.trim() : (ransomwareGroups()[0]?.attackId || null);
  let kc: ReturnType<typeof killChainGraph> | null = null;
  try { kc = killChainGraph(ref); } catch { kc = null; }
  const group = kc?.group ? { attackId: kc.group.attackId, name: kc.group.name } : null;
  const attackId = group?.attackId || "";
  const phases = (kc?.phases || []).map((p: any) => ({ name: p.name, covered: (p.used?.length || 0) > 0 }));
  const phasesCovered = phases.filter((p) => p.covered).length;
  const hasEncryption = attackId ? groupUsesTechnique(attackId, "T1486%") : false;
  const hasInhibitRecovery = attackId ? (groupUsesTechnique(attackId, "T1490%") || groupUsesTechnique(attackId, "T1489%")) : false;

  // blast radius = the valued estate ransomware would encrypt (tenant-scoped)
  // Dollar value per asset: FinancialValue ($) preferred, else BusinessValue, else RiskScore.
  // (FinancialValue/BusinessValue columns are stored as text/REAL → CAST to REAL.)
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tenantClause = tenant != null && aCols.has("TenantID") ? 'AND ("TenantID" = ? OR "TenantID" IS NULL)' : "";
  const args: unknown[] = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  const impacted = (xo.prepare(
    `SELECT AssetID assetId, AssetName name,
            CAST(COALESCE(FinancialValue,'') AS REAL) fin, CAST(COALESCE(BusinessValue,'') AS REAL) biz, CAST(COALESCE(RiskScore,0) AS REAL) risk
     FROM ASSET
     WHERE (CAST(COALESCE(FinancialValue,'') AS REAL) > 0 OR CAST(COALESCE(BusinessValue,'') AS REAL) > 0) ${tenantClause}
     LIMIT 500`
  ).all(...args) as { assetId: number; name: string; fin: number; biz: number; risk: number }[])
    .map((a) => ({ assetId: a.assetId, name: a.name, value: a.fin > 0 ? a.fin : (a.biz > 0 ? a.biz : a.risk) }))
    .filter((a) => a.value > 0).sort((x, y) => y.value - x.value);

  const primaryLoss = impacted.reduce((s, a) => s + a.value, 0);
  const ransom = primaryLoss > 0 ? money(Math.max(50000, primaryLoss * 0.12)) : 0;
  const recovery = money(primaryLoss * 0.30);
  const sle = primaryLoss + ransom + recovery;

  // ARO: base + internet exposure + KEV-listed exposure
  let exposed = false, kev = false;
  try { exposed = !!xo.prepare(`SELECT 1 FROM ASSET WHERE (websiteurl IS NOT NULL AND websiteurl<>'') ${tenant != null && aCols.has("TenantID") ? 'AND ("TenantID"=? OR "TenantID" IS NULL)' : ""} LIMIT 1`).get(...(tenant != null && aCols.has("TenantID") ? [tenant] : [])); } catch { /* */ }
  try { kev = topExposures(tenant, 30).results.some((t) => t.kev); } catch { /* */ }
  const aro = Math.min(0.4, 0.12 + (exposed ? 0.06 : 0) + (kev ? 0.06 : 0));
  const ale = money(sle * aro);
  // residual with offline backups + segmentation + MFA: don't pay, contain spread, faster recovery
  const residualSle = money(primaryLoss * 0.5 + recovery * 0.5);

  const controls: { name: string; source: string; effect: string }[] = [
    { name: "Offline, immutable, tested backups", source: "best-practice", effect: hasEncryption ? "restore instead of paying — breaks T1486 impact" : "fast recovery if data is encrypted" },
    { name: "Network segmentation / least privilege", source: "best-practice", effect: "limits lateral movement → shrinks the blast radius" },
    { name: "MFA on all external/remote access", source: "best-practice", effect: "blocks the common initial-access vector" },
    { name: "EDR + patch KEV-listed CVEs", source: "best-practice", effect: "counters exploitation & execution" },
    ...d3fendControls(attackId),
  ];

  return {
    group, techniques: kc?.coverage?.techniques || 0, hasEncryption, hasInhibitRecovery,
    phases, phasesCovered, phasesTotal: phases.length, impacted, currency: process.env.XORCISM_CURRENCY || "USD",
    primaryLoss: money(primaryLoss), ransom, recovery, sle: money(sle), aro: Math.round(aro * 100) / 100, ale, residualSle,
    controls,
    assumptions: [
      "Primary loss = sum of in-scope assets' FinancialValue ($; fallback BusinessValue/RiskScore) — value at risk if encrypted/down.",
      "Ransom demand ≈ 12% of primary loss (floor $50k); recovery/IR ≈ 30% of primary loss.",
      `ARO = 0.12 base${exposed ? " + 0.06 internet-exposed" : ""}${kev ? " + 0.06 KEV-listed exposure" : ""} = ${Math.round(aro * 100) / 100}.`,
      "Residual = offline backups (no ransom paid) + segmentation (≈50% smaller blast radius) + halved recovery.",
    ],
  };
}
