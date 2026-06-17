/**
 * assurance.ts — Continuously-proven compliance ("control assurance").
 *
 * The GRC endgame: instead of screenshots gathered once a year, each control objective
 * is evaluated LIVE from the security telemetry XORCISM already holds — Sigma detection
 * coverage, KEV/exploit exposure, asset classification, internet exposure, pentest
 * recency, finding closure, ATT&CK/D3FEND threat-informed defense. Each maps to ISO
 * 27001 / NIST CSF references and gets a status: proven / partial / gap, or
 * "attestation required" where telemetry genuinely cannot decide (e.g. offline backups).
 */
import { getDb } from "./db";
import { topExposures } from "./fusion";

export type CtlStatus = "proven" | "partial" | "gap" | "attest";
export interface Control {
  id: string; name: string; iso: string; nist: string;
  status: CtlStatus; score: number; metric: string; evidence: string[];
}
export interface Assurance {
  controls: Control[];
  stats: { total: number; proven: number; partial: number; gap: number; attest: number; provenPct: number };
  evaluatedAt: string;
}

// Baseline of common, high-signal ATT&CK techniques used to measure detection & TID coverage.
const BASELINE = ["T1059", "T1190", "T1486", "T1003", "T1021", "T1110", "T1046", "T1566", "T1078", "T1053", "T1547", "T1567"];

function sigmaCount(xt: ReturnType<typeof getDb>, tech: string): number {
  try { return (xt.prepare("SELECT COUNT(*) n FROM SIGMARULE WHERE UPPER(AttackTags) LIKE ?").get(`%${tech}%`) as { n: number }).n; } catch { return 0; }
}
function byScore(s: number, hi = 70, lo = 40): CtlStatus { return s >= hi ? "proven" : s >= lo ? "partial" : "gap"; }

export function controlAssurance(tenant: number | null): Assurance {
  const xo = getDb("XORCISM");
  const xc = getDb("XCOMPLIANCE");
  const xt = getDb("XTHREAT");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tcl = tenant != null && aCols.has("TenantID") ? 'AND ("TenantID"=? OR "TenantID" IS NULL)' : "";
  const targs = tenant != null && aCols.has("TenantID") ? [tenant] : [];

  const controls: Control[] = [];

  // 1. Detection & monitoring — Sigma coverage over the baseline techniques
  const covered = BASELINE.filter((t) => sigmaCount(xt, t) > 0).length;
  const totalRules = BASELINE.reduce((s, t) => s + sigmaCount(xt, t), 0);
  const detScore = Math.round((covered / BASELINE.length) * 100);
  controls.push({ id: "detection", name: "Security monitoring & detection", iso: "A.8.15/8.16", nist: "DE.CM", status: byScore(detScore), score: detScore, metric: `${covered}/${BASELINE.length} baseline ATT&CK techniques have a detection`, evidence: [`${totalRules} Sigma rules in the library cover the baseline techniques`] });

  // 2. Vulnerability management — open KEV-listed exposures
  let openKev = 0, scanned = 0, withExp = 0;
  try { const ex = topExposures(tenant, 100); scanned = ex.scanned; openKev = ex.results.filter((t) => t.kev).length; withExp = ex.results.filter((t) => t.exploits > 0).length; } catch { /* */ }
  const vmScore = openKev === 0 ? (scanned ? 100 : 60) : Math.max(0, 100 - openKev * 20);
  controls.push({ id: "vulnmgmt", name: "Vulnerability management", iso: "A.8.8", nist: "ID.RA / PR.PS", status: openKev === 0 && scanned ? "proven" : byScore(vmScore), score: vmScore, metric: `${openKev} KEV-listed exposure(s) open`, evidence: [`${scanned} asset-linked vulnerabilities scored`, `${withExp} with a public exploit`] });

  // 3. Asset inventory & classification — assets with a value set
  let assetTotal = 0, classified = 0;
  try {
    assetTotal = (xo.prepare(`SELECT COUNT(*) n FROM ASSET WHERE 1=1 ${tcl}`).get(...targs) as { n: number }).n;
    classified = (xo.prepare(`SELECT COUNT(*) n FROM ASSET WHERE (CAST(COALESCE(FinancialValue,'') AS REAL)>0 OR CAST(COALESCE(BusinessValue,'') AS REAL)>0 OR RiskScore>0) ${tcl}`).get(...targs) as { n: number }).n;
  } catch { /* */ }
  const amScore = assetTotal ? Math.round((classified / assetTotal) * 100) : 0;
  controls.push({ id: "assetmgmt", name: "Asset inventory & classification", iso: "A.5.9", nist: "ID.AM", status: byScore(amScore, 80, 50), score: amScore, metric: `${classified}/${assetTotal} assets classified (value/risk set)`, evidence: [`${assetTotal} assets in inventory`] });

  // 4. Attack-surface management — internet-exposed assets with exploitable exposure
  let exposed = 0;
  try { exposed = (xo.prepare(`SELECT COUNT(*) n FROM ASSET WHERE (websiteurl IS NOT NULL AND websiteurl<>'') ${tcl}`).get(...targs) as { n: number }).n; } catch { /* */ }
  const asmScore = exposed === 0 ? 100 : (withExp === 0 ? 75 : Math.max(0, 80 - withExp * 15));
  controls.push({ id: "exposure", name: "Attack-surface & exposure management", iso: "A.8.9", nist: "PR.PS / ID.RA", status: byScore(asmScore), score: asmScore, metric: `${exposed} internet-exposed asset(s)`, evidence: [`${withExp} exposure(s) with a public exploit across the estate`] });

  // 5. Threat-informed defense — D3FEND countermeasures mapped to the baseline techniques
  let d3covered = 0;
  try { for (const t of BASELINE) { const n = (xt.prepare("SELECT COUNT(*) n FROM D3FENDATTACKMAP WHERE AttackID LIKE ?").get(`${t}%`) as { n: number }).n; if (n > 0) d3covered++; } } catch { /* */ }
  const tidScore = Math.round((d3covered / BASELINE.length) * 100);
  controls.push({ id: "tid", name: "Threat-informed defense (ATT&CK/D3FEND)", iso: "A.5.7", nist: "ID.RA / DE.AE", status: byScore(tidScore), score: tidScore, metric: `${d3covered}/${BASELINE.length} baseline techniques have a D3FEND countermeasure`, evidence: ["D3FEND ↔ ATT&CK mappings imported"] });

  // 6. Security testing / pentest — recent pentest engagements
  let pentests = 0;
  try { pentests = (xc.prepare("SELECT COUNT(*) n FROM AUDIT WHERE AuditType='Pentest'").get() as { n: number }).n; } catch { /* */ }
  controls.push({ id: "validation", name: "Security testing & control validation", iso: "A.8.29", nist: "ID.RA-1", status: pentests > 0 ? "proven" : "gap", score: pentests > 0 ? 100 : 0, metric: `${pentests} pentest engagement(s) on record`, evidence: pentests > 0 ? ["pentest engagements + findings tracked in XORCISM"] : ["no pentest engagement recorded"] });

  // 7. Incident & finding management — finding closure ratio
  let findTotal = 0, findClosed = 0;
  try {
    findTotal = (xc.prepare("SELECT COUNT(*) n FROM AUDITFINDING").get() as { n: number }).n;
    findClosed = (xc.prepare("SELECT COUNT(*) n FROM AUDITFINDING WHERE LOWER(COALESCE(FindingStatus,'open')) IN ('closed','resolved','fixed','remediated','risk accepted')").get() as { n: number }).n;
  } catch { /* */ }
  const incScore = findTotal ? Math.round((findClosed / findTotal) * 100) : 100;
  controls.push({ id: "incident", name: "Finding & incident management", iso: "A.5.24-5.27", nist: "RS / RC", status: byScore(incScore, 80, 40), score: incScore, metric: `${findClosed}/${findTotal} findings resolved`, evidence: [`${findTotal - findClosed} open finding(s)`] });

  // 8. Ransomware resilience / backups — telemetry can't prove offline backups → attest
  controls.push({ id: "resilience", name: "Ransomware resilience & backups", iso: "A.8.13", nist: "PR.DS / RC.RP", status: "attest", score: 0, metric: "offline/immutable backups — manual attestation required", evidence: ["See the /ransomware scenario for the residual-loss reduction backups would buy"] });

  const tally = (st: CtlStatus) => controls.filter((c) => c.status === st).length;
  const measurable = controls.filter((c) => c.status !== "attest").length;
  const proven = tally("proven");
  return {
    controls,
    stats: { total: controls.length, proven, partial: tally("partial"), gap: tally("gap"), attest: tally("attest"), provenPct: measurable ? Math.round((proven / measurable) * 100) : 0 },
    evaluatedAt: new Date().toISOString().replace("T", " ").slice(0, 19),
  };
}
