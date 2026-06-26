/**
 * insurance.ts — Cyber Insurance Readiness cockpit (/insurance-readiness).
 *
 * The *insurer's* view of the estate — the third stakeholder lens alongside the defender's
 * EnterpriseRiskScore and the attacker's Adversary Opportunity Index. Cyber-insurance underwriting
 * (and the "ransomware supplemental application" every renewal now requires) gates coverage and
 * premium on a fairly standard control checklist: MFA, backups, EDR/monitoring, PAM, timely patching,
 * a tested IR plan, segmentation, awareness, email security, vendor risk, encryption.
 *
 * This module maps each of those required controls to XORCISM's LIVE signals (asset / identity /
 * patch / crisis inventories + control assurance + attack-path) and produces a renewal-readiness
 * score, a gap worklist ordered by underwriting weight, and the controls an insurer will still want
 * self-attested. Read-only and compute-only (no new table), mirroring assurance.ts.
 */
import { getDb } from "./db";
import { assetInventory } from "./assets";
import { identityInventory } from "./identities";
import { patchInventory } from "./patchmgmt";
import { crisisInventory } from "./crisis";
import { controlAssurance } from "./assurance";
import { attackPathGraph } from "./attackpath";
import { ransomwareScenario } from "./ransomware";

const safe = <T>(fn: () => T, dflt: T): T => { try { return fn(); } catch { return dflt; } };
const clamp = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));
type Status = "met" | "partial" | "gap" | "attest";
const band = (s: number): Status => (s >= 80 ? "met" : s >= 50 ? "partial" : "gap");

export interface InsControl {
  id: string; name: string; category: string; weight: number; insurerWhy: string;
  status: Status; score: number | null; metric: string; evidence: string[];
}
export interface InsuranceReadiness {
  score: number; grade: string; verdict: string;
  controls: InsControl[]; attest: InsControl[];
  summary: { met: number; partial: number; gap: number; attestPending: number; critical: number };
  worklist: { name: string; insurerWhy: string; metric: string; weight: number; impact: number }[];
  evaluatedAt: string;
}

const grade = (s: number): string => (s >= 85 ? "A" : s >= 70 ? "B" : s >= 55 ? "C" : s >= 40 ? "D" : "F");
const verdict = (s: number): string =>
  s >= 85 ? "Strong — favourable terms likely" : s >= 70 ? "Insurable — minor remediations before renewal"
  : s >= 55 ? "Conditional — underwriters will require fixes" : s >= 40 ? "At risk — coverage gaps / higher premium likely"
  : "Likely declined / heavily surcharged without remediation";

/** Compute the cyber-insurance readiness for a tenant from live XORCISM signals. Pass an already-built
 *  attack-path graph (e.g. from boardReport) to avoid recomputing it. */
export function insuranceReadiness(tenant: number | null, graph?: any): InsuranceReadiness {
  const A = safe(() => assetInventory(tenant).summary as any, null);
  const I = safe(() => identityInventory(tenant).summary as any, null);
  const P = safe(() => patchInventory(tenant).summary as any, null);
  const C = safe(() => crisisInventory(tenant).summary as any, null);
  const AS = safe(() => controlAssurance(tenant), null as any);
  const ap = graph ?? safe(() => attackPathGraph(tenant), null as any);
  const detScore = AS ? (AS.controls.find((c: any) => c.id === "detection")?.score ?? 0) : 0;

  const ctl = (id: string, name: string, category: string, weight: number, insurerWhy: string, score: number | null, metric: string, evidence: string[]): InsControl =>
    ({ id, name, category, weight, insurerWhy, status: score == null ? "attest" : band(score), score: score == null ? null : clamp(score), metric, evidence });

  const controls: InsControl[] = [];

  // 1. MFA — the single biggest underwriting gate
  controls.push(ctl("mfa", "Multi-factor authentication", "Identity", 10,
    "MFA on email, remote access and privileged accounts is a hard requirement for most carriers.",
    I ? (I.mfaGaps === 0 ? 100 : Math.max(0, 100 - I.mfaGaps * 15)) : null,
    I ? `${I.mfaGaps} identity/-ies without MFA` : "no identity inventory", I ? [`${I.total} identities, ${I.privileged} privileged`] : []));

  // 2. PAM — privileged & orphaned accounts
  controls.push(ctl("pam", "Privileged access management", "Identity", 8,
    "Tightly controlled, monitored privileged access limits ransomware blast radius.",
    I ? Math.max(0, 100 - (I.orphaned * 12) - Math.max(0, I.privileged - 5) * 3) : null,
    I ? `${I.privileged} privileged, ${I.orphaned} orphaned` : "no identity inventory", []));

  // 3. Backups — secure, tested, offline (3-2-1)
  controls.push(ctl("backups", "Secure, tested backups (3-2-1)", "Resilience", 10,
    "Immutable/offline tested backups are the primary ransomware recovery control underwriters check.",
    A ? (A.unbackedCritical === 0 ? 100 : Math.max(0, 100 - A.unbackedCritical * 20)) : null,
    A ? `${A.unbackedCritical} critical asset(s) with no backup plan` : "no asset inventory", A ? [`${A.crownJewels} crown jewels`] : []));

  // 4. Patch & vulnerability management
  controls.push(ctl("patch", "Timely patch & vulnerability management", "Vuln mgmt", 9,
    "Open KEV-listed and critical vulnerabilities are routinely cited in declinations.",
    (P || A) ? Math.min(P ? (P.coverage ?? 80) : 80, (P && P.kevUnpatched ? Math.max(0, 90 - P.kevUnpatched * 15) : 100), (A ? (A.withCriticalVulns === 0 ? 100 : Math.max(0, 100 - A.withCriticalVulns * 10)) : 100)) : null,
    `${P ? P.kevUnpatched : "?"} KEV unpatched · ${A ? A.withCriticalVulns : "?"} assets with critical vulns`, P ? [`patch coverage ${P.coverage ?? "?"}%`] : []));

  // 5. Endpoint & network monitoring (EDR / SIEM / logging)
  controls.push(ctl("monitoring", "Endpoint & network monitoring (EDR/SIEM)", "Detection", 9,
    "24×7 detection & logging is expected; absence pushes premium up or coverage down.",
    AS ? detScore : null, `${detScore}/100 baseline ATT&CK detection coverage`, AS ? [`assurance: ${AS.stats.proven}/${AS.stats.total} controls proven`] : []));

  // 6. Network segmentation
  controls.push(ctl("segmentation", "Network segmentation", "Architecture", 7,
    "Flat networks let ransomware spread; segmentation limits the insured loss.",
    ap ? (ap.stats.pathsFound === 0 ? (ap.stats.jewels ? 90 : 70) : Math.max(0, 90 - ap.stats.pathsFound * 8)) : null,
    ap ? `${ap.stats.pathsFound} attack path(s) to crown jewels` : "no attack-path data", []));

  // 7. Incident response plan — documented & tested
  controls.push(ctl("ir", "Incident response plan (tested)", "Resilience", 8,
    "A documented, exercised IR plan is a standard supplemental question.",
    C ? (C.exercises > 0 ? Math.min(100, C.readinessScore ?? 60) : 30) : null,
    C ? `${C.exercises} exercise(s), readiness ${C.readinessScore ?? "?"}/100` : "no crisis data", []));

  // 8. Business continuity & DR
  controls.push(ctl("bcdr", "Business continuity & disaster recovery", "Resilience", 6,
    "BC/DR plans and RTO/RPO evidence affect business-interruption coverage.",
    C ? Math.min(100, (C.scenarioCoverage ?? 0)) : null,
    C ? `${C.scenarioCoverage ?? 0}% scenario coverage` : "no crisis data", []));

  // 9-12. Controls XORCISM can't yet prove from telemetry → underwriter self-attestation
  const attest: InsControl[] = [
    ctl("awareness", "Security awareness & phishing training", "People", 5, "Annual training + phishing simulation reduce the #1 ransomware entry vector.", null, "self-attested (see /security-awareness)", []),
    ctl("email", "Email filtering & anti-phishing", "Detection", 5, "Advanced email filtering / DMARC is a common supplemental requirement.", null, "self-attested", []),
    ctl("tprm", "Third-party / supply-chain risk", "Vendor", 5, "Vendor breaches drive aggregation risk; carriers ask about TPRM.", null, "self-attested (see /tprm)", []),
    ctl("encryption", "Encryption at rest & in transit", "Data", 5, "Encryption of sensitive data limits breach-notification and liability exposure.", null, "self-attested", []),
  ];

  const scored = controls.filter((c) => c.score != null);
  const wsum = scored.reduce((s, c) => s + c.weight, 0) || 1;
  const score = clamp(scored.reduce((s, c) => s + (c.score as number) * c.weight, 0) / wsum);

  const worklist = controls.filter((c) => c.status === "gap" || c.status === "partial")
    .map((c) => ({ name: c.name, insurerWhy: c.insurerWhy, metric: c.metric, weight: c.weight, impact: Math.round(c.weight * (100 - (c.score as number)) / 100) }))
    .sort((a, b) => b.impact - a.impact);

  const summary = {
    met: controls.filter((c) => c.status === "met").length,
    partial: controls.filter((c) => c.status === "partial").length,
    gap: controls.filter((c) => c.status === "gap").length,
    attestPending: attest.length,
    critical: controls.filter((c) => c.status === "gap" && c.weight >= 9).length,
  };

  return { score, grade: grade(score), verdict: verdict(score), controls, attest, summary, worklist, evaluatedAt: new Date().toISOString() };
}

// ─── Policy record + program view (carrier / limit / renewal + coverage adequacy) ────────────────

export interface InsurancePolicy {
  carrier: string; policyNumber: string; coverageLimit: number; retention: number;
  premium: number; currency: string; renewalDate: string; status: string; notes: string;
}

export function ensureInsuranceTables(): void {
  getDb("XORCISM").prepare(
    `CREATE TABLE IF NOT EXISTS CYBERINSURANCEPOLICY (
       PolicyID INTEGER PRIMARY KEY, TenantID INTEGER, Carrier TEXT, PolicyNumber TEXT,
       CoverageLimit REAL, Retention REAL, Premium REAL, Currency TEXT, RenewalDate TEXT,
       Status TEXT, Notes TEXT, CreatedDate TEXT, UpdatedDate TEXT )`
  ).run();
}

export function getInsurancePolicy(tenant: number | null): InsurancePolicy | null {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    const r = xo.prepare(`SELECT * FROM CYBERINSURANCEPOLICY WHERE ${w} ORDER BY PolicyID DESC LIMIT 1`).get(...a) as any;
    if (!r) return null;
    return { carrier: r.Carrier || "", policyNumber: r.PolicyNumber || "", coverageLimit: Number(r.CoverageLimit) || 0, retention: Number(r.Retention) || 0, premium: Number(r.Premium) || 0, currency: r.Currency || "USD", renewalDate: r.RenewalDate || "", status: r.Status || "Active", notes: r.Notes || "" };
  } catch { return null; }
}

/** Upsert the tenant's (single current) cyber-insurance policy. */
export function saveInsurancePolicy(tenant: number | null, p: Partial<InsurancePolicy>): { ok: boolean } {
  ensureInsuranceTables();
  const xo = getDb("XORCISM");
  const now = new Date().toISOString();
  const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
  const a: unknown[] = tenant != null ? [tenant] : [];
  const existing = xo.prepare(`SELECT PolicyID FROM CYBERINSURANCEPOLICY WHERE ${w} ORDER BY PolicyID DESC LIMIT 1`).get(...a) as { PolicyID: number } | undefined;
  const vals = [p.carrier ?? "", p.policyNumber ?? "", Number(p.coverageLimit) || 0, Number(p.retention) || 0, Number(p.premium) || 0, p.currency ?? "USD", p.renewalDate ?? "", p.status ?? "Active", p.notes ?? ""];
  if (existing) {
    xo.prepare("UPDATE CYBERINSURANCEPOLICY SET Carrier=?,PolicyNumber=?,CoverageLimit=?,Retention=?,Premium=?,Currency=?,RenewalDate=?,Status=?,Notes=?,UpdatedDate=? WHERE PolicyID=?").run(...vals, now, existing.PolicyID);
  } else {
    const id = (xo.prepare("SELECT COALESCE(MAX(PolicyID),0)+1 n FROM CYBERINSURANCEPOLICY").get() as { n: number }).n;
    xo.prepare("INSERT INTO CYBERINSURANCEPOLICY (PolicyID,TenantID,Carrier,PolicyNumber,CoverageLimit,Retention,Premium,Currency,RenewalDate,Status,Notes,CreatedDate,UpdatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").run(id, tenant, ...vals, now, now);
  }
  return { ok: true };
}

export interface InsuranceProgram {
  policy: InsurancePolicy | null;
  coverage: { limit: number; modeledLoss: number | null; currency: string; adequacy: "covered" | "underinsured" | "unknown"; gap: number; source: string };
  renewal: { date: string; daysToRenewal: number | null; status: "ok" | "due-soon" | "overdue" | "unknown" };
}

/** The policy + coverage adequacy (limit vs the modeled single-event ransomware loss) + renewal countdown. */
export function insuranceProgram(tenant: number | null): InsuranceProgram {
  const policy = getInsurancePolicy(tenant);
  const rs = safe(() => ransomwareScenario(tenant) as any, null);
  const modeledLoss = rs && Number.isFinite(rs.sle) ? Math.round(rs.sle) : null;
  const limit = policy?.coverageLimit ?? 0;
  const currency = policy?.currency || rs?.currency || "USD";
  const adequacy: "covered" | "underinsured" | "unknown" = (!limit || modeledLoss == null) ? "unknown" : limit >= modeledLoss ? "covered" : "underinsured";
  const gap = adequacy === "underinsured" ? (modeledLoss as number) - limit : 0;

  let daysToRenewal: number | null = null;
  let rstatus: "ok" | "due-soon" | "overdue" | "unknown" = "unknown";
  if (policy?.renewalDate) {
    const d = Date.parse(policy.renewalDate);
    if (Number.isFinite(d)) {
      daysToRenewal = Math.ceil((d - Date.now()) / 86_400_000);
      rstatus = daysToRenewal < 0 ? "overdue" : daysToRenewal <= 45 ? "due-soon" : "ok";
    }
  }
  return {
    policy,
    coverage: { limit, modeledLoss, currency, adequacy, gap, source: "modeled single-event ransomware loss (FAIR / ransomware.ts)" },
    renewal: { date: policy?.renewalDate || "", daysToRenewal, status: rstatus },
  };
}
