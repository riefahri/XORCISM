/**
 * auditpack.ts — Audit & Accreditation package: one traceable, evidence-cited, AI-narrated report that
 * assembles what XORCISM already holds into audit-ready documentation, covering four needs at once:
 *
 *   1. Audit & accreditation — control-implementation status + framework readiness + an evidence index,
 *      each control cited to live telemetry (control-assurance) → an accreditation/SSP-style section.
 *   2. Regulatory & compliance — configuration findings (cloud CIS) + the audit trail (XAUDITLOG) +
 *      control implementations, for adherence to frameworks (SOC 2 / ISO 27001 / NIST CSF).
 *   3. Cyber-risk management — security posture, control effectiveness, emerging risks (KEV/exploit/EPSS)
 *      and the risk register vs appetite, for decision-ready reporting.
 *   4. Business impact analysis — critical functions/assets with RTO/RPO/MTD and impact dimensions.
 *
 * The deterministic data is the source of truth (every figure recomputes from current data); the local AI
 * only narrates the executive summary from those figures (offline templated fallback). Exports to Markdown.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { controlAssurance } from "./assurance";
import { riskRegisterInventory, getRiskGovernance } from "./riskregister";
import { topExposures } from "./fusion";
import { listAudit } from "./xid";
import { computeBia, type BiaComputedRow } from "./bia";
import { resolveControlId } from "./oscalcatalog";
import { ollamaStatus, ollamaChat } from "./ai";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

export interface AuditPackage {
  generatedAt: string; tenant: number | null; ai: boolean; model: string; executiveSummary: string;
  accreditation: {
    provenPct: number; total: number; proven: number; partial: number; gap: number; attest: number;
    frameworks: { fw: string; label: string; readinessPct: number; proven: number; measurable: number }[];
    controls: { id: string; name: string; status: string; refs: string; metric: string; evidence: string[]; frameworks: { fw: string; ref: string }[] }[];
  };
  regulatory: {
    cloud: { pass: number; fail: number; byProvider: Record<string, { pass: number; fail: number }> };
    auditTrail: { at: string; user: string; action: string; resource: string; detail: string }[];
    auditTrailTotal: number;
  };
  risk: {
    topExposures: { ref: string; cvss: number | null; kev: boolean; exploits: number; epss: number | null; priority: number }[];
    register: { total: number; overAppetite: number; byLevel: Record<string, number> };
    appetite: { category: string; appetiteLevel: string; toleranceRank: number; rationale: string }[];
  };
  bia: {
    entries: { asset: string; criticality: string; rto: string; rpo: string; mtd: string; owner: string }[]; total: number; critical: number;
    computed: BiaComputedRow[]; computedTotal: number; computedCritical: number;
  };
  evidenceIndex: { name: string; date: string }[];
  trend: { at: string; provenPct: number }[];
}

export function buildAuditPackage(tenant: number | null): AuditPackage {
  const xo = getDb("XORCISM");
  const xc = getDb("XCOMPLIANCE");

  // 1 + 2 (controls) — control-assurance is the live control-implementation evidence
  const a = controlAssurance(tenant);
  const accreditation = {
    provenPct: a.stats.provenPct, total: a.stats.total, proven: a.stats.proven, partial: a.stats.partial, gap: a.stats.gap, attest: a.stats.attest,
    frameworks: a.frameworks,
    controls: a.controls.map((c) => ({ id: c.id, name: c.name, status: c.status, refs: (c.frameworks || []).map((f) => `${f.fw}:${f.ref}`).join(" · ") || `ISO ${c.iso} · NIST ${c.nist}`, metric: c.metric, evidence: c.evidence, frameworks: (c.frameworks || []).map((f) => ({ fw: f.fw, ref: f.ref })) })),
  };

  // 2 — regulatory adherence: configuration findings (cloud CIS) + the audit trail
  const cloud: AuditPackage["regulatory"]["cloud"] = { pass: 0, fail: 0, byProvider: {} };
  try {
    if (has(xo, "CLOUDFINDING")) {
      const tw = tenant != null ? "WHERE (TenantID=? OR TenantID IS NULL)" : "";
      const rows = xo.prepare(`SELECT Provider, Status FROM CLOUDFINDING ${tw}`).all(...(tenant != null ? [tenant] : [])) as { Provider: string; Status: string }[];
      for (const r of rows) {
        const p = r.Provider || "Cloud"; cloud.byProvider[p] = cloud.byProvider[p] || { pass: 0, fail: 0 };
        if (r.Status === "pass") { cloud.pass++; cloud.byProvider[p].pass++; }
        else if (r.Status === "fail") { cloud.fail++; cloud.byProvider[p].fail++; }
      }
    }
  } catch { /* */ }
  let auditTrail: AuditPackage["regulatory"]["auditTrail"] = [];
  let auditTrailTotal = 0;
  try {
    const rows = listAudit(40, tenant);
    auditTrail = rows.map((r) => ({ at: String((r as Record<string, unknown>).Timestamp ?? ""), user: String((r as Record<string, unknown>).Email ?? (r as Record<string, unknown>).UserID ?? "system"), action: String((r as Record<string, unknown>).Action ?? ""), resource: `${(r as Record<string, unknown>).ResourceType ?? ""}/${(r as Record<string, unknown>).ResourceKey ?? ""}`, detail: String((r as Record<string, unknown>).Detail ?? "") }));
    if (has(xo, "XAUDITLOG")) auditTrailTotal = (xo.prepare("SELECT COUNT(*) n FROM XAUDITLOG").get() as { n: number }).n;
  } catch { /* */ }

  // 3 — cyber-risk: emerging exposures + risk register vs appetite
  let topExp: AuditPackage["risk"]["topExposures"] = [];
  try { topExp = topExposures(tenant, 10).results.map((e) => ({ ref: (e as { ref?: string; cve?: string }).ref || (e as { cve?: string }).cve || "", cvss: (e as { cvss?: number | null }).cvss ?? null, kev: !!(e as { kev?: unknown }).kev, exploits: Number((e as { exploits?: number }).exploits) || 0, epss: (e as { epss?: number | null }).epss ?? null, priority: Number((e as { priority?: number }).priority) || 0 })); } catch { /* */ }
  const register = { total: 0, overAppetite: 0, byLevel: {} as Record<string, number> };
  try {
    const inv = riskRegisterInventory(tenant) as { summary?: { risks?: number; overAppetite?: number; byLevel?: Record<string, number> } };
    const s = inv.summary || {};
    register.total = Number(s.risks) || 0;
    register.overAppetite = Number(s.overAppetite) || 0;
    register.byLevel = s.byLevel || {};
  } catch { /* */ }
  // the defined risk appetite (tuned on /risk-register) — auditors want the stated tolerance, not just performance against it
  let appetite: AuditPackage["risk"]["appetite"] = [];
  try {
    const gov = getRiskGovernance(tenant) as { appetite?: { Category?: string; AppetiteLevel?: string; ToleranceRank?: number; Rationale?: string }[] };
    appetite = (gov.appetite || []).map((a) => ({ category: String(a.Category || ""), appetiteLevel: String(a.AppetiteLevel || ""), toleranceRank: Number(a.ToleranceRank) || 0, rationale: String(a.Rationale || "") }));
  } catch { /* governance tables not ready */ }

  // 4 — business impact: human-authored BIAENTRY (authoritative) + a computed draft from asset signals
  const bia: AuditPackage["bia"] = { entries: [], total: 0, critical: 0, computed: [], computedTotal: 0, computedCritical: 0 };
  try {
    if (has(xo, "BIAENTRY")) {
      const rows = xo.prepare(`SELECT AssetName, CriticalityLevel, RTO, RPO, MTD, OwnerName FROM BIAENTRY ORDER BY
        CASE LOWER(COALESCE(CriticalityLevel,'')) WHEN 'critical' THEN 0 WHEN 'very high' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT 200`).all() as Record<string, unknown>[];
      bia.total = rows.length;
      bia.critical = rows.filter((r) => ["critical", "very high", "high"].includes(String(r.CriticalityLevel || "").toLowerCase())).length;
      bia.entries = rows.slice(0, 50).map((r) => ({ asset: String(r.AssetName || ""), criticality: String(r.CriticalityLevel || ""), rto: String(r.RTO ?? ""), rpo: String(r.RPO ?? ""), mtd: String(r.MTD ?? ""), owner: String(r.OwnerName || "") }));
    }
  } catch { /* */ }
  try {
    const c = computeBia(tenant, 50);
    bia.computed = c.rows; bia.computedTotal = c.total; bia.computedCritical = c.critical;
  } catch { /* */ }

  // evidence index — traceable artifacts
  let evidenceIndex: AuditPackage["evidenceIndex"] = [];
  try {
    if (has(xc, "EVIDENCE")) evidenceIndex = (xc.prepare("SELECT EvidenceName, CreatedDate FROM EVIDENCE ORDER BY EvidenceID DESC LIMIT 100").all() as Record<string, unknown>[]).map((r) => ({ name: String(r.EvidenceName || ""), date: String(r.CreatedDate || "") }));
  } catch { /* */ }

  // posture trend over prior persisted snapshots (read-only; recordAuditSnapshot writes them)
  let trend: AuditPackage["trend"] = [];
  try { trend = auditSnapshotTrend(tenant, 30); } catch { /* table not ready */ }

  return {
    generatedAt: new Date().toISOString().replace("T", " ").slice(0, 19), tenant, ai: false, model: "",
    executiveSummary: "", accreditation, regulatory: { cloud, auditTrail, auditTrailTotal },
    risk: { topExposures: topExp, register, appetite }, bia, evidenceIndex, trend,
  };
}

function offlineSummary(p: AuditPackage): string {
  const fw = p.accreditation.frameworks.map((f) => `${f.label} ${f.readinessPct}%`).join(", ");
  const reg = p.regulatory.cloud.fail + p.regulatory.cloud.pass;
  return [
    `Accreditation readiness is ${p.accreditation.provenPct}% of telemetry-measurable controls proven (${p.accreditation.proven} proven, ${p.accreditation.partial} partial, ${p.accreditation.gap} gap, ${p.accreditation.attest} attestation-required). Framework readiness: ${fw || "n/a"}.`,
    reg ? `Regulatory configuration evidence: ${p.regulatory.cloud.pass}/${reg} cloud CIS checks passing; ${p.regulatory.auditTrailTotal} audit-log entries provide the activity trail.` : `Audit trail: ${p.regulatory.auditTrailTotal} logged actions provide traceability.`,
    `Cyber-risk: ${p.risk.topExposures.filter((e) => e.kev).length} KEV-listed exposure(s) in the top findings; risk register holds ${p.risk.register.total} risk(s), ${p.risk.register.overAppetite} over appetite${p.risk.appetite.length ? ` against ${p.risk.appetite.length} defined appetite categor${p.risk.appetite.length === 1 ? "y" : "ies"}` : ""}.`,
    p.bia.total ? `Business impact: ${p.bia.critical}/${p.bia.total} assessed functions are high/critical, each with recovery objectives (RTO/RPO/MTD) defined.`
      : p.bia.computedTotal ? `Business impact: no formal BIA yet — a computed draft ranks ${p.bia.computedCritical}/${p.bia.computedTotal} assets high/critical from value and dependency signals, with suggested recovery objectives.`
      : `Business impact analysis: no BIA entries recorded yet.`,
    `Top priority: close the ${p.accreditation.gap} control gap(s) and the ${p.risk.register.overAppetite} over-appetite risk(s) before the assessment.`,
  ].join(" ");
}

export async function generateAuditPackage(tenant: number | null): Promise<AuditPackage> {
  const p = buildAuditPackage(tenant);
  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  if (status.reachable) {
    try {
      const facts = JSON.stringify({
        accreditation: { provenPct: p.accreditation.provenPct, proven: p.accreditation.proven, partial: p.accreditation.partial, gap: p.accreditation.gap, attest: p.accreditation.attest, frameworks: p.accreditation.frameworks },
        regulatory: { cloud: p.regulatory.cloud, auditTrailEntries: p.regulatory.auditTrailTotal },
        risk: { kev: p.risk.topExposures.filter((e) => e.kev).length, register: p.risk.register },
        bia: { total: p.bia.total, critical: p.bia.critical },
      });
      const sys = "You are a GRC analyst writing the executive summary of an audit & accreditation report. Using ONLY the supplied JSON facts (do not invent numbers, controls or certifications), write 4-6 sentences covering: accreditation readiness, regulatory/configuration evidence and traceability, cyber-risk posture vs appetite, and business-impact/recovery readiness — ending with the single highest-priority action. Plain, factual, board-appropriate.";
      const out = (await ollamaChat([{ role: "system", content: sys }, { role: "user", content: facts }], 0.2, 60000)).trim();
      if (out) { p.executiveSummary = out; p.ai = true; p.model = status.model || ""; }
    } catch { /* offline fallback below */ }
  }
  if (!p.executiveSummary) p.executiveSummary = offlineSummary(p);
  return p;
}

// ── Markdown rendering (the audit-ready document) ───────────────────────────────────
export function auditPackageMarkdown(p: AuditPackage): string {
  const L: string[] = [];
  L.push(`# Audit & Accreditation Package`, "", `_Generated ${p.generatedAt}${p.ai ? ` · executive summary by local AI (${p.model})` : " · executive summary: offline"}_`, "");
  L.push(`## Executive summary`, "", p.executiveSummary, "");
  L.push(`## 1 · Control implementation & accreditation readiness`, "", `**${p.accreditation.provenPct}%** of measurable controls proven — ${p.accreditation.proven} proven · ${p.accreditation.partial} partial · ${p.accreditation.gap} gap · ${p.accreditation.attest} attestation-required.`, "");
  if (p.trend.length >= 2) { const d = p.trend[p.trend.length - 1].provenPct - p.trend[0].provenPct; L.push(`Trend over ${p.trend.length} snapshots: ${p.trend[0].provenPct}% → ${p.trend[p.trend.length - 1].provenPct}% (${d >= 0 ? "+" : ""}${d} pts).`, ""); }
  L.push(`| Framework | Readiness | Proven |`, `|---|---|---|`, ...p.accreditation.frameworks.map((f) => `| ${f.label} | ${f.readinessPct}% | ${f.proven}/${f.measurable} |`), "");
  L.push(`| Control | Status | Mapping | Evidence |`, `|---|---|---|---|`, ...p.accreditation.controls.map((c) => `| ${c.name} | ${c.status} | ${c.refs} | ${(c.evidence || []).join("; ") || c.metric} |`), "");
  L.push("", `## 2 · Regulatory adherence (configuration & audit trail)`, "");
  L.push(`Cloud configuration checks: **${p.regulatory.cloud.pass} pass / ${p.regulatory.cloud.fail} fail** — ` + (Object.entries(p.regulatory.cloud.byProvider).map(([k, v]) => `${k}: ${v.pass}✓/${v.fail}✗`).join(", ") || "no cloud findings") + ".", "");
  L.push(`Audit trail: **${p.regulatory.auditTrailTotal}** logged actions (most recent ${p.regulatory.auditTrail.length}):`, "");
  L.push(`| When | User | Action | Resource |`, `|---|---|---|---|`, ...p.regulatory.auditTrail.slice(0, 15).map((e) => `| ${e.at} | ${e.user} | ${e.action} | ${e.resource} |`), "");
  L.push("", `## 3 · Cyber-risk posture`, "");
  L.push(`Risk register: **${p.risk.register.total}** risk(s), **${p.risk.register.overAppetite} over appetite**. Residual: ` + (Object.entries(p.risk.register.byLevel).map(([k, v]) => `${k}: ${v}`).join(", ") || "n/a") + ".", "");
  if (p.risk.appetite.length) { L.push("", `Defined risk appetite (tolerance):`, "", `| Category | Appetite | Tolerance (max acceptable residual) | Rationale |`, `|---|---|---|---|`, ...p.risk.appetite.map((a) => `| ${a.category} | ${a.appetiteLevel || "—"} | rank ≤ ${a.toleranceRank} | ${a.rationale || ""} |`)); }
  if (p.risk.topExposures.length) { L.push("", `Top emerging exposures:`, "", `| Reference | CVSS | KEV | Exploits | EPSS |`, `|---|---|---|---|---|`, ...p.risk.topExposures.map((e) => `| ${e.ref} | ${e.cvss ?? "—"} | ${e.kev ? "yes" : "no"} | ${e.exploits} | ${e.epss != null ? Math.round(e.epss * 100) + "%" : "—"} |`)); }
  L.push("", `## 4 · Business impact analysis`, "");
  if (p.bia.total) { L.push(`**${p.bia.critical}/${p.bia.total}** functions are high/critical, with recovery objectives:`, "", `| Function / Asset | Criticality | RTO | RPO | MTD | Owner |`, `|---|---|---|---|---|---|`, ...p.bia.entries.slice(0, 25).map((b) => `| ${b.asset} | ${b.criticality} | ${b.rto} | ${b.rpo} | ${b.mtd} | ${b.owner} |`)); }
  else if (p.bia.computedTotal) {
    L.push(`_No formal BIA recorded — the following is a **computed draft** ranking ${p.bia.computedCritical}/${p.bia.computedTotal} assets high/critical from business/financial value, risk score and dependency centrality. Review and promote to a formal BIA._`, "",
      `| Asset | Criticality | RTO | RPO | MTD | Drivers |`, `|---|---|---|---|---|---|`, ...p.bia.computed.slice(0, 25).map((b) => `| ${b.asset} | ${b.criticality} (${b.score}) | ${b.rto} | ${b.rpo} | ${b.mtd} | ${b.drivers.join(", ")} |`));
  } else L.push("_No BIA entries recorded — define critical functions and their RTO/RPO to complete this section._");
  L.push("", `## Evidence index`, "", p.evidenceIndex.length ? p.evidenceIndex.map((e) => `- ${e.name}${e.date ? ` (${e.date})` : ""}`).join("\n") : "_No catalogued evidence artifacts yet._");
  L.push("", `---`, `_Figures recompute from live telemetry at generation time; the deterministic checks are the source of truth and the local AI only narrates._`);
  return L.join("\n");
}

// ── Scheduled snapshotting (posture trend over time) ────────────────────────────────
// One rollup row per tenant per day in XCOMPLIANCE; the scheduler records it, buildAuditPackage reads it.
function ensureAuditSnapshotTable(): void {
  getDb("XCOMPLIANCE").exec(`CREATE TABLE IF NOT EXISTS AUDITPACKAGESNAPSHOT(
    SnapshotID INTEGER PRIMARY KEY AUTOINCREMENT, At TEXT, TenantID INTEGER,
    ProvenPct REAL, ControlGap INTEGER, CloudPass INTEGER, CloudFail INTEGER,
    RisksTotal INTEGER, RisksOverAppetite INTEGER, BiaCritical INTEGER, BiaTotal INTEGER);
    CREATE INDEX IF NOT EXISTS ix_auditsnap_tn ON AUDITPACKAGESNAPSHOT(TenantID, At);`);
}

export function recordAuditSnapshot(tenant: number | null): { at: string; provenPct: number } {
  ensureAuditSnapshotTable();
  const xc = getDb("XCOMPLIANCE");
  const p = buildAuditPackage(tenant);
  const today = new Date().toISOString().slice(0, 10);
  const biaTotal = p.bia.total || p.bia.computedTotal;
  const biaCrit = p.bia.total ? p.bia.critical : p.bia.computedCritical;
  const tw = tenant != null ? "TenantID=?" : "TenantID IS NULL";
  const last = xc.prepare(`SELECT SnapshotID, At FROM AUDITPACKAGESNAPSHOT WHERE ${tw} ORDER BY SnapshotID DESC LIMIT 1`).get(...(tenant != null ? [tenant] : [])) as { SnapshotID: number; At: string } | undefined;
  const vals = [p.accreditation.provenPct, p.accreditation.gap, p.regulatory.cloud.pass, p.regulatory.cloud.fail, p.risk.register.total, p.risk.register.overAppetite, biaCrit, biaTotal];
  if (last && String(last.At).slice(0, 10) === today) {
    xc.prepare(`UPDATE AUDITPACKAGESNAPSHOT SET At=?, ProvenPct=?, ControlGap=?, CloudPass=?, CloudFail=?, RisksTotal=?, RisksOverAppetite=?, BiaCritical=?, BiaTotal=? WHERE SnapshotID=?`)
      .run(p.generatedAt, ...vals, last.SnapshotID);
  } else {
    xc.prepare(`INSERT INTO AUDITPACKAGESNAPSHOT (At, TenantID, ProvenPct, ControlGap, CloudPass, CloudFail, RisksTotal, RisksOverAppetite, BiaCritical, BiaTotal) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(p.generatedAt, tenant, ...vals);
  }
  return { at: p.generatedAt, provenPct: p.accreditation.provenPct };
}

export function auditSnapshotTrend(tenant: number | null, n = 30): { at: string; provenPct: number }[] {
  const xc = getDb("XCOMPLIANCE");
  if (!has(xc, "AUDITPACKAGESNAPSHOT")) return [];
  const tw = tenant != null ? "WHERE TenantID=?" : "WHERE TenantID IS NULL";
  const rows = xc.prepare(`SELECT At, ProvenPct FROM AUDITPACKAGESNAPSHOT ${tw} ORDER BY At DESC, SnapshotID DESC LIMIT ?`).all(...(tenant != null ? [tenant, n] : [n])) as { At: string; ProvenPct: number }[];
  return rows.reverse().map((r) => ({ at: String(r.At || "").slice(0, 10), provenPct: Math.round(Number(r.ProvenPct) || 0) }));
}

// ── OSCAL export (NIST OSCAL 1.1.2 subset) ──────────────────────────────────────────
// Produces a System Security Plan (control-implementation) or a Plan of Action & Milestones from the
// same deterministic package — the machine-readable artifacts an assessor/accreditation body ingests.
const OSCAL_VERSION = "1.1.2";
const implStatus = (s: string): string => s === "proven" ? "implemented" : s === "partial" ? "partial" : s === "attest" ? "alternative" : "planned";

function oscalMeta(title: string): Record<string, unknown> {
  return { title, "last-modified": new Date().toISOString(), version: "1.0", "oscal-version": OSCAL_VERSION,
    remarks: "Generated by XORCISM from live security telemetry; figures are deterministic, not attestation." };
}

// Which internal framework code each OSCAL profile maps to, plus a profile href & id casing.
// These match the frameworks XORCISM's controls are actually mapped to (SOC 2 / ISO 27001 / NIST CSF 2.0).
// resolveControlId() is case-insensitive, so an imported OSCAL catalog (incl. NIST SP 800-53) still
// enriches control titles regardless of the casing chosen here.
const PROFILES: Record<string, { fw: string; href: string; lower: boolean }> = {
  soc2: { fw: "soc2", lower: false, href: "https://www.aicpa.org/soc4so" },
  iso27001: { fw: "iso27001", lower: false, href: "https://www.iso.org/standard/27001" },
  nistcsf: { fw: "nistcsf", lower: false, href: "https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final" },
};

// Resolve a control's id for the requested profile: pick the matching framework ref, normalise casing,
// and (if an OSCAL catalog has been imported) swap in the canonical id + title.
function resolveForProfile(c: AuditPackage["accreditation"]["controls"][number], profileKey: string | undefined, tenant: number | null): { controlId: string; title: string; resolved: boolean } {
  const prof = profileKey ? PROFILES[profileKey] : undefined;
  let ref = "";
  if (prof) { const m = c.frameworks.find((f) => f.fw === prof.fw); ref = m ? m.ref : ""; }
  if (!ref) ref = (c.frameworks[0]?.ref) || (c.refs.split("·")[0] || c.id).trim().replace(/^[a-z0-9]+:/i, "").trim() || c.id;
  if (prof?.lower) ref = ref.toLowerCase();
  let title = "", resolved = false;
  try { const r = resolveControlId(tenant, ref); if (r) { ref = r.controlId; title = r.title; resolved = true; } } catch { /* */ }
  return { controlId: ref || c.id, title, resolved };
}

export function auditPackageOscal(p: AuditPackage, kind: "ssp" | "poam" = "ssp", opts: { profile?: string; tenant?: number | null } = {}): Record<string, unknown> {
  const tenant = opts.tenant ?? p.tenant;
  if (kind === "poam") {
    const items: Record<string, unknown>[] = [];
    for (const c of p.accreditation.controls.filter((c) => c.status === "gap" || c.status === "partial")) {
      items.push({ uuid: randomUUID(), title: `Control gap: ${c.name}`,
        description: `${c.name} is ${c.status} (${c.refs}). Observed: ${c.metric}`,
        props: [{ name: "risk-status", value: "open" }, { name: "type", value: "control-deficiency" }] });
    }
    for (const [prov, v] of Object.entries(p.regulatory.cloud.byProvider)) {
      if (v.fail > 0) items.push({ uuid: randomUUID(), title: `Cloud configuration failures: ${prov}`,
        description: `${v.fail} CIS configuration check(s) failing on ${prov} (${v.pass} passing).`,
        props: [{ name: "risk-status", value: "open" }, { name: "type", value: "configuration" }] });
    }
    for (const e of p.risk.topExposures.filter((e) => e.kev)) {
      items.push({ uuid: randomUUID(), title: `KEV-listed exposure: ${e.ref}`,
        description: `${e.ref} is on the CISA KEV list (CVSS ${e.cvss ?? "n/a"}, ${e.exploits} known exploit(s)).`,
        props: [{ name: "risk-status", value: "open" }, { name: "type", value: "vulnerability" }] });
    }
    return { "plan-of-action-and-milestones": {
      uuid: randomUUID(), metadata: oscalMeta("XORCISM — Plan of Action & Milestones"),
      "system-id": { "identifier-type": "https://xorcism.ai/ns/system", id: `xorcism-tenant-${p.tenant ?? "all"}` },
      "poam-items": items.length ? items : [{ uuid: randomUUID(), title: "No open items", description: "No control gaps, cloud failures or KEV exposures recorded.", props: [{ name: "risk-status", value: "closed" }] }],
    } };
  }
  // SSP
  const prof = opts.profile ? PROFILES[opts.profile] : undefined;
  const impl = p.accreditation.controls.map((c) => {
    const r = resolveForProfile(c, opts.profile, tenant);
    return {
      uuid: randomUUID(),
      "control-id": r.controlId,
      props: [{ name: "implementation-status", value: implStatus(c.status) }, ...(r.resolved ? [{ name: "resolved-from-catalog", value: "true" }] : [])],
      statements: [{ "statement-id": `${c.id}_stmt`, uuid: randomUUID(),
        "by-components": [{ "component-uuid": randomUUID(), uuid: randomUUID(),
          description: c.metric, props: [{ name: "implementation-status", value: implStatus(c.status) }],
          links: (c.evidence || []).map((e) => ({ href: "#", rel: "evidence", text: e })) }] }],
      remarks: `${c.name}${r.title ? ` → ${r.title}` : ""}. Mapping: ${c.refs}`,
    };
  });
  const sens = p.accreditation.provenPct >= 70 ? "moderate" : p.accreditation.gap > 0 ? "high" : "low";
  return { "system-security-plan": {
    uuid: randomUUID(), metadata: oscalMeta(`XORCISM — System Security Plan${opts.profile ? ` (${opts.profile})` : ""}`),
    "import-profile": { href: prof ? prof.href : "#" },
    "system-characteristics": {
      "system-ids": [{ "identifier-type": "https://xorcism.ai/ns/system", id: `xorcism-tenant-${p.tenant ?? "all"}` }],
      "system-name": "XORCISM-assessed environment",
      description: `Control implementation evidence assembled from live telemetry. ${p.accreditation.provenPct}% of measurable controls proven; ${p.accreditation.gap} gap(s).`,
      "security-sensitivity-level": sens,
      "system-information": { "information-types": [{ uuid: randomUUID(), title: "Operational security data", description: "Security control telemetry and findings." }] },
      "security-impact-level": { "security-objective-confidentiality": sens, "security-objective-integrity": sens, "security-objective-availability": sens },
      status: { state: "operational" },
      "authorization-boundary": { description: "Assets and services inventoried in XORCISM for the assessed tenant." },
    },
    "system-implementation": { users: [{ uuid: randomUUID(), title: "System owner" }], components: [{ uuid: randomUUID(), type: "system", title: "Assessed system", description: "Aggregate of inventoried assets.", status: { state: "operational" } }] },
    "control-implementation": { description: "Implementation status per control objective, evidenced by live telemetry.", "implemented-requirements": impl },
  } };
}

/**
 * SARIF 2.1.0 export of the audit package — emits control gaps/partials and top cyber-risk exposures as
 * SARIF results, so the accreditation evidence drops into code-scanning / SARIF-consuming tools (GitHub
 * code scanning, DefectDojo, etc.). Built from the already-tenant-scoped package (no extra queries).
 */
export function auditPackageSarif(p: AuditPackage): unknown {
  const sevLevel = (s: string): "error" | "warning" | "note" =>
    /gap|crit|high|fail/i.test(s) ? "error" : /partial|med|moderate|warn/i.test(s) ? "warning" : "note";
  const rules: Record<string, unknown>[] = [];
  const ruleSeen = new Set<string>();
  const results: Record<string, unknown>[] = [];

  // control implementation gaps / partials
  for (const c of p.accreditation.controls.filter((x) => x.status === "gap" || x.status === "partial")) {
    const ruleId = `control/${c.id}`;
    if (!ruleSeen.has(ruleId)) {
      ruleSeen.add(ruleId);
      rules.push({ id: ruleId, name: c.name, shortDescription: { text: `Control: ${c.name}` },
        defaultConfiguration: { level: sevLevel(c.status) },
        properties: { frameworks: (c.frameworks || []).map((f) => `${f.fw}:${f.ref}`), tags: ["compliance", "control"] } });
    }
    results.push({
      ruleId, level: sevLevel(c.status),
      message: { text: `${c.name} — implementation status: ${c.status}.${c.refs ? ` Mapped to ${c.refs}.` : ""}${c.metric ? ` (${c.metric})` : ""}` },
      locations: [{ logicalLocations: [{ name: c.id, fullyQualifiedName: c.refs || c.id, kind: "control" }] }],
      properties: { status: c.status, evidence: c.evidence || [] },
    });
  }
  // top cyber-risk exposures (CVEs)
  for (const e of p.risk.topExposures) {
    const ruleId = `exposure/${e.ref}`;
    if (!ruleSeen.has(ruleId)) {
      ruleSeen.add(ruleId);
      rules.push({ id: ruleId, name: e.ref, shortDescription: { text: `Exposure ${e.ref}` },
        defaultConfiguration: { level: e.kev || e.priority >= 70 ? "error" : "warning" }, properties: { tags: ["vulnerability", e.kev ? "kev" : "exposure"] } });
    }
    results.push({
      ruleId, level: e.kev || e.priority >= 70 ? "error" : "warning",
      message: { text: `${e.ref}: priority ${e.priority}${e.cvss != null ? `, CVSS ${e.cvss}` : ""}${e.epss != null ? `, EPSS ${(e.epss * 100).toFixed(0)}%` : ""}${e.kev ? ", on CISA KEV" : ""}${e.exploits ? `, ${e.exploits} public exploit(s)` : ""}.` },
      locations: [{ logicalLocations: [{ name: e.ref, kind: "vulnerability" }] }],
      properties: { kev: e.kev, cvss: e.cvss, epss: e.epss, exploits: e.exploits, priority: e.priority },
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "XORCISM", informationUri: "https://github.com/XORCISM-AI/XORCISM", version: "1.6", rules } },
      results,
      properties: { generatedAt: p.generatedAt, provenPct: p.accreditation.provenPct, gaps: p.accreditation.gap, partials: p.accreditation.partial },
    }],
  };
}
