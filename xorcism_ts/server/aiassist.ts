/**
 * aiassist.ts — the second wave of local-AI copilots, closing the AI-coverage gaps across XORCISM
 * (threat modeling, framework crosswalks, incidents, risk/FAIR, compliance execution, remediation,
 * privacy, awareness, SOC, malware, OSINT, hardening). Same discipline as ai.ts: build context from
 * the org's own data, ask the local model (Ollama), and ALWAYS degrade to a genuinely useful
 * deterministic draft when the AI is offline. Nothing leaves the machine.
 */
import { getDb } from "./db";
import { ollamaChat, ollamaStatus, OLLAMA_MODEL, embedTexts, cosine } from "./ai";

export interface AiText { content: string; model: string; offline: boolean; [k: string]: unknown }

/** Run the local model with a system+user prompt, else return the deterministic draft. */
async function aiOrDet(sys: string, user: string, det: string, temp = 0.3, minLen = 24): Promise<AiText> {
  const status = await ollamaStatus();
  if (status.reachable) {
    try {
      const out = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user.slice(0, 13000) }], temp);
      if (out && out.trim().length >= minLen) return { content: out.trim(), model: OLLAMA_MODEL, offline: false };
    } catch { /* slow/failed model → deterministic */ }
  }
  return { content: det, model: status.reachable ? "fallback" : "offline", offline: true };
}

const OFF = "_Local AI unavailable — deterministic draft (start Ollama for an AI-authored version)._";
function cols(db: ReturnType<typeof getDb>, table: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function pick(row: Record<string, unknown> | undefined, names: string[]): string {
  if (!row) return "";
  for (const n of names) if (row[n] != null && String(row[n]).trim()) return String(row[n]).trim();
  return "";
}
function extractJson(s: string): any | null {
  if (!s) return null;
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = fence ? fence[1] : s;
  const i = body.indexOf("{"), j = body.lastIndexOf("}");
  if (i < 0 || j <= i) return null;
  try { return JSON.parse(body.slice(i, j + 1)); } catch { return null; }
}
const tokens = (s: string): Set<string> =>
  new Set((s || "").toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 4));
function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size || !b.size) return 0;
  let inter = 0; for (const t of a) if (b.has(t)) inter++;
  return inter / (a.size + b.size - inter);
}

// ───────────────────────── 1. Threat modeling (STRIDE + attack tree) ─────────────────────────
export async function draftThreatModel(opts: { name?: string; system?: string; assets?: string; dataFlows?: string; scope?: string; tenant?: number | null }): Promise<AiText> {
  const name = (opts.name || "System threat model").trim();
  let assetCtx = (opts.assets || "").trim();
  if (!assetCtx) {
    try {
      const xo = getDb("XORCISM");
      const where = opts.tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
      const rows = xo.prepare(`SELECT AssetName, AssetType FROM ASSET ${where} ORDER BY COALESCE(FinancialValue,0) DESC LIMIT 15`)
        .all(...(opts.tenant != null ? [opts.tenant] : [])) as { AssetName: string; AssetType?: string }[];
      if (rows.length) assetCtx = rows.map((r) => `- ${r.AssetName}${r.AssetType ? ` (${r.AssetType})` : ""}`).join("\n");
    } catch { /* optional */ }
  }
  const ctx = [opts.system && `System: ${opts.system}`, opts.scope && `Scope: ${opts.scope}`,
    assetCtx && `Assets/components:\n${assetCtx}`, opts.dataFlows && `Data flows:\n${opts.dataFlows}`].filter(Boolean).join("\n");
  const det = [
    `## Threat model — ${name}`, OFF, "",
    "### Assets & trust boundaries", assetCtx || "- (list the components, data stores and external dependencies, and the trust boundaries between them)", "",
    "### STRIDE threat enumeration",
    "| Category | Example threat | Affected element | Mitigation |",
    "|---|---|---|---|",
    "| **S**poofing | Identity spoofing / credential theft | Authentication boundary | MFA, strong session mgmt, mutual TLS |",
    "| **T**ampering | Unauthorized data/parameter modification | Data store, API | Input validation, integrity checks, signing |",
    "| **R**epudiation | Action denial / missing audit trail | Transactions | Tamper-evident logging, time sync |",
    "| **I**nformation disclosure | Sensitive data exposure | Data at rest/in transit | Encryption, least-privilege, data classification |",
    "| **D**enial of service | Resource exhaustion | Public endpoints | Rate limiting, autoscaling, quotas |",
    "| **E**levation of privilege | Auth bypass / privilege escalation | Authorization layer | RBAC, deny-by-default, server-side checks |", "",
    "### Attack tree (goal → paths)",
    "- **Goal:** compromise the system / exfiltrate critical data",
    "  - OR phishing → credential theft → VPN/SSO → lateral movement",
    "  - OR exploit an internet-exposed vulnerability → foothold → privilege escalation",
    "  - OR supply-chain / dependency compromise → code execution",
    "  - OR insider / over-scoped non-human identity abuse", "",
    "### Prioritized mitigations", "1. Enforce MFA + least privilege on the authentication/authorization boundary.",
    "2. Patch internet-exposed components and reduce the external attack surface.",
    "3. Encrypt and classify sensitive data; segment crown-jewel data stores.",
    "4. Add detections (map to MITRE ATT&CK) for the highest-likelihood paths above.",
  ].join("\n");
  const sys = "You are a senior application-security architect running a STRIDE threat-modeling session. " +
    "From the system description and assets, produce concise Markdown with: ## Assets & trust boundaries, ## STRIDE threat enumeration (a Markdown table: Category | Threat | Affected element | Mitigation), " +
    "## Attack tree (goal → OR/AND paths, nested bullets), ## Prioritized mitigations (map to MITRE ATT&CK where relevant). Be specific to the described system; under 500 words.";
  return aiOrDet(sys, `Threat model for: ${name}\n${ctx || "(no system details provided — produce a sensible default web-app/SaaS threat model)"}`, det, 0.35);
}

// ───────────────────────── 2. Framework crosswalk suggester (semantic) ─────────────────────────
function loadControls(vocab: string, limit = 400): { id: number; code: string; name: string; text: string }[] {
  const xo = getDb("XORCISM");
  let vid: number | undefined;
  try {
    const vc = cols(xo, "VOCABULARY");
    const namecol = vc.has("VocabularyName") ? "VocabularyName" : vc.has("Name") ? "Name" : null;
    if (/^\d+$/.test(vocab)) vid = Number(vocab);
    else if (namecol) {
      const r = xo.prepare(`SELECT VocabularyID FROM VOCABULARY WHERE ${namecol} LIKE ? ORDER BY VocabularyID LIMIT 1`).get(`%${vocab}%`) as { VocabularyID: number } | undefined;
      vid = r?.VocabularyID;
    }
  } catch { /* */ }
  if (vid == null) return [];
  try {
    const rows = xo.prepare("SELECT ControlID, CIS, ControlName, ControlDescription, Statement FROM CONTROL WHERE VocabularyID = ? LIMIT ?").all(vid, limit) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: Number(r.ControlID), code: String(r.CIS ?? r.ControlID ?? ""),
      name: String(r.ControlName ?? "").slice(0, 200),
      text: `${String(r.ControlName ?? "")} ${String(r.Statement ?? r.ControlDescription ?? "")}`.slice(0, 1200),
    }));
  } catch { return []; }
}

export interface MappingSuggestion { sourceCode: string; sourceName: string; targetCode: string; targetName: string; score: number; rationale: string }
export async function suggestControlMappings(opts: { sourceVocab: string; targetVocab: string; max?: number; tenant?: number | null }): Promise<{ mappings: MappingSuggestion[]; model: string; offline: boolean; method: string; sourceCount: number; targetCount: number }> {
  const src = loadControls(opts.sourceVocab);
  const tgt = loadControls(opts.targetVocab);
  const max = Math.max(1, Math.min(60, opts.max ?? 25));
  if (!src.length || !tgt.length) {
    return { mappings: [], model: "deterministic", offline: true, method: "none", sourceCount: src.length, targetCount: tgt.length };
  }
  // 1) candidate generation: semantic (embeddings) if available, else keyword (Jaccard).
  const srcEmb = await embedTexts(src.map((s) => s.text));
  const tgtEmb = srcEmb ? await embedTexts(tgt.map((t) => t.text)) : null;
  const method = srcEmb && tgtEmb ? "embeddings" : "keyword";
  const cand: MappingSuggestion[] = [];
  src.slice(0, max).forEach((s, si) => {
    const scored = tgt.map((t, ti) => ({
      t, score: srcEmb && tgtEmb ? cosine(srcEmb[si], tgtEmb[ti]) : jaccard(tokens(s.text), tokens(t.text)),
    })).sort((a, b) => b.score - a.score).slice(0, 1)[0];
    if (scored && scored.score > (method === "embeddings" ? 0.55 : 0.12)) {
      cand.push({
        sourceCode: s.code, sourceName: s.name, targetCode: scored.t.code, targetName: scored.t.name,
        score: Math.round(scored.score * 100) / 100,
        rationale: `Closest ${method} match (similarity ${(scored.score * 100).toFixed(0)}%). Review before accepting.`,
      });
    }
  });
  cand.sort((a, b) => b.score - a.score);

  // 2) optional AI rationale refinement on the top candidates
  const status = await ollamaStatus();
  if (status.reachable && cand.length) {
    try {
      const sys = "You are a GRC controls-mapping analyst. For each candidate control mapping, write a one-sentence rationale and a confidence 0-1. " +
        "Output ONLY a JSON object {\"mappings\":[{\"sourceCode\",\"targetCode\",\"rationale\",\"confidence\"}]}. Be conservative; lower confidence when the match is weak.";
      const user = "Candidate mappings (source ⇒ target):\n" + cand.slice(0, max).map((c) => `- ${c.sourceCode} "${c.sourceName}" ⇒ ${c.targetCode} "${c.targetName}"`).join("\n");
      const j = extractJson(await ollamaChat([{ role: "system", content: sys }, { role: "user", content: user.slice(0, 12000) }], 0.2));
      if (j && Array.isArray(j.mappings)) {
        const byKey = new Map(j.mappings.map((m: any) => [`${m.sourceCode}|${m.targetCode}`, m]));
        for (const c of cand) {
          const m = byKey.get(`${c.sourceCode}|${c.targetCode}`) as any;
          if (m) { if (m.rationale) c.rationale = String(m.rationale).slice(0, 400); if (Number.isFinite(Number(m.confidence))) c.score = Math.round(Number(m.confidence) * 100) / 100; }
        }
        cand.sort((a, b) => b.score - a.score);
        return { mappings: cand.slice(0, max), model: OLLAMA_MODEL, offline: false, method: method + "+ai", sourceCount: src.length, targetCount: tgt.length };
      }
    } catch { /* keep deterministic candidates */ }
  }
  return { mappings: cand.slice(0, max), model: status.reachable ? "fallback" : "offline", offline: true, method, sourceCount: src.length, targetCount: tgt.length };
}

// ───────────────────────── 3. Incident copilot (summary / RCA / comms / postmortem) ─────────────────────────
export async function incidentCopilot(opts: { incidentId?: number; mode?: string; tenant?: number | null }): Promise<AiText> {
  const mode = ["summary", "rootcause", "comms", "postmortem"].includes(String(opts.mode)) ? String(opts.mode) : "summary";
  let inc: Record<string, unknown> | undefined; let alerts: Record<string, unknown>[] = [];
  try {
    const xi = getDb("XINCIDENT");
    if (opts.incidentId) inc = xi.prepare("SELECT * FROM INCIDENT WHERE IncidentID = ?").get(opts.incidentId) as Record<string, unknown> | undefined;
    if (opts.incidentId && cols(xi, "ALERT").size)
      alerts = xi.prepare("SELECT * FROM ALERT WHERE IncidentID = ? LIMIT 25").all(opts.incidentId) as Record<string, unknown>[];
  } catch { /* optional */ }
  const title = pick(inc, ["Title", "IncidentName", "Name"]) || (opts.incidentId ? `Incident #${opts.incidentId}` : "Incident");
  const sev = pick(inc, ["Severity", "Priority"]);
  const status = pick(inc, ["Status", "State", "Classification"]);
  const desc = pick(inc, ["Description", "Summary", "Details"]);
  const ctx = [`Incident: ${title}`, sev && `Severity: ${sev}`, status && `Status: ${status}`, desc && `Description: ${desc.slice(0, 1500)}`,
    alerts.length ? `Linked alerts (${alerts.length}):\n` + alerts.slice(0, 15).map((a) => `- [${pick(a, ["Severity"]) || "?"}] ${pick(a, ["Title", "AlertName", "Name"]) || "alert"}${pick(a, ["AttackTechnique", "Technique"]) ? ` (${pick(a, ["AttackTechnique", "Technique"])})` : ""}`).join("\n") : ""].filter(Boolean).join("\n");
  const dets: Record<string, string> = {
    summary: [`## Incident summary — ${title}`, OFF, "", `**Severity:** ${sev || "—"} · **Status:** ${status || "—"} · **Linked alerts:** ${alerts.length}`, "",
      "**What we know:** " + (desc || "Populate the incident description and link alerts for a fuller summary."), "",
      "**Timeline (reconstruct):** detection → triage → containment → eradication → recovery.", "",
      "**Next actions:** confirm scope, contain affected assets, preserve evidence, and assess the regulatory notification clock."].join("\n"),
    rootcause: [`## Root-cause analysis — ${title}`, OFF, "", "**Working hypotheses (rank & disprove):**",
      "1. Initial access via phishing / stolen credentials.", "2. Exploitation of an unpatched internet-exposed vulnerability.",
      "3. Misconfiguration / excessive privilege abused for lateral movement.", "4. Third-party / supply-chain vector.", "",
      "**5 Whys:** ask 'why' iteratively from the symptom to the systemic cause.", "",
      "**Contributing factors:** detection gap, control gap, process gap. **Fix the systemic cause, not just the symptom.**"].join("\n"),
    comms: [`## Stakeholder communication — ${title}`, OFF, "", "**Internal (leadership):** what happened, current impact, what we're doing, next update time. Avoid speculation.",
      "", "**Technical teams:** scope, affected assets, containment actions, asks.", "",
      "**External/customers (if needed):** factual, reassuring, no over-promising; coordinate with legal.", "",
      `**Regulator (if applicable):** assess the notification clock now (e.g. NIS2 24h early-warning / 72h, GDPR 72h). Severity: ${sev || "TBD"}.`].join("\n"),
    postmortem: [`## Post-incident review — ${title}`, OFF, "", "### Summary", desc || "(one-paragraph factual summary)",
      "### Impact", "Systems, data, users, duration, and business impact.", "### Timeline", "Detection → response → recovery (with timestamps).",
      "### Root cause", "The systemic cause (not the trigger).", "### What went well / what didn't", "- …", "### Corrective actions (owner + due date)",
      "1. …", "", "_Blameless. Focus on systems and processes._"].join("\n"),
  };
  const sysByMode: Record<string, string> = {
    summary: "You are a SOC incident lead. Write a concise incident summary (Markdown): severity/status, what we know, a reconstructed timeline, and prioritized next actions.",
    rootcause: "You are an incident-response analyst. Produce a root-cause analysis (Markdown): ranked hypotheses with how to confirm/refute each, a 5-Whys chain, contributing factors, and the systemic fix.",
    comms: "You are an incident communications lead. Draft tailored, factual update messages for: internal leadership, technical teams, external/customers (if needed), and the regulator (assess the NIS2/GDPR notification clock). No speculation.",
    postmortem: "You are writing a blameless postmortem (Markdown): Summary, Impact, Timeline, Root cause, What went well/badly, Corrective actions with owners and due dates.",
  };
  const out = await aiOrDet(sysByMode[mode], `Mode: ${mode}\n${ctx}`, dets[mode], 0.3);
  return { ...out, mode };
}

// ───────────────────────── 4. Risk register drafting + FAIR PERT calibration ─────────────────────────
export async function draftRisk(opts: { title?: string; asset?: string; threat?: string; context?: string }): Promise<AiText> {
  const title = (opts.title || opts.threat || "Cyber risk").trim();
  const ctx = [opts.asset && `Asset/scope: ${opts.asset}`, opts.threat && `Threat/source: ${opts.threat}`, opts.context && `Context: ${opts.context}`].filter(Boolean).join("\n");
  const det = [`## Risk — ${title}`, OFF, "",
    `**Risk statement:** As a result of *${opts.threat || "a credible threat"}* exploiting *a weakness*${opts.asset ? ` in **${opts.asset}**` : ""}, the organization could suffer loss of confidentiality/integrity/availability and associated business impact.`,
    "", "**Likelihood:** Medium (revise from threat intel / EPSS / exposure).  **Impact:** High (revise from asset value / BIA).",
    "**Inherent risk:** High.", "", "**Treatment options:**",
    "- **Mitigate** — implement/strengthen the relevant control(s) (recommended).", "- **Transfer** — insurance / contractual.",
    "- **Accept** — document risk acceptance with owner + expiry.", "- **Avoid** — discontinue the exposing activity.", "",
    "**Recommended treatment:** Mitigate. **Residual risk (target):** Medium. **Owner:** risk owner. **Review:** quarterly."].join("\n");
  const sys = "You are an enterprise risk analyst. From the context, draft a risk-register entry in Markdown: a clear cause→event→consequence risk statement, a likelihood and impact rating with rationale, inherent risk, treatment options (mitigate/transfer/accept/avoid) with a recommendation, and a target residual risk + owner + review cadence. Under 250 words.";
  return aiOrDet(sys, `Risk: ${title}\n${ctx || "(no extra context)"}`, det);
}

export async function calibrateFair(opts: { scenario?: string; asset?: string; context?: string }): Promise<AiText & { suggestion: Record<string, number> }> {
  const scenario = (opts.scenario || "Loss event").trim();
  // deterministic, defensible Beta-PERT starting estimates (annualized)
  const suggestion = { tefMin: 0.1, tefMl: 1, tefMax: 6, vuln: 0.5, lmMin: 10000, lmMl: 100000, lmMax: 1000000 };
  const det = [`## FAIR calibration — ${scenario}`, OFF, "",
    "Starting Beta-PERT estimates (annualized) — **calibrate with your data, then refine the ranges**:", "",
    "| Factor | Min | Most likely | Max |", "|---|---|---|---|",
    `| Threat Event Frequency (per yr) | ${suggestion.tefMin} | ${suggestion.tefMl} | ${suggestion.tefMax} |`,
    `| Vulnerability (P(loss\\|event)) | — | ${suggestion.vuln} | — |`,
    `| Loss Magnitude ($) | ${suggestion.lmMin.toLocaleString()} | ${suggestion.lmMl.toLocaleString()} | ${suggestion.lmMax.toLocaleString()} |`, "",
    `**Implied LEF** ≈ TEF × Vulnerability ≈ ${(suggestion.tefMl * suggestion.vuln).toFixed(2)} loss events/yr.`,
    `**Implied ALE (point)** ≈ LEF × LM(ml) ≈ $${Math.round(suggestion.tefMl * suggestion.vuln * suggestion.lmMl).toLocaleString()}/yr.`, "",
    "**Calibration notes:** anchor TEF on observed incidents / threat intel / EPSS; anchor Vulnerability on control strength vs. threat capability; anchor Loss Magnitude on primary (response, replacement) + secondary (fines, reputation, legal) losses. Use these as inputs to /fair-tef and /fair-mam — do not treat as ground truth."].join("\n");
  const sys = "You are a FAIR (Factor Analysis of Information Risk) quantification analyst. For the loss-event scenario, propose defensible Beta-PERT min/most-likely/max estimates for Threat Event Frequency (per year), Vulnerability (probability a threat event becomes a loss), and Loss Magnitude ($, primary+secondary). " +
    "Output a Markdown table plus the implied LEF and ALE and a short calibration rationale for each factor. Be explicit that these are starting estimates for human calibration. Under 280 words.";
  const out = await aiOrDet(sys, `Scenario: ${scenario}\n${[opts.asset && `Asset: ${opts.asset}`, opts.context].filter(Boolean).join("\n")}`, det, 0.3);
  return { ...out, suggestion };
}

// ───────────────────────── 5. Compliance execution (implementation / POA&M / gap analysis) ─────────────────────────
export async function draftControlImplementation(opts: { control?: string; framework?: string; context?: string }): Promise<AiText> {
  const control = (opts.control || "the control").trim();
  const det = [`## Implementation — ${control}`, OFF, "",
    `**Objective:** satisfy *${control}*${opts.framework ? ` (${opts.framework})` : ""}.`, "",
    "**Implementation statement:** Describe the policy, process and technical mechanism that meets the control, who is responsible, and how often it operates.", "",
    "**Concrete steps:**", "1. Assign an owner and document the policy/standard.", "2. Configure the technical mechanism (tooling, baseline).",
    "3. Operate it as a repeatable process with records.", "4. Monitor/measure effectiveness and review periodically.", "",
    "**Evidence to collect:** policy doc, configuration/screenshot, ticket/record of operation, review minutes."].join("\n");
  const sys = "You are a GRC analyst writing a control-implementation narrative. Produce Markdown: Objective, an implementation statement (policy + process + technical mechanism + responsibility + frequency), concrete numbered steps, and the evidence to collect for an auditor. Specific and auditable; under 280 words.";
  return aiOrDet(sys, `Control: ${control}\n${[opts.framework && `Framework: ${opts.framework}`, opts.context].filter(Boolean).join("\n")}`, det);
}

export async function draftPoam(opts: { weakness?: string; control?: string; severity?: string; context?: string }): Promise<AiText> {
  const weakness = (opts.weakness || "Identified weakness").trim();
  const det = [`## POA&M item — ${weakness}`, OFF, "",
    `**Weakness:** ${weakness}${opts.control ? ` (control: ${opts.control})` : ""}`, `**Severity:** ${opts.severity || "High"}`,
    "**Risk if unaddressed:** state the impact in business terms.", "", "**Remediation plan / milestones:**",
    "1. Short-term mitigation / compensating control (≤30 days).", "2. Permanent remediation (≤90 days).", "3. Verification & closure evidence.", "",
    "**Resources:** owner, team, budget.  **Scheduled completion:** set a realistic date.  **Status:** Open."].join("\n");
  const sys = "You are writing a NIST 800-53 / FedRAMP POA&M (Plan of Action & Milestones) item. Produce Markdown: Weakness, Severity, business risk if unaddressed, remediation plan with dated milestones (interim mitigation + permanent fix + verification), required resources, owner, scheduled completion, and status. Under 220 words.";
  return aiOrDet(sys, `Weakness: ${weakness}\n${[opts.control && `Control: ${opts.control}`, opts.severity && `Severity: ${opts.severity}`, opts.context].filter(Boolean).join("\n")}`, det);
}

export async function complianceGapAnalysis(opts: { framework?: string; objective?: string; context?: string }): Promise<AiText> {
  const fw = (opts.framework || "the framework").trim();
  const det = [`## Gap analysis — ${fw}${opts.objective ? ` · ${opts.objective}` : ""}`, OFF, "",
    "**Current state:** summarize what is in place today (controls, evidence).", "**Required state:** the framework's expectation.", "",
    "**Gaps:**", "- Policy/governance gap — …", "- Technical control gap — …", "- Evidence/operating gap — …", "",
    "**Prioritized remediation:** address the highest-risk gaps first; assign owners; track in a POA&M.", "",
    "_Tip: import the framework catalogue and map your controls so this analysis is data-driven._"].join("\n");
  const sys = "You are a compliance auditor doing a gap analysis. Produce Markdown: current state vs. required state, a prioritized list of gaps (governance / technical / evidence), and a remediation plan with owners. Be specific to the framework/objective; under 300 words.";
  return aiOrDet(sys, `Framework: ${fw}\n${[opts.objective && `Objective: ${opts.objective}`, opts.context].filter(Boolean).join("\n")}`, det);
}

// ───────────────────────── 6. Remediation advice (SCA / patch) ─────────────────────────
export async function remediationAdvice(opts: { cve?: string; component?: string; version?: string; asset?: string; context?: string }): Promise<AiText> {
  const subj = opts.cve || (opts.component ? `${opts.component}${opts.version ? `@${opts.version}` : ""}` : "the finding");
  let enrich = "";
  if (opts.cve) {
    try {
      const xv = getDb("XVULNERABILITY");
      const r = xv.prepare("SELECT KEV, EPSS, VULName FROM VULNERABILITY WHERE UPPER(VULReferential)=UPPER(?) LIMIT 1").get(opts.cve) as Record<string, unknown> | undefined;
      if (r) enrich = `KEV=${r.KEV ? "yes" : "no"}, EPSS=${r.EPSS ?? "-"}${r.VULName ? `, ${String(r.VULName).slice(0, 200)}` : ""}`;
    } catch { /* optional */ }
  }
  const det = [`## Remediation — ${subj}`, OFF, "", enrich && `**Signals:** ${enrich}`, "",
    "**Recommended action:** upgrade to the latest fixed version (preferred). If immediate upgrade isn't possible, apply a temporary mitigation / virtual patch and schedule the upgrade.", "",
    "**Steps:**", "1. Confirm the affected version and whether the vulnerable code path is actually used (reachability).",
    "2. Identify the fixed version and review breaking changes.", "3. Test the upgrade in staging; roll out with a rollback plan.",
    "4. If blocked: apply WAF/virtual-patch or config mitigation; restrict exposure; add detection.", "",
    "**Prioritization:** patch KEV / high-EPSS / internet-exposed instances first (risk-based SLA)."].filter(Boolean).join("\n");
  const sys = "You are a vulnerability-remediation engineer. For the given CVE/component, give concise Markdown advice: recommended fixed version / upgrade path, whether it's likely reachable, concrete steps (incl. staging + rollback), a temporary mitigation if upgrade is blocked, and risk-based prioritization (KEV/EPSS/exposure). Do not invent specific version numbers you aren't given. Under 260 words.";
  return aiOrDet(sys, `Subject: ${subj}\n${[enrich && `Signals: ${enrich}`, opts.asset && `Asset: ${opts.asset}`, opts.context].filter(Boolean).join("\n")}`, det);
}

// ───────────────────────── 7. Privacy (DPIA draft + breach assessment) ─────────────────────────
export async function draftDpia(opts: { processing?: string; dataCategories?: string; context?: string }): Promise<AiText> {
  const proc = (opts.processing || "the processing activity").trim();
  const det = [`## DPIA — ${proc}`, OFF, "",
    "**1. Description:** nature, scope, context and purposes of the processing.", `**2. Data categories:** ${opts.dataCategories || "(list personal/special-category data)"}.`,
    "**3. Necessity & proportionality:** lawful basis, data minimization, retention, data-subject rights.", "",
    "**4. Risks to individuals:**", "- Unauthorized access / disclosure", "- Excessive collection / retention", "- Loss of control / lack of transparency", "",
    "**5. Measures to mitigate:** encryption, access control, minimization, DPA with processors, transparency, retention limits.", "",
    "**6. Residual risk & sign-off:** DPO opinion + controller decision."].join("\n");
  const sys = "You are a Data Protection Officer drafting a GDPR Article 35 DPIA. Produce Markdown: description of processing, data categories, necessity & proportionality (lawful basis, minimization, retention, rights), risks to individuals, mitigating measures, and residual risk + sign-off. Under 320 words.";
  return aiOrDet(sys, `Processing: ${proc}\n${[opts.dataCategories && `Data: ${opts.dataCategories}`, opts.context].filter(Boolean).join("\n")}`, det);
}

export async function assessBreach(opts: { description?: string; dataCategories?: string; recordCount?: number }): Promise<AiText> {
  const det = [`## Breach assessment`, OFF, "",
    `**Incident:** ${opts.description || "(describe the breach)"}`, `**Data involved:** ${opts.dataCategories || "TBD"}${opts.recordCount ? ` · ~${opts.recordCount} records` : ""}`, "",
    "**Likely risk to individuals:** assess based on data sensitivity, volume, identifiability and potential consequences.", "",
    "**Notification obligations:**", "- **Supervisory authority (GDPR Art. 33):** within **72h** unless unlikely to result in risk.",
    "- **Data subjects (GDPR Art. 34):** without undue delay if **high** risk.", "- **NIS2 (if in scope):** 24h early warning / 72h notification / 1-month final report.", "",
    "**Immediate actions:** contain, preserve evidence, document the assessment, start the clock, prepare notifications."].join("\n");
  const sys = "You are a privacy/incident lead assessing a personal-data breach. Produce Markdown: likely risk to individuals (sensitivity × volume × identifiability), the notification verdict for the supervisory authority (GDPR 72h) and data subjects (Art. 34 high-risk) and NIS2 if applicable, and immediate actions. Be decisive about the clock. Under 240 words.";
  return aiOrDet(sys, `Breach: ${opts.description || ""}\nData: ${opts.dataCategories || ""}${opts.recordCount ? `\nRecords: ${opts.recordCount}` : ""}`, det);
}

// ───────────────────────── 8. Security awareness (phishing template + coaching) ─────────────────────────
export async function draftPhishingTemplate(opts: { theme?: string; difficulty?: string; pretext?: string }): Promise<AiText> {
  const theme = (opts.theme || "IT password reset").trim();
  const det = [`## Phishing-simulation template — ${theme}`, OFF, "_For authorized internal security-awareness testing only._", "",
    `**Difficulty:** ${opts.difficulty || "medium"}`, `**Pretext:** ${opts.pretext || theme}`, "",
    "**Subject:** Action required: verify your account", "**Sender (spoof-style, lookalike domain):** it-support@company-secure[.]example", "",
    "**Body:**", "> We detected unusual sign-in activity. To keep your account active, please confirm your details within 24 hours.", "> [Verify my account]  ← (tracked simulation link)", "",
    "**Red flags to teach:** urgency/threat, lookalike domain, generic greeting, unexpected link, request to authenticate.", "",
    "**Landing page:** show the red flags and a 60-second micro-lesson."].join("\n");
  const sys = "You are a security-awareness engineer building an AUTHORIZED internal phishing-simulation template (defensive training only). Produce Markdown: difficulty, pretext, a realistic subject line and sender style, a short body with a tracked simulation link placeholder, the red flags to teach, and the landing-page teaching points. Do not include real malicious infrastructure. Under 220 words.";
  return aiOrDet(sys, `Theme: ${theme}\n${[opts.difficulty && `Difficulty: ${opts.difficulty}`, opts.pretext && `Pretext: ${opts.pretext}`].filter(Boolean).join("\n")}`, det, 0.5);
}

export async function awarenessCoaching(opts: { name?: string; phishProne?: number; fails?: number; role?: string }): Promise<AiText> {
  const who = (opts.name || "this user").trim();
  const det = [`## Awareness coaching — ${who}`, OFF, "",
    `**Phish-prone:** ${opts.phishProne != null ? opts.phishProne + "%" : "—"}${opts.fails != null ? ` · failed sims: ${opts.fails}` : ""}${opts.role ? ` · role: ${opts.role}` : ""}`, "",
    "**Personalized plan:**", "1. Targeted micro-training on the specific lure type they fell for.", "2. Increase simulation frequency until improvement is sustained.",
    "3. Reinforce the 3 red flags: unexpected urgency, sender/domain mismatch, credential/link requests.", "4. Positive reinforcement on reporting (not just on clicking).", "",
    "**Manager note:** frame as support, not punishment; re-test in 30 days."].join("\n");
  const sys = "You are a human-risk / security-awareness coach. From the user's phish-prone score and history, write a short, supportive, personalized coaching plan (Markdown): targeted training, cadence, the specific behaviors to reinforce, and a manager note. Encouraging, non-punitive. Under 200 words.";
  return aiOrDet(sys, `User: ${who}\nPhish-prone: ${opts.phishProne ?? "?"}\nFails: ${opts.fails ?? "?"}\nRole: ${opts.role ?? "?"}`, det, 0.4);
}

// ───────────────────────── 9. SOC (alert triage + shift handover) ─────────────────────────
export async function socTriage(opts: { alerts?: { name?: string; severity?: string; technique?: string; detail?: string }[]; tenant?: number | null }): Promise<AiText> {
  let alerts = (opts.alerts || []).slice(0, 30);
  if (!alerts.length) {
    try {
      const xi = getDb("XINCIDENT");
      if (cols(xi, "ALERT").size) {
        const rows = xi.prepare("SELECT * FROM ALERT ORDER BY AlertID DESC LIMIT 20").all() as Record<string, unknown>[];
        alerts = rows.map((a) => ({ name: pick(a, ["Title", "AlertName", "Name"]), severity: pick(a, ["Severity"]), technique: pick(a, ["AttackTechnique", "Technique"]), detail: pick(a, ["Description"]) }));
      }
    } catch { /* optional */ }
  }
  const ctx = alerts.length ? alerts.map((a, i) => `${i + 1}. [${a.severity || "?"}] ${a.name || "alert"}${a.technique ? ` (${a.technique})` : ""}${a.detail ? ` — ${a.detail.slice(0, 160)}` : ""}`).join("\n") : "(no open alerts)";
  const det = [`## SOC triage`, OFF, "", `**Open alerts:** ${alerts.length}`, "",
    "**Suggested priority order:** critical/high first, then alerts sharing an ATT&CK technique or asset (likely the same incident).", "",
    "**For each alert:** validate (true/false positive), enrich (asset, identity, prevalence), decide (escalate to incident / monitor / close), and act.", "",
    "**Correlation:** cluster alerts by technique/asset/time — they may be one attack. Top of queue:",
    ...alerts.slice(0, 5).map((a, i) => `${i + 1}. [${a.severity || "?"}] ${a.name || "alert"}${a.technique ? ` · ${a.technique}` : ""}`)].join("\n");
  const sys = "You are a Tier-2 SOC analyst triaging the alert queue. Produce Markdown: a suggested priority order with one-line rationale per top alert, likely correlations (alerts that are probably the same incident), and recommended disposition (escalate/monitor/close) for the top few. Be decisive; under 280 words.";
  return aiOrDet(sys, `Open alerts:\n${ctx}`, det);
}

export async function shiftHandover(opts: { tenant?: number | null }): Promise<AiText> {
  let openInc = 0, openAlerts = 0;
  try {
    const xi = getDb("XINCIDENT");
    if (cols(xi, "INCIDENT").size) openInc = (xi.prepare("SELECT COUNT(*) n FROM INCIDENT WHERE LOWER(COALESCE(Status,'open')) NOT IN ('closed','resolved')").get() as { n: number }).n;
    if (cols(xi, "ALERT").size) openAlerts = (xi.prepare("SELECT COUNT(*) n FROM ALERT").get() as { n: number }).n;
  } catch { /* optional */ }
  const det = [`## SOC shift handover`, OFF, "", `**Open incidents:** ${openInc} · **Alerts in queue:** ${openAlerts}`, "",
    "**Ongoing / watch items:** (active incidents, their state and next step).", "**Escalations pending:** (awaiting decision/owner).",
    "**Completed this shift:** (closed incidents, tuning done).", "**For the next shift:** (specific follow-ups, scheduled tasks, things to watch).", "",
    "_Keep it factual and action-oriented._"].join("\n");
  const sys = "You are the outgoing SOC shift lead writing a handover. Produce Markdown: open incidents and their state/next step, pending escalations, what was completed this shift, and specific watch-items/follow-ups for the next shift. Concise and action-oriented; under 220 words.";
  return aiOrDet(sys, `Open incidents: ${openInc}\nAlerts in queue: ${openAlerts}`, det);
}

// ───────────────────────── 10. Malware multi-engine verdict synthesis ─────────────────────────
export async function synthesizeMalwareVerdict(opts: { indicator?: string; type?: string; engines?: { engine?: string; verdict?: string; detail?: string }[] }): Promise<AiText & { verdict: string }> {
  const ind = (opts.indicator || "indicator").trim();
  const engines = (opts.engines || []).slice(0, 20);
  const mal = engines.filter((e) => /malicious|detected|positive|suspicious|threat/i.test(`${e.verdict} ${e.detail}`)).length;
  const verdict = !engines.length ? "Unknown" : mal === 0 ? "Likely clean" : mal >= Math.max(2, Math.ceil(engines.length / 3)) ? "Malicious" : "Suspicious";
  const ctx = engines.length ? engines.map((e) => `- ${e.engine || "engine"}: ${e.verdict || "?"}${e.detail ? ` (${String(e.detail).slice(0, 160)})` : ""}`).join("\n") : "(no engine results)";
  const det = [`## Malware verdict — ${ind}`, OFF, "", `**Type:** ${opts.type || "—"} · **Engines flagging malicious/suspicious:** ${mal}/${engines.length}`,
    `**Synthesized verdict:** ${verdict}.`, "", "**Engine results:**", ctx, "",
    "**Recommended action:** " + (verdict === "Malicious" ? "treat as IOC — block, hunt for the indicator across the estate, and create an incident." : verdict === "Suspicious" ? "corroborate with a second source and sandbox before blocking." : verdict === "Likely clean" ? "no action; record the negative result." : "submit to the configured engines to obtain a verdict.")].join("\n");
  const sys = "You are a malware analyst synthesizing multi-engine reputation results into ONE verdict (Malicious / Suspicious / Likely clean / Unknown) with a one-line rationale, then a recommended action (block + hunt / corroborate + sandbox / no action). Weigh consensus and engine reliability; don't over-react to a single low-confidence hit. Markdown, under 200 words.";
  const out = await aiOrDet(sys, `Indicator: ${ind}\nType: ${opts.type || ""}\nEngine results:\n${ctx}`, det, 0.2);
  return { ...out, verdict };
}

// ───────────────────────── 11. OSINT graph insights ─────────────────────────
export async function osintGraphInsights(opts: { tenant?: number | null }): Promise<AiText> {
  let nodes = 0, edges = 0, sample = "";
  try {
    const xt = getDb("XTHREAT");
    if (cols(xt, "INTELEXCHANGE").size) {
      nodes = (xt.prepare("SELECT COUNT(*) n FROM INTELEXCHANGE").get() as { n: number }).n;
      const rows = xt.prepare("SELECT * FROM INTELEXCHANGE ORDER BY rowid DESC LIMIT 15").all() as Record<string, unknown>[];
      sample = rows.map((r) => `- ${pick(r, ["Name", "Title", "Value", "Indicator"]) || "node"} (${pick(r, ["Type", "Category"]) || "?"})`).join("\n");
    }
  } catch { /* optional */ }
  const det = [`## OSINT graph insights`, OFF, "", `**Nodes:** ${nodes}`, "",
    "**Look for:** clusters that share an indicator (domain/IP/email), bridges connecting otherwise-separate clusters (pivot points), and entities with unusually high degree (hubs / likely infrastructure).", "",
    sample && "**Recent entities:**", sample, "",
    "**Suggested next steps:** resolve duplicate entities, pivot on the highest-degree hubs, and label confirmed malicious clusters."].filter(Boolean).join("\n");
  const sys = "You are an OSINT link-analysis analyst (Palantir-style). From the entity sample, suggest Markdown insights: likely clusters, bridge/pivot entities, high-degree hubs, probable duplicate entities to merge, and the next investigative pivots. Under 240 words.";
  return aiOrDet(sys, `Graph nodes: ${nodes}\nRecent entities:\n${sample || "(none)"}`, det);
}

// ───────────────────────── 12. Hardening remediation (OVAL/CIS failed check) ─────────────────────────
export async function ovalRemediation(opts: { check?: string; result?: string; platform?: string }): Promise<AiText> {
  const check = (opts.check || "the failed check").trim();
  const det = [`## Hardening remediation — ${check}`, OFF, "", `**Platform:** ${opts.platform || "—"} · **Result:** ${opts.result || "fail"}`, "",
    "**Why it matters:** explain the security weakness this check protects against.", "",
    "**Remediation:**", "1. Apply the recommended secure setting (config/registry/policy).", "2. Validate the change and re-run the check.",
    "3. Roll out via configuration management / GPO / Ansible for consistency.", "", "**Rollback:** record the prior value before changing.",
    "**Caution:** test in a non-production system first — some hardening settings can affect functionality."].join("\n");
  const sys = "You are a systems-hardening engineer. For the failed OVAL/CIS check, produce Markdown: why it matters, concrete remediation steps (the setting to change and how, per the platform), how to validate, how to roll out at scale (config mgmt), rollback, and a caution about functional impact. Under 240 words.";
  return aiOrDet(sys, `Check: ${check}\nPlatform: ${opts.platform || ""}\nResult: ${opts.result || ""}`, det);
}

// ───────────────────────── 13. TPRM — vendor risk brief (Vendict-style) ─────────────────────────
export async function tprmVendorBrief(opts: {
  name?: string; services?: string; domain?: string; dataSensitivity?: string; businessCriticality?: string;
  tier?: string; postureScore?: number; postureGrade?: string; conformance?: number; residualTier?: string;
  usesAI?: boolean; aiUse?: string; findings?: { title?: string; severity?: string; detail?: string }[];
}): Promise<AiText> {
  const name = (opts.name || "the vendor").trim();
  const f = (opts.findings || []).filter((x) => (x.severity || "").toLowerCase() !== "info");
  const high = f.filter((x) => /crit|high/i.test(x.severity || ""));
  const aiFollow = opts.usesAI ? [
    "Does the vendor train or fine-tune models on our data, and can we opt out?",
    "What is the retention/deletion timeframe for prompts and outputs?",
    "What guardrails exist against prompt injection, data leakage and harmful output?",
    "Is there human oversight and an incident process for AI failures (per ISO/IEC 42001)?",
  ] : [];
  const baseFollow = [
    /pii|phi|regulated|restricted/i.test(opts.dataSensitivity || "") ? "Confirm data-processing terms, sub-processors and breach-notification SLAs (GDPR Art. 28/33)." : "Confirm what data is shared and where it is stored/processed.",
    Number(opts.postureScore ?? 100) < 80 ? "Remediate the open external posture findings (TLS/headers) before go-live." : "Maintain the current external posture and re-scan on cadence.",
    opts.conformance == null ? "Send the security questionnaire (CSA AI-CAIQ / OCIL) and collect evidence." : (Number(opts.conformance) < 70 ? "Close the questionnaire gaps; require evidence for any 'No'/'Partial'." : "Spot-check the questionnaire evidence at renewal."),
  ];
  const det = [
    `## Vendor risk brief — ${name}`, OFF, "",
    `**Service:** ${opts.services || "—"}${opts.domain ? ` · **Domain:** ${opts.domain}` : ""}`,
    `**Inherent:** ${opts.tier || tierFromWords(opts.dataSensitivity, opts.businessCriticality)} (data ${opts.dataSensitivity || "?"} × criticality ${opts.businessCriticality || "?"}) · **Posture:** ${opts.postureGrade || "—"}${opts.postureScore != null ? ` (${opts.postureScore}/100)` : ""} · **Questionnaire:** ${opts.conformance != null ? `${opts.conformance}% conformance` : "not assessed"} · **Residual:** ${opts.residualTier || "—"}`,
    opts.usesAI ? `\n**AI use:** ${opts.aiUse || "this vendor processes data with AI — treat as in-scope for AI-TRiSM."}` : "",
    "", "### Key risks",
    ...(high.length ? high.map((x) => `- **${x.severity?.toUpperCase()}** — ${x.title}${x.detail ? `: ${x.detail}` : ""}`) : ["- No critical/high findings recorded yet — complete the external scan and questionnaire."]),
    "", "### Recommended verdict",
    `- ${verdictFor(opts)}`,
    "", "### Follow-up questions to send the vendor",
    ...[...aiFollow, ...baseFollow].map((q) => `- ${q}`),
  ].filter((l) => l !== "").join("\n");
  const sys = "You are a third-party risk (TPRM) analyst. From the vendor signals, write a concise Markdown brief: 1-line service summary, the key risks (call out AI-specific risk if the vendor uses AI), a recommended verdict (approve / approve-with-conditions / remediate-then-approve / reject) with the conditions, and 4-6 targeted follow-up questions to send the vendor. Ground it in the data sensitivity, posture and questionnaire conformance. Under 260 words.";
  const user = JSON.stringify(opts).slice(0, 6000);
  return aiOrDet(sys, user, det);
}
function tierFromWords(data?: string, crit?: string): string {
  const dw: Record<string, number> = { none: 0, internal: 25, confidential: 50, pii: 75, phi: 85, regulated: 100, restricted: 100 };
  const cw: Record<string, number> = { low: 25, medium: 50, high: 75, critical: 100 };
  const s = 0.5 * (dw[(data || "").toLowerCase().replace(/[^a-z]/g, "")] ?? 25) + 0.5 * (cw[(crit || "").toLowerCase().replace(/[^a-z]/g, "")] ?? 50);
  return s >= 75 ? "Critical" : s >= 50 ? "High" : s >= 25 ? "Medium" : "Low";
}
function verdictFor(o: { postureScore?: number; conformance?: number; residualTier?: string; findings?: { severity?: string }[] }): string {
  const crit = (o.findings || []).some((x) => /crit/i.test(x.severity || ""));
  const p = o.postureScore ?? 100, c = o.conformance ?? 0;
  if (crit || p < 55) return "**Remediate-then-approve** — critical exposure or a failing posture grade must be fixed before onboarding.";
  if (o.residualTier === "Critical" || o.residualTier === "High") return "**Approve with conditions** — accept under a remediation plan, evidence for questionnaire gaps and a short review cadence.";
  if (o.conformance != null && c < 70) return "**Approve with conditions** — close the questionnaire gaps and collect evidence.";
  return "**Approve** — residual risk is within appetite; review on the standard cadence.";
}

// ───────────────────────── 14. TPRM — questionnaire review (gaps / red flags / verdict) ─────────────────────────
export async function tprmReviewQuestionnaire(opts: { runId?: number; tenant?: number | null }): Promise<AiText> {
  let rows: { name: string; text: string; answer: string; comment: string; section: string }[] = [];
  let runName = "the questionnaire run"; let conf: number | null = null;
  if (opts.runId) {
    try {
      const db = getDb("XCOMPLIANCE");
      const run = db.prepare("SELECT Name, QuestionnaireName, Conformance FROM QUESTIONNAIRERUN WHERE RunID = ?").get(opts.runId) as any;
      if (run) { runName = String(run.Name || run.QuestionnaireName || runName); conf = run.Conformance != null ? Number(run.Conformance) : null; }
      rows = (db.prepare(`SELECT r.Section, r.Answer, r.Comment, q.QuestionName, q.QuestionText
        FROM QUESTIONNAIRERESPONSE r LEFT JOIN QUESTION q ON q.QuestionID = r.QuestionID WHERE r.RunID = ? ORDER BY r.DisplayOrder`).all(opts.runId) as any[])
        .map((x) => ({ name: String(x.QuestionName || ""), text: String(x.QuestionText || ""), answer: String(x.Answer || "").toLowerCase(), comment: String(x.Comment || ""), section: String(x.Section || "") }));
    } catch { /* none */ }
  }
  const answered = rows.filter((r) => r.answer);
  const nos = rows.filter((r) => r.answer === "no");
  const partials = rows.filter((r) => r.answer === "partial");
  const noEvidence = answered.filter((r) => (r.answer === "yes") && !r.comment.trim());
  const det = [
    `## Questionnaire review — ${runName}`, OFF, "",
    `**Answered:** ${answered.length}/${rows.length}${conf != null ? ` · **Conformance:** ${conf}%` : ""}`,
    "", "### Gaps (answered No)",
    ...(nos.length ? nos.slice(0, 20).map((r) => `- **${r.name}** — ${shorten(r.text)}${r.comment ? ` _(note: ${shorten(r.comment, 100)})_` : ""}`) : ["- None."]),
    "", "### Partial / needs follow-up",
    ...(partials.length ? partials.slice(0, 20).map((r) => `- **${r.name}** — ${shorten(r.text)}`) : ["- None."]),
    "", "### Red flags",
    ...redFlags(nos, partials, noEvidence),
    "", "### Verdict",
    `- ${conf == null ? "Incomplete — finish the questionnaire before deciding." : conf >= 80 ? "**Acceptable** — strong conformance; spot-check evidence." : conf >= 60 ? "**Conditional** — acceptable only with a remediation plan for the gaps above." : "**Insufficient** — too many gaps; require remediation and re-assessment before onboarding."}`,
  ].join("\n");
  const sys = "You are a TPRM analyst reviewing a completed vendor security questionnaire. Identify the material gaps (answered No), the items needing follow-up (Partial), any red flags (e.g. Yes with no evidence on a critical control), and give a verdict (acceptable / conditional / insufficient) with the conditions. Markdown, under 280 words.";
  const user = JSON.stringify({ runName, conf, responses: rows.slice(0, 120) }).slice(0, 11000);
  return aiOrDet(sys, user, det);
}
function redFlags(nos: any[], partials: any[], noEvidence: any[]): string[] {
  const out: string[] = [];
  const hit = (arr: any[], re: RegExp) => arr.filter((r) => re.test(r.text + " " + r.name));
  const enc = hit(nos, /encrypt/i); if (enc.length) out.push(`- Encryption gap: ${enc.length} encryption control(s) answered No.`);
  const mfa = hit(nos, /mfa|multi-factor|authentication/i); if (mfa.length) out.push(`- Authentication gap: ${mfa.length} access/MFA control(s) answered No.`);
  const ir = hit(nos, /incident|breach|notif/i); if (ir.length) out.push(`- Incident-response gap: ${ir.length} incident/breach control(s) answered No.`);
  if (noEvidence.length > 5) out.push(`- ${noEvidence.length} "Yes" answers carry no evidence/comment — request supporting evidence.`);
  if (!out.length) out.push("- No automatic red flags detected — confirm evidence for the high-impact controls.");
  return out;
}

// ───────────────────────── 15. TPRM — auto-draft questionnaire answers (Vendict-style) ─────────────────────────
export async function tprmDraftAnswers(opts: { runId?: number; knowledge?: string; max?: number; tenant?: number | null }): Promise<AiText & { suggestions: { name: string; answer: string; rationale: string }[] }> {
  const kb = (opts.knowledge || "").trim();
  const kbTokens = tokens(kb);
  let rows: { name: string; text: string; answer: string }[] = [];
  if (opts.runId) {
    try {
      const db = getDb("XCOMPLIANCE");
      rows = (db.prepare(`SELECT r.Answer, q.QuestionName, q.QuestionText FROM QUESTIONNAIRERESPONSE r LEFT JOIN QUESTION q ON q.QuestionID = r.QuestionID
        WHERE r.RunID = ? AND (r.Answer IS NULL OR r.Answer = '') ORDER BY r.DisplayOrder LIMIT ?`).all(opts.runId, Math.min(opts.max || 40, 120)) as any[])
        .map((x) => ({ name: String(x.QuestionName || ""), text: String(x.QuestionText || ""), answer: "" }));
    } catch { /* none */ }
  }
  // deterministic suggestion: if the knowledge base overlaps the question, suggest Yes w/ that evidence, else flag
  const suggestions = rows.map((r) => {
    const overlap = jaccard(tokens(r.text + " " + r.name), kbTokens);
    if (kb && overlap >= 0.06) return { name: r.name, answer: "yes", rationale: "Supported by the knowledge base — attach the relevant policy/control as evidence." };
    if (/encrypt|tls|https/i.test(r.text) && /encrypt|tls|aes|https/i.test(kb)) return { name: r.name, answer: "yes", rationale: "Encryption is documented in the knowledge base." };
    return { name: r.name, answer: "", rationale: "Not covered by the knowledge base — answer manually and provide evidence." };
  });
  const covered = suggestions.filter((s) => s.answer === "yes").length;
  const det = [
    `## Draft questionnaire answers`, OFF, "",
    kb ? `Matched **${covered}/${suggestions.length}** unanswered question(s) to your knowledge base.` : "_Provide a knowledge base (policies, prior answers, control descriptions) so answers can be drafted._",
    "", ...suggestions.slice(0, 40).map((s) => `- **${s.name}** → ${s.answer ? `**${s.answer.toUpperCase()}**` : "_manual_"} — ${s.rationale}`),
    "", "_Review every suggested answer before submitting — drafts must be verified against evidence._",
  ].join("\n");
  const sys = "You are a vendor security analyst auto-filling a security questionnaire from a knowledge base of policies and prior answers. For each unanswered question, propose Yes/No/Partial/NA and a one-line rationale citing the knowledge base. Only answer Yes when the knowledge base supports it; otherwise flag for manual review. Return Markdown.";
  const user = JSON.stringify({ knowledge: kb.slice(0, 6000), questions: rows.slice(0, 60) }).slice(0, 12000);
  const out = await aiOrDet(sys, user, det);
  return { ...out, suggestions };
}
function shorten(s: string, n = 80): string { s = String(s || "").replace(/\s+/g, " ").trim(); return s.length > n ? s.slice(0, n) + "…" : s; }
