/**
 * threatcopilot.ts — Threat-Intel Copilot (Exvora-inspired: "noise → signal, decision-ready intelligence").
 *
 * Two capabilities, both grounded in XORCISM's own data (no external SaaS — exvora.ai has no public API):
 *
 *  1. decisionReadyFeed() — turns the vulnerability/threat firehose into a short, decision-ready list:
 *     every relevant CVE is scored to one of **Act / Prioritise / Track** (the SSVC-style verdicts Exvora
 *     surfaces) from KEV (active exploitation) + EPSS (exploit probability) + CVSS + the stored SSVC
 *     decision, each with a confidence and a plain-English "why". Scoped to the tenant's estate
 *     (ASSETVULNERABILITY) when links exist, else the global KEV/high-EPSS frontier.
 *
 *  2. copilotAnswer(mode, question) — a "Vera"-style analyst with four modes (Ask / Investigate / Draft /
 *     Challenge). It runs deterministic queries over XVULNERABILITY / XTHREAT / XINCIDENT / XORCISM, then
 *     (optionally) has the local LLM synthesise an answer — and ALWAYS returns the queries it ran and the
 *     sources it cited, so the analyst can see how the answer was reached. Works offline (deterministic
 *     fallback) when no local model is reachable.
 */
import { getDb } from "./db";
import { ollamaChat, aiProviderInfo } from "./ai";

const xo = (): ReturnType<typeof getDb> => getDb("XORCISM");
const xv = (): ReturnType<typeof getDb> => getDb("XVULNERABILITY");
const xt = (): ReturnType<typeof getDb> => getDb("XTHREAT");
const xi = (): ReturnType<typeof getDb> => getDb("XINCIDENT");

function cols(db: ReturnType<typeof getDb>, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(db: ReturnType<typeof getDb>, t: string): boolean {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
}
const truthy = (v: unknown): boolean => v === 1 || v === "1" || v === true || String(v ?? "").toLowerCase() === "true";
const numOr = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; };

// ── 1) decision-ready triage (Act / Prioritise / Track) ─────────────────────────
export type Decision = "Act" | "Prioritise" | "Track";
export interface DecisionItem {
  vid: number; cve: string; title: string; decision: Decision; confidence: "High" | "Medium" | "Low";
  kev: boolean; epss: number | null; cvss: number | null; ssvc: string | null; assets: number; why: string;
}
const DEC_RANK: Record<Decision, number> = { Act: 0, Prioritise: 1, Track: 2 };

function decide(kev: boolean, epss: number | null, cvss: number | null, ssvc: string | null): { decision: Decision; confidence: DecisionItem["confidence"]; why: string } {
  const s = String(ssvc || "").toLowerCase();
  let decision: Decision = "Track";
  const why: string[] = [];
  if (kev) { decision = "Act"; why.push("KEV — actively exploited"); }
  if (/\bact\b/.test(s)) { decision = "Act"; why.push("SSVC: Act"); }
  else if (/attend/.test(s)) { if (decision !== "Act") decision = "Prioritise"; why.push("SSVC: Attend"); }
  else if (/track\s*\*/.test(s)) { if (decision !== "Act") decision = "Prioritise"; why.push("SSVC: Track*"); }
  if (epss != null && epss >= 0.7 && cvss != null && cvss >= 7) { decision = "Act"; why.push(`EPSS ${(epss * 100).toFixed(0)}% + CVSS ${cvss}`); }
  else if (epss != null && epss >= 0.4) { if (decision === "Track") decision = "Prioritise"; why.push(`EPSS ${(epss * 100).toFixed(0)}%`); }
  if (cvss != null && cvss >= 9 && decision === "Track") { decision = "Prioritise"; why.push(`CVSS ${cvss}`); }
  const confidence: DecisionItem["confidence"] = (kev || s) ? "High" : (epss != null ? "Medium" : "Low");
  if (!why.length) why.push(cvss != null ? `CVSS ${cvss}` : "no exploitation signal");
  return { decision, confidence, why: why.join(" · ") };
}

export interface DecisionFeed {
  scope: "estate" | "global"; summary: { act: number; prioritise: number; track: number; total: number };
  items: DecisionItem[];
}
export function decisionReadyFeed(tenant: number | null, limit = 100): DecisionFeed {
  const v = xv();
  const vc = cols(v, "VULNERABILITY");
  if (!vc.size) return { scope: "global", summary: { act: 0, prioritise: 0, track: 0, total: 0 }, items: [] };
  const idCol = vc.has("VULName") ? "VULName" : vc.has("VULShortName") ? "VULShortName" : "VulnerabilityID";
  const titleCol = vc.has("VULDescription") ? "VULDescription" : (vc.has("VULShortName") ? "VULShortName" : idCol);
  const kevSel = vc.has("KEV") ? "KEV" : "0 AS KEV";
  const epssSel = vc.has("EPSS") ? "EPSS" : "NULL AS EPSS";
  const cvssSel = vc.has("CVSSBaseScore") ? "CVSSBaseScore" : "NULL AS CVSSBaseScore";
  const ssvcSel = vc.has("SsvcDecision") ? "SsvcDecision" : "NULL AS SsvcDecision";

  // Estate scope: CVEs linked to the tenant's assets.
  const assetCount = new Map<number, number>();
  let vids: number[] = [];
  if (has(xo(), "ASSETVULNERABILITY")) {
    const av = cols(xo(), "ASSETVULNERABILITY");
    const fp = av.has("FalsePositive") ? "AND (FalsePositive IS NULL OR FalsePositive=0)" : "";
    const tw = tenant != null && av.has("TenantID") ? `AND TenantID = ${Number(tenant)}` : "";
    for (const r of xo().prepare(`SELECT VulnerabilityID v, COUNT(DISTINCT AssetID) n FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${fp} ${tw} GROUP BY VulnerabilityID`).all() as { v: number; n: number }[]) {
      assetCount.set(Number(r.v), Number(r.n)); vids.push(Number(r.v));
    }
  }
  const scope: DecisionFeed["scope"] = vids.length ? "estate" : "global";

  let rows: Record<string, unknown>[] = [];
  if (scope === "estate") {
    for (let i = 0; i < vids.length; i += 400) {
      const chunk = vids.slice(i, i + 400); const ph = chunk.map(() => "?").join(",");
      rows.push(...v.prepare(`SELECT VulnerabilityID, ${idCol} cve, ${titleCol} title, ${kevSel}, ${epssSel}, ${cvssSel}, ${ssvcSel} FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as Record<string, unknown>[]);
    }
  } else {
    const where = vc.has("KEV") ? "WHERE KEV IS NOT NULL AND KEV NOT IN ('0','false','')" : (vc.has("EPSS") ? "WHERE EPSS >= 0.3" : "");
    const order = vc.has("EPSS") ? "ORDER BY EPSS DESC" : (vc.has("CVSSBaseScore") ? "ORDER BY CVSSBaseScore DESC" : "");
    rows = v.prepare(`SELECT VulnerabilityID, ${idCol} cve, ${titleCol} title, ${kevSel}, ${epssSel}, ${cvssSel}, ${ssvcSel} FROM VULNERABILITY ${where} ${order} LIMIT 600`).all() as Record<string, unknown>[];
  }

  const items: DecisionItem[] = rows.map((r) => {
    const kev = truthy(r.KEV); const epss = numOr(r.EPSS); const cvss = numOr(r.CVSSBaseScore); const ssvc = r.SsvcDecision ? String(r.SsvcDecision) : null;
    const d = decide(kev, epss, cvss, ssvc);
    return {
      vid: Number(r.VulnerabilityID), cve: String(r.cve || `VID#${r.VulnerabilityID}`), title: String(r.title || "").slice(0, 160),
      decision: d.decision, confidence: d.confidence, kev, epss, cvss, ssvc, assets: assetCount.get(Number(r.VulnerabilityID)) || 0, why: d.why,
    };
  });
  items.sort((a, b) => DEC_RANK[a.decision] - DEC_RANK[b.decision] || (b.epss ?? 0) - (a.epss ?? 0) || (b.cvss ?? 0) - (a.cvss ?? 0) || b.assets - a.assets);
  const top = items.slice(0, limit);
  const summary = { act: items.filter((i) => i.decision === "Act").length, prioritise: items.filter((i) => i.decision === "Prioritise").length, track: items.filter((i) => i.decision === "Track").length, total: items.length };
  return { scope, summary, items: top };
}

// ── 2) "Vera"-style multi-mode analyst ──────────────────────────────────────────
export type CopilotMode = "ask" | "investigate" | "draft" | "challenge";
export interface CopilotQuery { label: string; detail: string; count?: number }
export interface CopilotSource { type: string; ref: string; label: string }
export interface CopilotAnswer { mode: CopilotMode; answer: string; queries: CopilotQuery[]; sources: CopilotSource[]; model: string; offline: boolean }

interface Gathered { context: string; queries: CopilotQuery[]; sources: CopilotSource[] }

/** Run the deterministic queries that ground an answer; returns context text + the queries/sources to cite. */
function gather(mode: CopilotMode, question: string, tenant: number | null): Gathered {
  const queries: CopilotQuery[] = []; const sources: CopilotSource[] = []; const lines: string[] = [];
  const q = (label: string, detail: string, count?: number): void => { queries.push({ label, detail, count }); };

  // Always: decision-ready posture snapshot.
  const feed = decisionReadyFeed(tenant, 12);
  q("decision-ready triage", `score CVEs (KEV/EPSS/CVSS/SSVC) → Act/Prioritise/Track [${feed.scope}]`, feed.summary.total);
  lines.push(`Decision-ready posture (${feed.scope}): Act=${feed.summary.act}, Prioritise=${feed.summary.prioritise}, Track=${feed.summary.track} (of ${feed.summary.total}).`);
  feed.items.slice(0, 8).forEach((i) => {
    lines.push(`- [${i.decision}] ${i.cve} — ${i.why}${i.assets ? ` (${i.assets} asset${i.assets > 1 ? "s" : ""})` : ""}`);
    sources.push({ type: "CVE", ref: i.cve, label: `${i.cve} (${i.decision})` });
  });

  const entity = extractEntity(question);

  if (mode === "investigate" && entity.cve) {
    const v = xv(); const vc = cols(v, "VULNERABILITY");
    const idCol = vc.has("VULName") ? "VULName" : "VULShortName";
    const row = v.prepare(`SELECT VulnerabilityID, ${vc.has("VULDescription") ? "VULDescription" : "''"} d, ${vc.has("KEV") ? "KEV" : "0"} KEV, ${vc.has("EPSS") ? "EPSS" : "NULL"} EPSS, ${vc.has("CVSSBaseScore") ? "CVSSBaseScore" : "NULL"} CVSSBaseScore, ${vc.has("SsvcDecision") ? "SsvcDecision" : "NULL"} SsvcDecision FROM VULNERABILITY WHERE ${idCol} = ? LIMIT 1`).get(entity.cve) as Record<string, unknown> | undefined;
    q("CVE lookup", `VULNERABILITY where ${idCol}=${entity.cve}`, row ? 1 : 0);
    if (row) {
      const d = decide(truthy(row.KEV), numOr(row.EPSS), numOr(row.CVSSBaseScore), row.SsvcDecision ? String(row.SsvcDecision) : null);
      lines.push(`CVE ${entity.cve}: ${String(row.d || "").slice(0, 280)}`);
      lines.push(`Signals → ${d.decision} (${d.why}).`);
      sources.push({ type: "CVE", ref: entity.cve, label: entity.cve });
      if (has(xo(), "ASSETVULNERABILITY")) {
        const av = cols(xo(), "ASSETVULNERABILITY");
        const tw = tenant != null && av.has("TenantID") ? `AND TenantID = ${Number(tenant)}` : "";
        const affected = xo().prepare(`SELECT COUNT(DISTINCT AssetID) n FROM ASSETVULNERABILITY WHERE VulnerabilityID = ? ${tw}`).get(Number(row.VulnerabilityID)) as { n: number };
        q("affected assets", `ASSETVULNERABILITY where VulnerabilityID=${row.VulnerabilityID}`, affected.n);
        lines.push(`Affected assets in scope: ${affected.n}.`);
      }
    } else lines.push(`CVE ${entity.cve} is not in the local vulnerability store.`);
  } else if (mode === "investigate" && entity.actor) {
    const t = xt();
    if (has(t, "THREATACTOR")) {
      const a = t.prepare(`SELECT ThreatActorName, ThreatActorDescription, country, Aliases FROM THREATACTOR WHERE ThreatActorName LIKE ? OR Aliases LIKE ? LIMIT 1`).get(`%${entity.actor}%`, `%${entity.actor}%`) as Record<string, unknown> | undefined;
      q("threat-actor lookup", `THREATACTOR like ${entity.actor}`, a ? 1 : 0);
      if (a) { lines.push(`Threat actor ${a.ThreatActorName} (${a.country || "?"}): ${String(a.ThreatActorDescription || "").slice(0, 300)}`); sources.push({ type: "ThreatActor", ref: String(a.ThreatActorName), label: String(a.ThreatActorName) }); }
    }
  }

  if (mode === "challenge") {
    const t = xt();
    if (has(t, "HYPOTHESIS")) {
      const hyps = t.prepare(`SELECT HypothesisName, HypothesisDescription, Confidence FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 6`).all() as Record<string, unknown>[];
      q("active hypotheses", "HYPOTHESIS (latest)", hyps.length);
      hyps.forEach((h) => { lines.push(`Hypothesis: ${h.HypothesisName} — conf ${h.Confidence ?? "?"}`); sources.push({ type: "Hypothesis", ref: String(h.HypothesisName), label: String(h.HypothesisName) }); });
    }
  }

  // Recent threat reporting (signal context).
  if (has(xt(), "THREATREPORT")) {
    const reps = xt().prepare(`SELECT ThreatReportName, ${cols(xt(), "THREATREPORT").has("AiSummary") ? "AiSummary" : "ThreatReportDescription"} s FROM THREATREPORT ORDER BY CreatedDate DESC LIMIT 4`).all() as Record<string, unknown>[];
    q("recent threat reports", "THREATREPORT (latest 4)", reps.length);
    reps.forEach((r) => { if (r.ThreatReportName) sources.push({ type: "Report", ref: String(r.ThreatReportName), label: String(r.ThreatReportName).slice(0, 60) }); });
  }
  // Open incidents.
  if (has(xi(), "INCIDENT")) {
    const ic = cols(xi(), "INCIDENT");
    const tw = tenant != null && ic.has("TenantID") ? `WHERE TenantID = ${Number(tenant)}` : "";
    const n = xi().prepare(`SELECT COUNT(*) n FROM INCIDENT ${tw}`).get() as { n: number };
    q("incidents", "INCIDENT count", n.n);
    lines.push(`Incidents on record: ${n.n}.`);
  }

  return { context: lines.join("\n"), queries, sources: dedupSources(sources) };
}

function dedupSources(s: CopilotSource[]): CopilotSource[] {
  const seen = new Set<string>(); const out: CopilotSource[] = [];
  for (const x of s) { const k = `${x.type}:${x.ref}`; if (!seen.has(k)) { seen.add(k); out.push(x); } if (out.length >= 24) break; }
  return out;
}
function extractEntity(question: string): { cve?: string; actor?: string } {
  const cve = /CVE-\d{4}-\d{4,7}/i.exec(question)?.[0]?.toUpperCase();
  const actor = /\b(APT\s?\d+|Lazarus|Sandworm|FIN\d+|Conti|LockBit|Scattered Spider|Volt Typhoon|Fancy Bear|Cozy Bear)\b/i.exec(question)?.[0];
  return { cve, actor };
}

const MODE_SYSTEM: Record<CopilotMode, string> = {
  ask: "You are a senior threat-intelligence analyst. Answer the question concisely (<=180 words) using ONLY the evidence provided. State the decision-ready takeaway first. Do not invent CVEs or facts.",
  investigate: "You are a CTI investigator. From the evidence, summarise what is known about the entity, its exposure in this environment, and the recommended decision (Act/Prioritise/Track). <=200 words.",
  draft: "You are writing a board-ready threat-landscape brief. Use the evidence to produce a crisp executive summary: top risks, why now, exposure, and recommended actions. Plain business English, <=220 words.",
  challenge: "You are a red-team analyst applying Analysis of Competing Hypotheses. For the stated hypothesis, give: (1) the strongest supporting evidence, (2) the strongest disconfirming evidence or alternative explanation, (3) a cognitive-bias checklist (anchoring, confirmation, availability) with a one-line check each, and (4) a calibrated confidence. <=220 words.",
};

function offlineAnswer(mode: CopilotMode, question: string, g: Gathered): string {
  const head: Record<CopilotMode, string> = {
    ask: "Decision-ready answer (offline synthesis):",
    investigate: "Investigation summary (offline synthesis):",
    draft: "Threat-landscape brief (offline synthesis):",
    challenge: "Competing-hypotheses review (offline synthesis):",
  };
  let body = `${head[mode]}\n\n${g.context}`;
  if (mode === "challenge") {
    body += `\n\nBias checklist:\n- Anchoring: are we over-weighting the first/loudest signal? Re-rank by EPSS×exposure, not recency.\n- Confirmation: did we seek disconfirming evidence (assets NOT affected, compensating controls)?\n- Availability: is a recent headline inflating perceived likelihood vs. base rates?`;
  }
  if (mode === "draft") body += `\n\nRecommended actions: remediate all "Act" items first, schedule "Prioritise", and track the rest. Validate exposure against the asset estate.`;
  body += `\n\nQuestion: ${question || "(none)"}`;
  return body;
}

export async function copilotAnswer(mode: CopilotMode, question: string, tenant: number | null): Promise<CopilotAnswer> {
  const m: CopilotMode = (["ask", "investigate", "draft", "challenge"] as CopilotMode[]).includes(mode) ? mode : "ask";
  const g = gather(m, question || "", tenant);
  const info = aiProviderInfo();
  let answer = ""; let offline = false; let model = info.model;
  const userMsg = `Question / topic: ${question || "(give a posture overview)"}\n\nEvidence:\n${g.context}`;
  try {
    answer = (await ollamaChat([{ role: "system", content: MODE_SYSTEM[m] }, { role: "user", content: userMsg }], 0.2, 60000)).trim();
    if (!answer) throw new Error("empty");
  } catch {
    offline = true; model = "offline"; answer = offlineAnswer(m, question || "", g);
  }
  return { mode: m, answer, queries: g.queries, sources: g.sources, model, offline };
}
