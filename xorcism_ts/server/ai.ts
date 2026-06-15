/**
 * ai.ts — Integration of a local LLM (Ollama) with lightweight RAG over XORCISM data.
 *
 * Config (environment variables, never entered in the UI):
 *   OLLAMA_URL    base of the Ollama API (default http://localhost:11434)
 *   OLLAMA_MODEL  model to use           (default llama3.1:8b)
 *
 * No data leaves the machine: everything goes through the local Ollama server.
 */
import { getDb, assetRiskExposure } from "./db";

const OLLAMA_URL = (process.env.OLLAMA_URL || "http://localhost:11434").replace(/\/$/, "");
export const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3.1:8b";

interface ChatMsg { role: "system" | "user" | "assistant"; content: string }

export async function ollamaChat(messages: ChatMsg[], temperature = 0.2): Promise<string> {
  const r = await fetch(`${OLLAMA_URL}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: OLLAMA_MODEL, messages, stream: false, options: { temperature } }),
  });
  if (!r.ok) throw new Error(`Ollama HTTP ${r.status}`);
  const data = (await r.json()) as { message?: { content?: string }; error?: string };
  if (data.error) throw new Error(data.error);
  return (data.message?.content || "").trim();
}

export async function ollamaStatus(): Promise<{ reachable: boolean; url: string; model: string; models: string[] }> {
  try {
    const r = await fetch(`${OLLAMA_URL}/api/tags`);
    if (!r.ok) return { reachable: false, url: OLLAMA_URL, model: OLLAMA_MODEL, models: [] };
    const d = (await r.json()) as { models?: { name: string }[] };
    return { reachable: true, url: OLLAMA_URL, model: OLLAMA_MODEL, models: (d.models || []).map((m) => m.name) };
  } catch {
    return { reachable: false, url: OLLAMA_URL, model: OLLAMA_MODEL, models: [] };
  }
}

const STOPWORDS = new Set([
  "what", "which", "most", "current", "threat", "threats", "organisation", "organization",
  "cyber", "impacting", "impact", "there", "about", "with", "from", "that", "this", "your",
  "our", "are", "the", "for", "and", "how", "should", "could", "would", "have",
]);

/** Fetches the relevant RAG context from XORCISM (best-effort, each block isolated). */
export function buildThreatContext(question: string): { text: string; sources: string[] } {
  const blocks: string[] = [];
  const sources: string[] = [];
  const kw = Array.from(
    new Set((question || "").toLowerCase().split(/[^a-z0-9.]+/).filter((w) => w.length >= 4 && !STOPWORDS.has(w)))
  ).slice(0, 6);

  // 1) KEV vulnerabilities (actively exploited) present on the org's assets (cross-database join).
  try {
    const xo = getDb("XORCISM");
    const xv = getDb("XVULNERABILITY");
    const avs = xo.prepare("SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL").all() as { AssetID: number; VulnerabilityID: unknown }[];
    if (avs.length) {
      const kevRows = xv.prepare("SELECT VULReferentialID, VULReferential FROM VULNERABILITY WHERE KEV=1").all() as { VULReferentialID: unknown; VULReferential: string }[];
      const kevName = new Map(kevRows.map((r) => [String(r.VULReferentialID), r.VULReferential]));
      const hits = avs.filter((a) => kevName.has(String(a.VulnerabilityID)));
      if (hits.length) {
        const names = new Map((xo.prepare("SELECT AssetID, AssetName FROM ASSET").all() as { AssetID: number; AssetName: string }[]).map((r) => [r.AssetID, r.AssetName]));
        const list = hits.slice(0, 25).map((h) => `- ${names.get(h.AssetID) || `asset#${h.AssetID}`}: ${kevName.get(String(h.VulnerabilityID))}`);
        blocks.push(`KEV (known-exploited) vulnerabilities on the organisation's assets [${hits.length} total]:\n${list.join("\n")}`);
        sources.push("KEV×assets");
      }
    }
  } catch { /* skip */ }

  // 2) Most exposed assets (RiskScore × FinancialValue).
  try {
    const exp = assetRiskExposure(10);
    if (exp.assets.length) {
      blocks.push("Highest-exposure assets (RiskScore × FinancialValue):\n" +
        exp.assets.slice(0, 10).map((a) => `- ${a.name} (risk ${a.risk}, value ${a.value})`).join("\n"));
      sources.push("risk-exposure");
    }
  } catch { /* skip */ }

  // 3) MITRE ATT&CK techniques matching the question's keywords.
  try {
    if (kw.length) {
      const xt = getDb("XTHREAT");
      const where = kw.map(() => "Name LIKE ?").join(" OR ");
      const rows = xt.prepare(`SELECT DISTINCT AttackID, Name FROM ATTACKTECHNIQUE WHERE ${where} LIMIT 15`).all(...kw.map((k) => `%${k}%`)) as { AttackID: string; Name: string }[];
      if (rows.length) {
        blocks.push("Relevant MITRE ATT&CK techniques:\n" + rows.map((r) => `- ${r.AttackID} ${r.Name}`).join("\n"));
        sources.push("ATT&CK");
      }
    }
  } catch { /* skip */ }

  // 4) Observed hunts + current hypotheses.
  try {
    const xt = getDb("XTHREAT");
    const hunts = xt.prepare("SELECT HuntName, HuntStatus, AttackTags FROM HUNT ORDER BY HuntID DESC LIMIT 10").all() as { HuntName: string; HuntStatus: string; AttackTags: string }[];
    if (hunts.length) {
      blocks.push("Recent threat hunts:\n" + hunts.map((h) => `- [${h.HuntStatus || "?"}] ${h.HuntName} (ATT&CK: ${h.AttackTags || "-"})`).join("\n"));
      sources.push("hunts");
    }
    const hyp = xt.prepare("SELECT HypothesisName FROM HYPOTHESIS ORDER BY HypothesisID DESC LIMIT 8").all() as { HypothesisName: string }[];
    if (hyp.length) {
      blocks.push("Current hunt hypotheses:\n" + hyp.map((h) => `- ${h.HypothesisName}`).join("\n"));
      sources.push("hypotheses");
    }
  } catch { /* skip */ }

  return { text: blocks.join("\n\n"), sources };
}

/** "Ask the threat model": RAG over XORCISM + local LLM. */
export async function askThreatModel(question: string): Promise<{ answer: string; sources: string[]; model: string }> {
  const { text, sources } = buildThreatContext(question);
  const system =
    "You are a cyber threat intelligence analyst for this organisation (its data comes from the XORCISM platform). " +
    "Answer concisely with prioritised, actionable recommendations. Rely on the provided CONTEXT (the organisation's own data) " +
    "over generic knowledge, and explicitly say when relevant data is missing. Never invent asset names or CVEs that are not in the CONTEXT.";
  const user = `Question: ${question}\n\nCONTEXT (from XORCISM):\n${text || "(no organisation-specific data retrieved)"}`;
  const answer = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { answer, sources, model: OLLAMA_MODEL };
}

/** Suggested answer to a questionnaire question (OCIL). Human-in-the-loop. */
export async function suggestOcilAnswer(question: string, description?: string): Promise<{ answer: string; model: string }> {
  const system =
    "You are a security & compliance assistant helping answer a security/OCIL questionnaire. " +
    "Propose a clear, concise answer. If the question expects yes / no / not-applicable, state the recommended response " +
    "and a one-sentence justification. Keep it under 120 words. This is a draft for human review.";
  const user = `Questionnaire question: ${question}` + (description ? `\nAdditional context: ${description}` : "");
  const answer = await ollamaChat([{ role: "system", content: system }, { role: "user", content: user }]);
  return { answer, model: OLLAMA_MODEL };
}
