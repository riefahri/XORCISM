/**
 * ai-guardrails.ts — AI-agent guardrails cockpit (/ai-guardrails).
 * Renders the AI Guardrail Baseline coverage, discovered AI agents + posture, runtime guardrail
 * violations, the guardrail-tool inventory and framework coverage, from /api/ai-guardrails.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Ctrl { id: string; title: string; category: string; description: string; weight: number; frameworks: Record<string, string> }
interface Data {
  baseline: { control: Ctrl; pass: number; fail: number; coverage: number }[];
  baselineDef: Ctrl[];
  agents: { id: number; agent: string; host: string; name: string; framework: string; model: string; endpoint: string; usesTools: boolean; autonomous: boolean; guardrails: string; secretsExposed: number; score: number; coverage: number; gaps: string[] }[];
  violations: { id: number; agent: string; host: string; technique: string; name: string; severity: string; evidence: string; source: string; huntId: number | null; at: string }[];
  tools: { name: string; kind: string; url: string; deployedOn: number }[];
  frameworks: { name: string; controls: number }[];
  summary: { agents: number; avgScore: number | null; atRisk: number; controlsCovered: number; openViolations: number; gateways: number };
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ag-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
function scoreColor(s: number): string { return s >= 70 ? "#34d399" : s >= 40 ? "#fbbf24" : "#f87171"; }
function sevClass(s: string): string { return `s-${(s || "info").toLowerCase()}`; }
function ctrlTitle(d: Data, id: string): string { return d.baselineDef.find((c) => c.id === id)?.title || id; }

function render(d: Data): void {
  const s = d.summary;
  const cards = [
    card("AI agents", String(s.agents), "discovered on the fleet", s.agents ? "#a78bfa" : "#94a3b8"),
    card("Avg posture", s.avgScore == null ? "—" : s.avgScore + "%", "guardrail baseline score", s.avgScore == null ? "#94a3b8" : scoreColor(s.avgScore)),
    card("At risk", String(s.atRisk), "agents below 50%", s.atRisk ? "#f87171" : "#34d399"),
    card("Controls covered", `${s.controlsCovered}/12`, "baseline controls assessed", "#60a5fa"),
    card("Violations", String(s.openViolations), "runtime guardrail hits", s.openViolations ? "#f87171" : "#34d399"),
    card("Gateways", String(s.gateways), "guardrail engines deployed", s.gateways ? "#34d399" : "#94a3b8"),
  ].join("");

  // Baseline coverage
  const baseRows = d.baseline.map((b) => {
    const total = b.pass + b.fail;
    const pct = total ? Math.round((b.pass / total) * 100) : null;
    const fw = Object.entries(b.control.frameworks).filter(([, v]) => v).map(([k, v]) => `<span class="fw" title="${esc({ aix: "OWASP AI Exchange", saif: "Google SAIF", iso42001: "ISO/IEC 42001", llm: "OWASP LLM Top 10", atlas: "MITRE ATLAS", nist: "NIST AI RMF" }[k] || k)}">${esc(v)}</span>`).join("");
    return `<tr>
      <td><span class="aname">${esc(b.control.title)}</span> <span class="muted" style="font-size:10px">×${b.control.weight}</span><div class="muted" style="font-size:11px;max-width:460px">${esc(b.control.description)}</div><div style="margin-top:3px">${fw}</div></td>
      <td>${esc(b.control.category)}</td>
      <td>${total ? `<span class="pill p-pass">${b.pass}✓</span> ${b.fail ? `<span class="pill p-fail">${b.fail}✗</span>` : ""}` : `<span class="muted">—</span>`}</td>
      <td style="min-width:90px">${pct == null ? `<span class="muted">n/a</span>` : `<b style="color:${scoreColor(pct)}">${pct}%</b><div class="covbar"><span style="width:${pct}%"></span></div>`}</td>
    </tr>`;
  }).join("");

  // Discovered agents
  const agentRows = d.agents.length ? d.agents.map((a) => `<tr>
      <td><span class="scorebar"><span style="width:${Math.max(4, a.score)}%;background:${scoreColor(a.score)}"></span></span><b>${a.score}</b></td>
      <td><span class="aname">${esc(a.name)}</span>${a.framework ? ` <span class="tag">${esc(a.framework)}</span>` : ""}<br><span class="muted mono" style="font-size:11px">${esc(a.host)}${a.endpoint ? " · " + esc(a.endpoint) : ""}${a.model ? " · " + esc(a.model) : ""}</span></td>
      <td>${a.usesTools ? `<span class="tag">tools</span> ` : ""}${a.autonomous ? `<span class="tag">autonomous</span>` : ""}${a.secretsExposed ? ` <span class="pill p-fail">${a.secretsExposed} secret${a.secretsExposed > 1 ? "s" : ""}</span>` : ""}</td>
      <td>${a.guardrails ? esc(a.guardrails) : `<span class="pill p-fail">none</span>`}</td>
      <td>${a.gaps.length ? a.gaps.slice(0, 6).map((g) => `<span class="gap" title="${esc(ctrlTitle(d, g))}">${esc(g)}</span>`).join("") : `<span class="muted">—</span>`}</td>
    </tr>`).join("")
    : `<tr><td colspan="5" class="muted">No AI agents discovered yet — launch an <span class="mono">aiguard</span> scan on an agent. It detects LLM apps / frameworks (LangChain, CrewAI, AutoGen…), MCP servers and local models, and scores each against the baseline.</td></tr>`;

  // Violations
  const violRows = d.violations.length ? d.violations.slice(0, 40).map((v) => `<tr>
      <td class="muted" style="font-size:11px">${esc((v.at || "").slice(0, 19))}</td>
      <td><span class="sev ${sevClass(v.severity)}">${esc(v.severity)}</span></td>
      <td class="mono" style="font-size:11px">${esc(v.technique)}</td>
      <td>${esc(v.name)}${v.huntId ? ` <a href="/?db=XTHREAT&table=HUNT&filterCol=HuntID&filterVal=${esc(v.huntId)}">→ hunt #${esc(v.huntId)}</a>` : ""}<div class="muted mono" style="font-size:10px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.evidence)}</div></td>
      <td class="muted" style="font-size:11px">${esc(v.source)}</td>
    </tr>`).join("")
    : `<tr><td colspan="5" class="muted">No guardrail violations recorded. Runtime monitoring flags prompt injection, jailbreaks, data exfiltration and excessive agency in AI-agent traces (heuristics + local AI); a guardrail gateway's block telemetry also lands here.</td></tr>`;

  // Tools
  const toolRows = d.tools.map((t) => `<tr>
      <td><a href="${esc(t.url)}" target="_blank" rel="noopener" class="aname">${esc(t.name)}</a></td>
      <td>${esc(t.kind)}</td>
      <td>${t.deployedOn ? `<span class="pill p-pass">deployed on ${t.deployedOn} agent${t.deployedOn > 1 ? "s" : ""}</span>` : `<span class="muted">not detected</span>`}</td>
    </tr>`).join("");

  const fwChips = d.frameworks.map((f) => `<span class="fw"><b>${esc(String(f.controls))}</b> ${esc(f.name)}</span>`).join("");

  $("ag-body").innerHTML = `<div class="ag-cards">${cards}</div>
    <div class="ag-section">AI Guardrail Baseline (12 controls) <span class="muted" style="font-weight:400;text-transform:none;font-size:11px"> — framework coverage: ${fwChips}</span></div>
    <table class="ag"><thead><tr><th>Guardrail control</th><th>Category</th><th>Pass / fail</th><th>Adoption</th></tr></thead><tbody>${baseRows}</tbody></table>

    <div class="ag-section">Discovered AI agents (${d.agents.length})</div>
    <table class="ag"><thead><tr><th>Posture</th><th>Agent / host</th><th>Profile</th><th>Guardrails</th><th>Gaps</th></tr></thead><tbody>${agentRows}</tbody></table>

    <div class="ag-section">Runtime guardrail violations (${d.violations.length})</div>
    <table class="ag"><thead><tr><th>When</th><th>Severity</th><th>Technique</th><th>Violation</th><th>Source</th></tr></thead><tbody>${violRows}</tbody></table>

    <div class="ag-section">Guardrail tools &amp; gateways</div>
    <table class="ag"><thead><tr><th>Tool</th><th>Kind</th><th>Status</th></tr></thead><tbody>${toolRows}</tbody></table>

    <div class="legend">Posture &amp; monitoring come from the XOR endpoint agent (kind <span class="mono">aiguard</span>); enforcement is delegated to an inline guardrail gateway (NeMo Guardrails / LLM Guard / Llama Guard / Lakera…) whose block telemetry is imported by the <span class="mono">llm-guard</span> connector. AI traces are analysed by the <b>local</b> AI — raw prompts never leave the host. Maps to OWASP AI Exchange, Google SAIF, ISO/IEC 42001, OWASP LLM Top 10, MITRE ATLAS and NIST AI RMF.</div>`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/ai-guardrails"); if (!r.ok) throw new Error(`HTTP ${r.status}`); render(await r.json()); }
  catch (e) { $("ag-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load AI guardrails: ${esc((e as Error).message)} — admin access required.</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
