/**
 * ai-guardrails.ts — AI-agent guardrails cockpit (/ai-guardrails).
 * Renders the AI Guardrail Baseline coverage, discovered AI agents + posture, runtime guardrail
 * violations, the guardrail-tool inventory and framework coverage, from /api/ai-guardrails.
 */
import { initI18n, t } from "./i18n";
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
    card(t("aig.kpi.agents"), String(s.agents), t("aig.kpi.agentsFoot"), s.agents ? "#a78bfa" : "#94a3b8"),
    card(t("aig.kpi.posture"), s.avgScore == null ? "—" : s.avgScore + "%", t("aig.kpi.postureFoot"), s.avgScore == null ? "#94a3b8" : scoreColor(s.avgScore)),
    card(t("aig.kpi.atRisk"), String(s.atRisk), t("aig.kpi.atRiskFoot"), s.atRisk ? "#f87171" : "#34d399"),
    card(t("aig.kpi.controls"), `${s.controlsCovered}/12`, t("aig.kpi.controlsFoot"), "#60a5fa"),
    card(t("aig.kpi.violations"), String(s.openViolations), t("aig.kpi.violationsFoot"), s.openViolations ? "#f87171" : "#34d399"),
    card(t("aig.kpi.gateways"), String(s.gateways), t("aig.kpi.gatewaysFoot"), s.gateways ? "#34d399" : "#94a3b8"),
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
      <td>${a.usesTools ? `<span class="tag">${t("aig.tools")}</span> ` : ""}${a.autonomous ? `<span class="tag">${t("aig.autonomous")}</span>` : ""}${a.secretsExposed ? ` <span class="pill p-fail">${a.secretsExposed} ${t("aig.secrets")}</span>` : ""}</td>
      <td>${a.guardrails ? esc(a.guardrails) : `<span class="pill p-fail">${t("aig.none")}</span>`}</td>
      <td>${a.gaps.length ? a.gaps.slice(0, 6).map((g) => `<span class="gap" title="${esc(ctrlTitle(d, g))}">${esc(g)}</span>`).join("") : `<span class="muted">—</span>`}</td>
    </tr>`).join("")
    : `<tr><td colspan="5" class="muted">${t("aig.noAgents")}</td></tr>`;

  // Violations
  const violRows = d.violations.length ? d.violations.slice(0, 40).map((v) => `<tr>
      <td class="muted" style="font-size:11px">${esc((v.at || "").slice(0, 19))}</td>
      <td><span class="sev ${sevClass(v.severity)}">${esc(v.severity)}</span></td>
      <td class="mono" style="font-size:11px">${esc(v.technique)}</td>
      <td>${esc(v.name)}${v.huntId ? ` <a href="/?db=XTHREAT&table=HUNT&filterCol=HuntID&filterVal=${esc(v.huntId)}">→ hunt #${esc(v.huntId)}</a>` : ""}<div class="muted mono" style="font-size:10px;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.evidence)}</div></td>
      <td class="muted" style="font-size:11px">${esc(v.source)}</td>
    </tr>`).join("")
    : `<tr><td colspan="5" class="muted">${t("aig.noViol")}</td></tr>`;

  // Tools
  const toolRows = d.tools.map((tl) => `<tr>
      <td><a href="${esc(tl.url)}" target="_blank" rel="noopener" class="aname">${esc(tl.name)}</a></td>
      <td>${esc(tl.kind)}</td>
      <td>${tl.deployedOn ? `<span class="pill p-pass">${t("aig.deployedOn")} ${tl.deployedOn}</span>` : `<span class="muted">${t("aig.notDetected")}</span>`}</td>
    </tr>`).join("");

  const fwChips = d.frameworks.map((f) => `<span class="fw"><b>${esc(String(f.controls))}</b> ${esc(f.name)}</span>`).join("");

  $("ag-body").innerHTML = `<div class="ag-cards">${cards}</div>
    <div class="ag-section">${t("aig.sec.baseline")} <span class="muted" style="font-weight:400;text-transform:none;font-size:11px"> — ${t("aig.sec.fwCoverage")}: ${fwChips}</span></div>
    <table class="ag"><thead><tr><th>${t("aig.col.control")}</th><th>${t("aig.col.category")}</th><th>${t("aig.col.passfail")}</th><th>${t("aig.col.adoption")}</th></tr></thead><tbody>${baseRows}</tbody></table>

    <div class="ag-section">${t("aig.sec.agents")} (${d.agents.length})</div>
    <table class="ag"><thead><tr><th>${t("aig.col.posture")}</th><th>${t("aig.col.agentHost")}</th><th>${t("aig.col.profile")}</th><th>${t("aig.col.guardrails")}</th><th>${t("aig.col.gaps")}</th></tr></thead><tbody>${agentRows}</tbody></table>

    <div class="ag-section">${t("aig.sec.violations")} (${d.violations.length})</div>
    <table class="ag"><thead><tr><th>${t("aig.col.when")}</th><th>${t("aig.col.severity")}</th><th>${t("aig.col.technique")}</th><th>${t("aig.col.violation")}</th><th>${t("aig.col.source")}</th></tr></thead><tbody>${violRows}</tbody></table>

    <div class="ag-section">${t("aig.sec.tools")}</div>
    <table class="ag"><thead><tr><th>${t("aig.col.tool")}</th><th>${t("aig.col.kind")}</th><th>${t("aig.col.status")}</th></tr></thead><tbody>${toolRows}</tbody></table>

    <div class="legend">${t("aig.legend")}</div>`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/ai-guardrails"); if (!r.ok) throw new Error(`HTTP ${r.status}`); render(await r.json()); }
  catch (e) { $("ag-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("aig.loadFail")}: ${esc((e as Error).message)} — ${t("aig.adminReq")}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
