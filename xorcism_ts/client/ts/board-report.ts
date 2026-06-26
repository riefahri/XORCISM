/** board-report.ts — Board Cyber-Risk Report (/board-report).
 *  Renders posture + trend + critical assets + risks + remediation + financial + the six
 *  board questions, with an on-demand local-AI board narrative. Reads /api/board-report. */
// NB: import as T — `t` is used as a param name in this file (md()'s inl(t)).
import { initI18n, t as T } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2800); }

interface Driver { key: string; label: string; value: number }
interface TrendPt { date: string; posture: number; risk: number }
interface Risk { ref: string; priority: number; kev: boolean; exploits: number; assets: number; epssPct: number | null; whyItMatters: string }
interface Report {
  generatedAt: string;
  posture: { score: number; grade: string; verdict: string; enterpriseRisk: number; drivers: Driver[] };
  trend: { points: TrendPt[]; direction: "improving" | "worsening" | "flat"; deltaPct: number; startScore: number; currentScore: number; rangeDays: number };
  criticalAssets: { total: number; atRisk: number; pctAtRisk: number; pathsFound: number; entries: number };
  risks: Risk[];
  remediation: { label: string; paths: number; rationale: string }[];
  financial: { aleTotal: number; topRisks: { title: string; level: string; ale: number | null }[] };
  resources: { openIncidents: number; mttrHours: number | null; mttdMinutes: number | null; compliance: { audits: number; auditsDone: number; openFindings: number; completionPct: number } };
  questions: { q: string; a: string }[];
}

const card = (lbl: string, val: string, foot: string, color?: string, trend?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>${trend || ""}<div class="foot">${esc(foot)}</div></div>`;

/** Minimal markdown → HTML for the AI narrative (headings, bold, bullets). */
function md(s: string): string {
  const lines = esc(s).split(/\r?\n/); const out: string[] = []; let inUl = false;
  const inl = (t: string): string => t.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/(?<!\*)\*(?!\s)([^*]+)\*/g, "<i>$1</i>").replace(/`([^`]+)`/g, "<code>$1</code>");
  for (const ln of lines) {
    const m = ln.match(/^\s*[-*]\s+(.*)/);
    if (m) { if (!inUl) { out.push("<ul>"); inUl = true; } out.push(`<li>${inl(m[1])}</li>`); continue; }
    if (inUl) { out.push("</ul>"); inUl = false; }
    if (/^###\s+/.test(ln)) out.push(`<h3>${inl(ln.replace(/^###\s+/, ""))}</h3>`);
    else if (/^##\s+/.test(ln)) out.push(`<h2>${inl(ln.replace(/^##\s+/, ""))}</h2>`);
    else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
  }
  if (inUl) out.push("</ul>");
  return out.join("");
}

/** SVG sparkline of posture (0–100, higher = better) over time. */
function trendSvg(pts: TrendPt[]): string {
  if (pts.length < 2) return `<div class="muted" style="padding:18px 0">${T("br.trend.noHistory")}</div>`;
  const W = 560, H = 150, padL = 30, padR = 10, padT = 12, padB = 22;
  const xs = (i: number): number => padL + (i / (pts.length - 1)) * (W - padL - padR);
  const ys = (v: number): number => padT + (1 - v / 100) * (H - padT - padB);
  const path = pts.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.posture).toFixed(1)}`).join(" ");
  const area = `${path} L${xs(pts.length - 1).toFixed(1)},${(H - padB).toFixed(1)} L${xs(0).toFixed(1)},${(H - padB).toFixed(1)} Z`;
  const grid = [0, 25, 50, 75, 100].map((v) => `<line x1="${padL}" y1="${ys(v)}" x2="${W - padR}" y2="${ys(v)}" stroke="#1e2133"/><text x="2" y="${ys(v) + 3}" fill="#64748b" font-size="9">${v}</text>`).join("");
  const last = pts[pts.length - 1];
  return `<svg class="lc" viewBox="0 0 ${W} ${H}" width="100%" height="${H}" preserveAspectRatio="xMidYMid meet">
    ${grid}
    <path d="${area}" fill="#f9731622" stroke="none"/>
    <path d="${path}" fill="none" stroke="#f97316" stroke-width="2"/>
    <circle cx="${xs(pts.length - 1)}" cy="${ys(last.posture)}" r="3.5" fill="#fbbf24"/>
    <text x="${W - padR}" y="${ys(last.posture) - 7}" fill="#fbbf24" font-size="11" font-weight="700" text-anchor="end">${last.posture}</text>
    <text x="${padL}" y="${H - 5}" fill="#64748b" font-size="9">${esc(pts[0].date)}</text>
    <text x="${W - padR}" y="${H - 5}" fill="#64748b" font-size="9" text-anchor="end">${esc(last.date)}</text>
  </svg>`;
}

function render(r: Report): void {
  const tcls = r.trend.direction === "improving" ? "tr-up" : r.trend.direction === "worsening" ? "tr-dn" : "tr-flat";
  const tarrow = r.trend.direction === "improving" ? "▲" : r.trend.direction === "worsening" ? "▼" : "▬";
  const gradeCls = `g-${r.posture.grade}`;
  const fmt$ = (n: number): string => "$" + Math.round(n).toLocaleString();

  const cards = [
    card(T("br.card.posture"), `<span class="grade ${gradeCls}">${r.posture.score}</span><span style="font-size:14px;color:#64748b">/100</span>`,
      `${fmt("br.card.grade", { g: r.posture.grade })} · ${r.posture.verdict}`, undefined,
      r.trend.rangeDays ? `<div class="trend ${tcls}">${tarrow} ${r.trend.deltaPct >= 0 ? "+" : ""}${r.trend.deltaPct}% / ${r.trend.rangeDays}${T("br.dShort")}</div>` : ""),
    card(T("br.card.critAtRisk"), `${r.criticalAssets.pctAtRisk}%`, fmt("br.card.critAtRisk.f", { atRisk: r.criticalAssets.atRisk, total: r.criticalAssets.total }), r.criticalAssets.pctAtRisk > 0 ? "#f87171" : "#34d399"),
    card(T("br.card.paths"), String(r.criticalAssets.pathsFound), fmt("br.card.paths.f", { n: r.criticalAssets.entries }), r.criticalAssets.pathsFound ? "#fbbf24" : "#34d399"),
    card(T("br.card.exploited"), String(r.risks.filter((x) => x.kev || x.exploits).length), T("br.card.exploited.f"), r.risks.some((x) => x.kev) ? "#f87171" : undefined),
    r.financial.aleTotal ? card(T("br.card.financial"), fmt$(r.financial.aleTotal), T("br.card.financial.f"), "#fbbf24") : card(T("br.card.incidents"), String(r.resources.openIncidents), r.resources.mttrHours != null ? `MTTR ${r.resources.mttrHours}h` : T("br.card.inResponse"), r.resources.openIncidents ? "#fb923c" : "#34d399"),
    card(T("br.card.compliance"), `${r.resources.compliance.completionPct}%`, fmt("br.card.compliance.f", { n: r.resources.compliance.openFindings }), r.resources.compliance.openFindings ? "#fb923c" : "#34d399"),
  ].join("");

  // Six board questions
  const qa = r.questions.map((q) => `<div class="qa"><div class="q">${esc(q.q)}</div><div class="a">${esc(q.a)}</div></div>`).join("");

  // Top risks table
  const riskRows = r.risks.length ? r.risks.map((x) => `<tr>
    <td><b>${esc(x.ref)}</b></td>
    <td>${x.kev ? `<span class="pill pill-kev">KEV</span> ` : ""}${x.exploits ? `<span class="pill pill-exp">${T("br.exploit")}</span> ` : ""}<span class="pill pill-prio">P${x.priority}</span></td>
    <td>${x.epssPct != null ? x.epssPct + "%" : "<span class='muted'>—</span>"}</td>
    <td>${x.assets}</td>
    <td class="muted">${esc(x.whyItMatters)}</td></tr>`).join("")
    : `<tr><td colspan="5" class="muted">${T("br.risks.empty")}</td></tr>`;

  // Remediation choke points
  const rem = r.remediation.length ? r.remediation.map((c, i) => `<div class="qa"><div class="q">${i + 1}. ${esc(c.label)} <span class="muted" style="font-weight:400">· ${fmt("br.rem.paths", { n: c.paths })}</span></div><div class="a">${esc(c.rationale)}</div></div>`).join("")
    : `<div class="muted" style="padding:10px 0">${T("br.rem.empty")}</div>`;

  // Financial detail
  const finRows = r.financial.topRisks.length ? r.financial.topRisks.map((x) => `<tr><td>${esc(x.title)}</td><td><span class="pill pill-prio">${esc(x.level)}</span></td><td style="text-align:right">${x.ale != null ? fmt$(x.ale) : "<span class='muted'>—</span>"}</td></tr>`).join("")
    : `<tr><td colspan="3" class="muted">${T("br.fin.empty")}</td></tr>`;

  // Posture drivers (what's pushing risk up/down)
  const drivers = r.posture.drivers.length ? r.posture.drivers.map((d) => {
    const up = d.value > 0; const w = Math.min(100, Math.abs(d.value) / Math.max(1, Math.max(...r.posture.drivers.map((x) => Math.abs(x.value)))) * 100);
    return `<div style="margin:5px 0"><div style="display:flex;justify-content:space-between;font-size:12px;color:#cbd5e1"><span>${esc(d.label)}</span><span style="color:${up ? "#f87171" : "#4ade80"}">${up ? "+" : ""}${d.value}</span></div>
      <div style="height:6px;background:#0f1117;border-radius:4px;overflow:hidden;margin-top:2px"><div style="height:100%;width:${w}%;background:${up ? "#ef4444" : "#22c55e"}"></div></div></div>`;
  }).join("") : `<div class="muted">${T("br.drivers.empty")}</div>`;

  $("body").innerHTML = `
    <div class="cards">${cards}</div>

    <div class="sec">${T("br.sec.questions")}</div>
    <div class="panel">${qa}</div>

    <div class="sec">${T("br.sec.investments")}</div>
    <div class="grid2">
      <div class="panel"><h3>${T("br.panel.trend")}</h3><div class="ph">${T("br.panel.trend.sub")}</div>${trendSvg(r.trend.points)}</div>
      <div class="panel"><h3>${T("br.panel.drivers")}</h3><div class="ph">${fmt("br.panel.drivers.sub", { n: r.posture.enterpriseRisk })}</div>${drivers}</div>
    </div>

    <div class="sec">${T("br.sec.risks")} <span class="spacer"></span></div>
    <div class="panel"><table class="bt"><thead><tr><th>${T("br.th.exposure")}</th><th>${T("br.th.signals")}</th><th>EPSS</th><th>${T("br.th.assets")}</th><th>${T("br.th.why")}</th></tr></thead><tbody>${riskRows}</tbody></table></div>

    <div class="sec">${T("br.sec.remediate")}</div>
    <div class="panel">${rem}</div>

    <div class="sec">${T("br.sec.financial")}</div>
    <div class="panel"><table class="bt"><thead><tr><th>${T("br.th.risk")}</th><th>${T("br.th.level")}</th><th style="text-align:right">ALE</th></tr></thead><tbody>${finRows}</tbody>${r.financial.aleTotal ? `<tfoot><tr><td colspan="2" style="font-weight:700">${T("br.fin.total")}</td><td style="text-align:right;font-weight:700;color:#fbbf24">${fmt$(r.financial.aleTotal)}</td></tr></tfoot>` : ""}</table></div>

    <div class="sec">${T("br.sec.narrative")} <span class="spacer"></span><span class="muted no-print" style="font-size:11px;font-weight:400">${T("br.narrative.hint")}</span></div>
    <div id="ai-out" class="exec"><span class="muted">${T("br.narrative.placeholder")}</span></div>

    <div class="muted" style="font-size:11px;margin-top:18px">${fmt("br.footer", { date: esc(new Date(r.generatedAt).toLocaleString()) })}</div>`;
}

function loadAi(): void {
  const btn = $("btn-ai") as HTMLButtonElement;
  btn.disabled = true; const old = btn.innerHTML; btn.innerHTML = T("br.ai.loading");
  const out = $("ai-out"); out.innerHTML = `<span class="muted">${T("br.ai.generating")}</span>`;
  fetch("/api/ai/board-narrative", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j: { narrative: string; model: string; offline: boolean }) => {
      out.innerHTML = md(j.narrative) + `<div class="muted" style="font-size:11px;margin-top:10px">— ${j.offline ? T("br.ai.offline") : T("br.ai.model") + ": " + esc(j.model)}</div>`;
    })
    .catch((e) => { out.innerHTML = `<span class="muted">⚠️ ${esc(e.message || e)}</span>`; })
    .finally(() => { btn.disabled = false; btn.innerHTML = old; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("btn-print") as HTMLButtonElement).onclick = () => window.print();
  ($("btn-ai") as HTMLButtonElement).onclick = loadAi;
  fetch("/api/board-report").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((d: Report) => render(d))
    .catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
