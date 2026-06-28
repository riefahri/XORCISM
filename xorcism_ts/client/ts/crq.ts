/**
 * crq.ts — CRQ Decision Support cockpit (/crq). Gartner-aligned: turns the quantified risk register
 * (FAIR/CRQ ALE) into decisions — remediate-first, best investments, appetite breaches, scenarios.
 */
export {}; // module scope
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Action { id: number; ref: string; title: string; level: string; ale: number; aleLow: number; aleHigh: number; treatment: string; overAppetite: boolean; expectedReduction: number; effectiveness: number; reason: string; }
interface Crq {
  currency: string;
  portfolio: { totalALE: number; aleLow: number; aleHigh: number; quantifiedRisks: number; openRisks: number; overAppetite: number; untreated: number; aboveAppetiteALE: number };
  remediateFirst: Action[]; investments: Action[];
  appetite: { overCount: number; withinCount: number; overALE: number; items: Action[] };
  scenarios: { name: string; ale: number; reductionPct: number; note: string }[];
  questions: { q: string; a: string }[]; generated: string;
}

let CUR = "EUR";
const money = (n: number): string => `${CUR} ${Math.round(n).toLocaleString("en-US")}`;
const lcls = (l: string): string => "lvl " + l.toLowerCase().replace(/\s+/g, "");

function actionTable(rows: Action[], kind: "ale" | "reduction"): string {
  if (!rows.length) return `<div class="muted" style="padding:8px 0">No quantified open risks. Quantify risks with FAIR-MAM / FAIR-TEF to populate this.</div>`;
  const head = kind === "ale" ? "Annualized loss (range)" : "Expected annual reduction";
  return `<table class="cq"><thead><tr><th>Risk</th><th>Residual</th><th>Treatment</th><th class="num">${head}</th><th>Why</th></tr></thead><tbody>` +
    rows.map((a) => `<tr>
      <td><b style="color:#e2e8f0">${esc(a.ref || "#" + a.id)}</b> ${esc(a.title)}${a.overAppetite ? ' <span class="over">over appetite</span>' : ""}</td>
      <td><span class="${lcls(a.level)}">${esc(a.level)}</span></td>
      <td>${esc(a.treatment || "—")}</td>
      <td class="num">${kind === "ale" ? `${money(a.ale)}<div class="muted" style="font-size:10.5px">${money(a.aleLow)}–${money(a.aleHigh)}</div>` : `${money(a.expectedReduction)}<div class="muted" style="font-size:10.5px">@ ${(a.effectiveness * 100).toFixed(0)}% eff.</div>`}</td>
      <td class="muted">${esc(a.reason)}</td>
    </tr>`).join("") + `</tbody></table>`;
}

function scenarioBars(scn: Crq["scenarios"]): string {
  const max = Math.max(...scn.map((s) => s.ale), 1);
  return `<div class="bars">` + scn.map((s) =>
    `<div class="bar-row"><div class="nm">${esc(s.name)}${s.reductionPct ? ` <span class="muted">(−${s.reductionPct}%)</span>` : ""}</div>
      <div class="track"><div class="fill" style="width:${Math.round((s.ale / max) * 100)}%"></div></div>
      <div class="amt">${money(s.ale)}/yr</div></div>`).join("") + `</div>` +
    `<div class="muted" style="font-size:11.5px;margin-top:6px">${scn.map((s) => esc(s.note)).slice(1).join(" ")}</div>`;
}

function render(d: Crq): void {
  CUR = d.currency || "EUR";
  const p = d.portfolio;
  if (!p.quantifiedRisks) {
    $("cq-body").innerHTML = `<div class="cq-panel"><div class="muted">No quantified open risks yet. Add annualized loss (ALE) to risks in the
      <a href="/risk-register" style="color:#7c83fd">Risk Register</a> or decompose a loss with
      <a href="/fair-mam" style="color:#7c83fd">FAIR-MAM</a> — this cockpit then turns that quantification into decisions.</div></div>`;
    return;
  }
  const cards = [
    `<div class="cq-card"><div class="lbl">Portfolio annualized loss</div><div class="val" style="color:#f87171">${money(p.totalALE)}</div><div class="foot">range ${money(p.aleLow)}–${money(p.aleHigh)} · ${p.quantifiedRisks} quantified</div></div>`,
    `<div class="cq-card"><div class="lbl">Above risk appetite</div><div class="val" style="color:${p.overAppetite ? "#fbbf24" : "#34d399"}">${p.overAppetite}</div><div class="foot">${money(p.aboveAppetiteALE)}/yr at stake</div></div>`,
    `<div class="cq-card"><div class="lbl">Untreated</div><div class="val" style="color:${p.untreated ? "#fbbf24" : "#34d399"}">${p.untreated}</div><div class="foot">no plan / not accepted</div></div>`,
    `<div class="cq-card"><div class="lbl">Open risks</div><div class="val">${p.openRisks}</div><div class="foot">in the register</div></div>`,
  ].join("");
  const q = (i: number): string => d.questions[i] ? `<div class="qbox"><div class="q">${esc(d.questions[i].q)}</div>${esc(d.questions[i].a)}</div>` : "";
  $("cq-body").innerHTML = `
    <div class="cq-cards">${cards}</div>
    <div class="cq-panel"><h2>1 · Remediate first</h2><div class="qh">Highest annualized loss across open quantified risks.</div>${q(0)}${actionTable(d.remediateFirst, "ale")}</div>
    <div class="cq-panel"><h2>2 · Investments that maximize risk reduction</h2><div class="qh">Ranked by expected annualized loss removed (transparent control-effectiveness assumption; add a treatment cost to compute ROSI).</div>${q(1)}${actionTable(d.investments, "reduction")}</div>
    <div class="cq-panel"><h2>3 · Risks outside appetite</h2><div class="qh">The board-level decisions.</div>${q(2)}${actionTable(d.appetite.items, "ale")}</div>
    <div class="cq-panel"><h2>4 · Optimize resources — scenario comparison</h2><div class="qh">How portfolio ALE moves as you treat more of the register.</div>${q(3)}${scenarioBars(d.scenarios)}</div>`;
}

document.addEventListener("DOMContentLoaded", () => {
  fetch("/api/crq").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((d: Crq) => render(d))
    .catch((e) => { $("cq-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(String(e))}</div>`; });
});
