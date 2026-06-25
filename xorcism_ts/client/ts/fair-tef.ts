/** fair-tef.ts — FAIR Threat/Loss Event Frequency estimator (/fair-tef). Reads /api/fair-tef. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLInputElement { return document.getElementById(id) as HTMLInputElement; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const tfmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, val]) => s.split(`{${k}}`).join(String(val)), t(key));
function v(id: string): number { const n = parseFloat($(id).value); return Number.isFinite(n) ? n : 0; }
const triple = (p: string): [number, number, number] => [v(p + "0"), v(p + "1"), v(p + "2")];
function toast(m: string): void { const e = document.getElementById("toast")!; e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 2400); }
let CCY = "EUR";
function money(n: number | null | undefined): string { if (n == null) return "—"; const a = Math.abs(n); const s = a >= 1e9 ? (n / 1e9).toFixed(2) + "B" : a >= 1e6 ? (n / 1e6).toFixed(2) + "M" : a >= 1e3 ? (n / 1e3).toFixed(1) + "k" : String(Math.round(n)); return s + " " + CCY; }
function freq(n: number): string { const u = t("ftef.perYr"); if (!n) return "0 " + u; return n >= 1 ? n.toFixed(2) + " " + u : `${n.toFixed(3)} ${u} ${tfmt("ftef.oneIn", { n: Math.round(1 / n) })}`; }

function payload(): any {
  const fm = $("fairmam").value;
  const p: any = { name: $("name").value.trim(), threatCommunity: $("tc").value.trim(), cf: triple("cf"), poa: triple("poa"), tcap: triple("tcap"), rs: triple("rs"), currency: $("ccy").value.trim() || "EUR", iterations: v("iter") || 10000 };
  if (fm) p.fairMamAssessmentId = Number(fm); else p.lossMagnitude = v("lm");
  if ($("risk").value) p.riskRegisterEntryId = Number($("risk").value);
  return p;
}

/** Loss-exceedance curve: P(annual ≥ x) — x is annual $ (with loss magnitude) else annual frequency. */
function lecChart(lec: { x: number; prob: number }[], isMoney: boolean): string {
  if (!lec || lec.length < 2) return "";
  const W = 360, H = 150, padL = 38, padB = 22, padT = 8, padR = 8;
  const xs = lec.map((p) => p.x); const xmax = Math.max(1, ...xs);
  const X = (x: number): number => padL + (x / xmax) * (W - padL - padR);
  const Y = (p: number): number => padT + (1 - p) * (H - padT - padB);
  const line = lec.map((p, i) => `${i ? "L" : "M"}${X(p.x).toFixed(1)},${Y(p.prob).toFixed(1)}`).join(" ");
  const area = `${line} L${X(lec[lec.length - 1].x).toFixed(1)},${H - padB} L${X(lec[0].x).toFixed(1)},${H - padB} Z`;
  const fmt = (x: number): string => isMoney ? money(x) : x.toFixed(2);
  const yt = [0, 0.25, 0.5, 0.75, 1].map((p) => `<text x="${padL - 4}" y="${Y(p) + 3}" text-anchor="end" font-size="9" fill="#64748b">${Math.round(p * 100)}%</text><line x1="${padL}" y1="${Y(p)}" x2="${W - padR}" y2="${Y(p)}" stroke="#1e2133"/>`).join("");
  const xt = [0, 0.5, 1].map((f) => `<text x="${X(xmax * f)}" y="${H - padB + 12}" text-anchor="middle" font-size="9" fill="#64748b">${fmt(xmax * f)}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:150px;display:block">
    <defs><linearGradient id="lecg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#a78bfa" stop-opacity="0.3"/><stop offset="1" stop-color="#a78bfa" stop-opacity="0"/></linearGradient></defs>
    ${yt}${xt}<path d="${area}" fill="url(#lecg)"/><path d="${line}" fill="none" stroke="#a78bfa" stroke-width="2"/>
    <text x="${padL}" y="${padT + 2}" font-size="9" fill="#94a3b8">P(annual ${isMoney ? "loss" : "events"} ≥ x)</text></svg>`;
}

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;

function renderResult(d: any): void {
  const hasAle = !!d.ale;
  const cards = [
    card("TEF", freq(d.tef.mean), t("ftef.cTefFoot"), "#60a5fa"),
    card(t("ftef.cVuln"), (d.vulnerability * 100).toFixed(0) + "%", "P(TCap > RS)", d.vulnerability >= 0.5 ? "#f87171" : "#fbbf24"),
    card("LEF", freq(d.lef.mean), t("ftef.cLefFoot"), "#a78bfa"),
    hasAle ? card(t("ftef.cAle"), money(d.ale.mean), t("ftef.cAleFoot"), "#f97316") : card("LEF p90", freq(d.lef.p90), t("ftef.cP90Foot"), "#a78bfa"),
  ].join("");
  const tree = `<div class="tree">
    <b>TEF ${freq(d.tef.mean)}</b> <span class="muted">${t("ftef.treeTef")}</span><br>
    × ${t("ftef.cVuln")} <b>${(d.vulnerability * 100).toFixed(0)}%</b> = <b>LEF ${freq(d.lef.mean)}</b>${hasAle ? `<br>× ${t("ftef.lossMag")} <b>${money(d.lossMagnitude)}</b> = <b>ALE ${money(d.ale.mean)}</b>` : ""}</div>`;
  const ranges = `<table class="t"><thead><tr><th>${t("ftef.thMetric")}</th><th class="r">min</th><th class="r">p10</th><th class="r">p50</th><th class="r">${t("ftef.thMean")}</th><th class="r">p90</th><th class="r">max</th></tr></thead><tbody>
    <tr><td>TEF ${t("ftef.perYr")}</td><td class="r">${d.tef.min}</td><td class="r">${d.tef.p10}</td><td class="r">${d.tef.p50}</td><td class="r">${d.tef.mean}</td><td class="r">${d.tef.p90}</td><td class="r">${d.tef.max}</td></tr>
    <tr><td>LEF ${t("ftef.perYr")}</td><td class="r">${d.lef.min}</td><td class="r">${d.lef.p10}</td><td class="r">${d.lef.p50}</td><td class="r">${d.lef.mean}</td><td class="r">${d.lef.p90}</td><td class="r">${d.lef.max}</td></tr>
    ${hasAle ? `<tr><td>ALE ${esc(CCY)}</td><td class="r">${money(d.ale.min)}</td><td class="r">${money(d.ale.p10)}</td><td class="r">${money(d.ale.p50)}</td><td class="r">${money(d.ale.mean)}</td><td class="r">${money(d.ale.p90)}</td><td class="r">${money(d.ale.max)}</td></tr>` : ""}
  </tbody></table>`;
  document.getElementById("result")!.innerHTML = `<div class="cards">${cards}</div>${tree}
    ${lecChart(d.lec, hasAle)}
    <div class="sec2" style="margin:12px 0 6px">${tfmt("ftef.distribution", { n: d.iterations.toLocaleString() })}</div>${ranges}`;
}

function renderInventory(d: any): void {
  // dropdowns
  const fm = $("fairmam"); fm.innerHTML = `<option value="">— none —</option>` + d.fairmam.map((a: any) => `<option value="${a.id}">${esc(a.name)} (${money(a.total)})</option>`).join("");
  const rk = $("risk"); rk.innerHTML = `<option value="">— none —</option>` + d.risks.map((r: any) => `<option value="${r.id}">${esc(r.ref)} — ${esc(r.title)}</option>`).join("");
  const s = d.summary;
  const cards = [
    card(t("ftef.cEstimates"), String(s.assessments), t("ftef.cEstimatesFoot")),
    card(t("ftef.cTotalAle"), money(s.totalAle), t("ftef.cTotalAleFoot"), "#f97316"),
    card(t("ftef.cLargestAle"), money(s.largestAle), t("ftef.cLargestAleFoot"), "#f87171"),
    card(t("ftef.cAvgLef"), freq(s.avgLef), t("ftef.cLefFoot"), "#a78bfa"),
  ].join("");
  const rows = d.assessments.length
    ? `<table class="t"><thead><tr><th>${t("ftef.thName")}</th><th class="r">TEF</th><th class="r">${t("ftef.thVuln")}</th><th class="r">LEF</th><th class="r">${t("ftef.thLossMag")}</th><th class="r">ALE</th><th class="r">ALE p90</th><th>${t("ftef.thDate")}</th></tr></thead><tbody>${d.assessments.map((a: any) => `<tr>
      <td>${esc(a.name)}${a.threatCommunity ? `<div class="muted" style="font-size:10px">${esc(a.threatCommunity)}</div>` : ""}</td>
      <td class="r">${a.tef.toFixed(3)}</td><td class="r">${(a.vuln * 100).toFixed(0)}%</td><td class="r">${a.lef.toFixed(3)}</td>
      <td class="r">${a.lossMagnitude ? money(a.lossMagnitude) : "—"}</td><td class="r">${a.ale != null ? money(a.ale) : "—"}</td><td class="r">${a.aleP90 != null ? money(a.aleP90) : "—"}</td>
      <td class="muted" style="font-size:11px">${esc(a.createdDate || "")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ftef.noEstimates")}</div>`;
  document.getElementById("inventory")!.innerHTML = `<div class="cards">${cards}</div>${rows}`;
}

function load(): void {
  fetch("/api/fair-tef").then((r) => r.json()).then((d) => { CCY = (d.summary && d.summary.currency) || "EUR"; renderInventory(d); }).catch(() => { document.getElementById("inventory")!.innerHTML = `<div class="muted">${t("ftef.loadFailed")}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  load();
  $("ccy").addEventListener("change", () => { CCY = $("ccy").value.trim() || "EUR"; });
  document.getElementById("btn-estimate")!.addEventListener("click", () => {
    CCY = $("ccy").value.trim() || "EUR";
    document.getElementById("result")!.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("ftef.simulating")}</div>`;
    fetch("/api/fair-tef/compute", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload()) })
      .then((r) => r.json()).then((d) => { if (d.error) throw new Error(d.error); renderResult(d); }).catch((e) => { document.getElementById("result")!.innerHTML = `<div class="muted" style="padding:20px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
  });
  document.getElementById("btn-save")!.addEventListener("click", () => {
    fetch("/api/fair-tef/assess", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload()) })
      .then((r) => r.json()).then((d) => {
        if (d.error) throw new Error(d.error);
        if (d.result) renderResult(d.result);
        toast(d.riskWriteback ? tfmt("ftef.savedWriteback", { lef: d.riskWriteback.lef, ale: d.riskWriteback.ale != null ? ` + ALE ${money(d.riskWriteback.ale)}` : "", ref: d.riskWriteback.ref }) : t("ftef.savedEstimate"));
        load();
      }).catch((e) => toast(tfmt("ftef.saveFailed", { e: e.message || e })));
  });
});
