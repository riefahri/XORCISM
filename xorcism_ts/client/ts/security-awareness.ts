/** security-awareness.ts — Security Awareness cockpit (/security-awareness). Training catalogue +
 * enrollment, phishing simulation campaigns, Phish-Prone %, repeat clickers, per-user human-risk
 * worklist, from /api/security-awareness. KnowBe4-style. */
// NB: import as T — `t` is used as a local/param name throughout this file (trainingRow(t), toast()).
import { initI18n, t as T } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

interface Training { id: number; name: string; category: string; provider: string; duration: number | null; required: boolean; status: string; enrolled: number; completed: number; completionRate: number | null; }
interface Phish { id: number; name: string; theme: string; difficulty: string; status: string; sentDate: string | null; sent: number; clicked: number; reported: number; submitted: number; clickRate: number; reportRate: number; }
interface UserRow { id: number; name: string; clicks: number; submitted: number; reported: number; campaigns: number; trainingsDone: number; trainingsAssigned: number; incomplete: number; risk: number; phishProne: boolean; repeatClicker: boolean; }
interface Data { trainings: Training[]; phishing: Phish[]; users: UserRow[]; worklist: { kind: string; id: number; name: string; severity: string; reason: string }[]; summary: any; }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="sa-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const scls = (s: string): string => `sv-${["Critical", "High", "Medium", "Low"].includes(s) ? s : "Low"}`;
const riskColor = (r: number): string => (r >= 70 ? "#f87171" : r >= 40 ? "#fbbf24" : r >= 15 ? "#a3e635" : "#34d399");
const rateColor = (r: number): string => (r >= 30 ? "#f87171" : r >= 15 ? "#fbbf24" : "#34d399");

function bar(pct: number, color: string): string {
  return `<span class="bar" title="${pct}%"><i style="width:${Math.max(0, Math.min(100, pct))}%;background:${color}"></i></span>`;
}

function trainingRow(t: Training): string {
  const cr = t.completionRate;
  return `<tr>
    <td><span class="nm">${esc(t.name)}</span>${t.required ? ` <span class="tag t-req">${T("saw.required")}</span>` : ""}</td>
    <td>${t.category ? `<span class="tag t-cat">${esc(t.category)}</span>` : "<span class='muted'>—</span>"}</td>
    <td>${t.provider ? `<span class="tag t-prov">${esc(t.provider)}</span>` : "<span class='muted'>—</span>"}</td>
    <td>${t.duration ? `${t.duration} ${T("saw.min")}` : "<span class='muted'>—</span>"}</td>
    <td>${t.enrolled}</td>
    <td>${cr == null ? `<span class='muted'>${T("saw.noEnrollees")}</span>` : `${bar(cr, cr >= 80 ? "#34d399" : cr >= 50 ? "#fbbf24" : "#f87171")} <span class="muted">${t.completed}/${t.enrolled} · ${cr}%</span>`}</td>
  </tr>`;
}

function phishRow(p: Phish): string {
  return `<tr>
    <td><span class="nm">${esc(p.name)}</span>${p.theme ? `<div class="muted" style="font-size:11px">${esc(p.theme)}</div>` : ""}</td>
    <td>${esc(p.difficulty || "—")}</td>
    <td>${esc(p.status || "—")}</td>
    <td>${p.sentDate || "<span class='muted'>—</span>"}</td>
    <td>${p.sent}</td>
    <td><span class="tag t-phish">${p.clicked}</span> ${bar(p.clickRate, rateColor(p.clickRate))} <span class="muted ppp">${p.clickRate}%</span></td>
    <td>${p.submitted ? `<span class="tag t-sub">${p.submitted}</span>` : "<span class='muted'>0</span>"}</td>
    <td><span class="tag t-report">${p.reported}</span> <span class="muted ppp">${p.reportRate}%</span></td>
  </tr>`;
}

function userRow(u: UserRow): string {
  return `<tr>
    <td><span class="nm">${esc(u.name)}</span></td>
    <td>${bar(u.risk, riskColor(u.risk))} <span class="riskpill" style="background:${riskColor(u.risk)}22;color:${riskColor(u.risk)}">${u.risk}</span></td>
    <td>${u.clicks ? `<span class="tag t-phish">${u.clicks}×</span>` : "<span class='muted'>0</span>"}${u.repeatClicker ? ` <span class='muted' style='font-size:10px'>${T("saw.repeat")}</span>` : ""}</td>
    <td>${u.submitted ? `<span class="tag t-sub">${u.submitted}</span>` : "<span class='muted'>0</span>"}</td>
    <td>${u.reported ? `<span class="tag t-report">${u.reported}</span>` : "<span class='muted'>0</span>"}</td>
    <td>${u.trainingsAssigned ? `${u.trainingsDone}/${u.trainingsAssigned}${u.incomplete ? ` <span class="muted" style="font-size:11px">${fmt("saw.due", { n: u.incomplete })}</span>` : ""}` : `<span class='tag t-phish'>${T("saw.never")}</span>`}</td>
  </tr>`;
}

function load(): void {
  fetch("/api/security-awareness").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => {
    const s = d.summary;
    if (!d.trainings.length && !d.phishing.length) {
      $("sa-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${T("saw.empty.title")}<br>
        ${T("saw.empty.sub")}
        <div style="margin-top:14px"><button class="btn-sm2" id="sa-new-t">${T("saw.btn.newTraining")}</button> <button class="btn-sm2" id="sa-new-p">${T("saw.btn.newPhish")}</button></div></div>`;
      wireCreate();
      return;
    }
    const ppp = s.phishPronePct;
    const cards = [
      card(T("saw.card.phishProne"), ppp == null ? "—" : `${ppp}%`, T("saw.card.phishProne.f"), ppp == null ? undefined : rateColor(ppp)),
      card(T("saw.card.completion"), s.completionRate == null ? "—" : `${s.completionRate}%`, fmt("saw.card.completion.f", { done: s.completed, total: s.enrolled }), s.completionRate == null ? undefined : (s.completionRate >= 80 ? "#34d399" : "#fbbf24")),
      card(T("saw.card.repeat"), String(s.repeatClickers), T("saw.card.repeat.f"), s.repeatClickers ? "#f87171" : "#34d399"),
      card(T("saw.card.neverTrained"), String(s.neverTrained), T("saw.card.neverTrained.f"), s.neverTrained ? "#fbbf24" : "#34d399"),
      card(T("saw.card.avgRisk"), String(s.avgRisk), fmt("saw.card.avgRisk.f", { n: s.highRisk }), riskColor(s.avgRisk)),
      card(T("saw.card.campaigns"), String(s.campaigns), fmt("saw.card.campaigns.f", { r: s.recipients, rep: s.reported }), "#60a5fa"),
    ].join("");
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.slice(0, 50).map((w) => `<li><span class="sev ${scls(w.severity)}">${esc(w.severity)}</span> <b style="color:#e2e8f0">${esc(w.name)}</b> — ${esc(w.reason)}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${T("saw.noFindings")}</div>`;
    const tTable = d.trainings.length
      ? `<table class="sa"><thead><tr><th>${T("saw.th.course")}</th><th>${T("saw.th.category")}</th><th>${T("saw.th.provider")}</th><th>${T("saw.th.duration")}</th><th>${T("saw.th.enrolled")}</th><th>${T("saw.th.completion")}</th></tr></thead><tbody>${d.trainings.map(trainingRow).join("")}</tbody></table>`
      : `<div class='muted' style='padding:8px 0'>${T("saw.noCourses")}</div>`;
    const pTable = d.phishing.length
      ? `<table class="sa"><thead><tr><th>${T("saw.th.campaign")}</th><th>${T("saw.th.difficulty")}</th><th>${T("saw.th.status")}</th><th>${T("saw.th.sentDate")}</th><th>${T("saw.th.recipients")}</th><th>${T("saw.th.clicked")}</th><th>${T("saw.th.submitted")}</th><th>${T("saw.th.reported")}</th></tr></thead><tbody>${d.phishing.map(phishRow).join("")}</tbody></table>`
      : `<div class='muted' style='padding:8px 0'>${T("saw.noCampaigns")}</div>`;
    const uTable = d.users.length
      ? `<table class="sa"><thead><tr><th>${T("saw.th.user")}</th><th>${T("saw.th.humanRisk")}</th><th>${T("saw.th.clicked")}</th><th>${T("saw.th.submitted")}</th><th>${T("saw.th.reported")}</th><th>${T("saw.th.training")}</th></tr></thead><tbody>${d.users.slice(0, 100).map(userRow).join("")}</tbody></table>`
      : `<div class='muted' style='padding:8px 0'>${T("saw.noUsers")}</div>`;
    $("sa-body").innerHTML = `<div class="sa-cards">${cards}</div>
      <div class="sa-section">${fmt("saw.sec.worklist", { n: d.worklist.length })}</div>${work}
      <div class="sa-section">${fmt("saw.sec.catalogue", { n: d.trainings.length })}<span class="spacer"></span><button class="btn-sm2" id="sa-new-t">${T("saw.btn.newTraining")}</button></div>${tTable}
      <div class="sa-section">${fmt("saw.sec.phishing", { n: d.phishing.length })}<span class="spacer"></span><button class="btn-sm2" id="sa-new-p">${T("saw.btn.newPhish")}</button></div>${pTable}
      <div class="sa-section">${fmt("saw.sec.perUser", { n: d.users.length })}</div>${uTable}`;
    wireCreate();
  }).catch((e) => { $("sa-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function wireCreate(): void {
  const tBtn = document.getElementById("sa-new-t");
  if (tBtn) tBtn.onclick = () => {
    const name = prompt(T("saw.prompt.trainingName"));
    if (!name) return;
    const category = prompt(T("saw.prompt.trainingCat")) || "";
    fetch("/api/security-awareness/training", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, category, required: true }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(T("saw.toast.trainingCreated")); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
  const p = document.getElementById("sa-new-p");
  if (p) p.onclick = () => {
    const name = prompt(T("saw.prompt.phishName"));
    if (!name) return;
    const theme = prompt(T("saw.prompt.phishTheme")) || "";
    fetch("/api/security-awareness/phishing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, theme, difficulty: "Medium" }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast(T("saw.toast.phishCreated")); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}
document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
