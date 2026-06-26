/** team-ops.ts — Purple/Red/Blue Team Operations cockpit (/team-ops). Reads /api/team-ops. */
// NB: import as T — `t` is used as a param name in this file (tcls(t), .map((t)=>…)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let TACTICS: string[] = [];
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const rateColor = (p: number): string => (p >= 75 ? "#4ade80" : p >= 50 ? "#fbbf24" : "#f87171");
const ocls = (o: string): string => `o-${["prevented", "detected", "logged", "missed"].includes(o) ? o : "missed"}`;
const tcls = (t: string): string => `t-${["Red", "Blue", "Purple", "AppSec"].includes(t) ? t : "Purple"}`;

function load(): void {
  fetch("/api/team-ops").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    TACTICS = d.tactics;
    const s = d.summary;
    const cards = [
      card(T("tops.cPrevent"), `${s.preventionRate}%`, T("tops.cPrevent.f"), rateColor(s.preventionRate)),
      card(T("tops.cDetect"), `${s.detectionRate}%`, T("tops.cDetect.f"), rateColor(s.detectionRate)),
      card(T("tops.cVisibility"), `${s.visibility}%`, T("tops.cVisibility.f"), rateColor(s.visibility)),
      card("MTTD", s.mttdMinutes == null ? "—" : `${s.mttdMinutes}m`, T("tops.cMttd.f"), s.mttdMinutes != null && s.mttdMinutes <= 30 ? "#4ade80" : "#fbbf24"),
      card(T("tops.cMissed"), String(s.missed), T("tops.cMissed.f"), s.missed ? "#f87171" : "#4ade80"),
      card(T("tops.cExercises"), String(s.exercises), fmt("tops.cExercises.f", { n: s.testCases })),
    ].join("");
    const exs = d.exercises.length
      ? `<table class="t"><thead><tr><th>${T("tops.thExercise")}</th><th>${T("tops.thType")}</th><th>${T("tops.thAdversary")}</th><th>${T("tops.thCases")}</th><th>${T("tops.thPrevent")}</th><th>${T("tops.thDetect")}</th><th>${T("tops.thVisibility")}</th><th></th></tr></thead><tbody>${d.exercises.map((e: any) => `<tr>
          <td><span class="nm">${esc(e.name)}</span></td><td><span class="tm ${tcls(e.type)}">${esc(e.type)}</span></td><td class="muted" style="font-size:11px">${esc(e.actor)}</td>
          <td>${e.total}</td><td style="color:${rateColor(e.preventionRate)}">${e.preventionRate}%</td><td style="color:${rateColor(e.detectionRate)}">${e.detectionRate}%</td>
          <td>${bar(e.visibility)} <span class="muted">${e.visibility}%</span></td><td><button class="btn-sm2 open" data-id="${e.id}">${T("tops.open")}</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">${T("tops.noExercises")}</div>`;
    const tactics = d.byTactic.length ? d.byTactic.map((t: any) => `<div class="tac"><span class="nm2">${esc(t.tactic)}</span>${bar(t.rate)}<span style="min-width:80px;text-align:right;color:${rateColor(t.rate)};font-weight:700">${t.rate}% <span class="muted" style="font-weight:400">(${t.detected}/${t.tested})</span></span></div>`).join("") : `<div class="muted">${T("tops.noCases")}</div>`;
    const work = d.worklist.length
      ? `<ul class="worklist">${d.worklist.map((w: any) => `<li><span class="oc ${ocls(w.outcome === "logged-only" ? "logged" : "missed")}">${esc(w.outcome)}</span> <span class="mono">${esc(w.attackId)}</span> <b style="color:#e2e8f0">${esc(w.technique)}</b> <span class="muted">${esc(w.tactic)}</span> <a class="btn-sm2" style="margin-left:auto" href="/purple-team">${T("tops.buildDetection")}</a></li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${T("tops.noGaps")}</div>`;
    const caps = d.capByTeam.map((c: any) => `<div class="panel"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span class="tm ${tcls(c.team)}">${esc(c.team)} ${T("tops.team")}</span><span class="muted">${fmt("tops.capsMeta", { n: c.count, m: c.maturity == null ? "—" : c.maturity + "/5" })}</span></div>${d.capabilities.filter((x: any) => x.team === c.team).map((x: any) => `<div style="font-size:12px;padding:4px 0;border-top:1px solid #1e2133"><b style="color:#e2e8f0">${esc(x.name)}</b> <span class="muted">${esc(x.category)} · ${T("tops.maturity")} ${x.maturity ?? "—"}/5 · ${esc(x.capacity)}</span><div class="muted" style="font-size:11px">${esc(x.tooling)}</div></div>`).join("")}</div>`).join("");
    const autos = d.automations.map((a: any) => `<div class="auto"><span class="tm ${tcls(a.team)}">${esc(a.team)}</span> <b>${esc(a.name)}</b> — ${esc(a.desc)} <span class="muted" style="font-size:11px">[${esc(a.tools)}]</span></div>`).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${fmt("tops.secExercises", { n: d.exercises.length })}<span class="spacer"></span><button class="btn-sm2" id="new-ex">${T("tops.newExercise")}</button></div>${exs}
      <div class="grid2" style="margin-top:8px">
        <div class="panel"><div class="sec" style="margin-top:0">${T("tops.secTactic")}</div>${tactics}</div>
        <div class="panel"><div class="sec" style="margin-top:0">${fmt("tops.secWork", { n: d.worklist.length })}</div>${work}</div>
      </div>
      <div class="sec">${T("tops.secCaps")}</div><div class="grid2">${caps}</div>
      <div class="sec">${T("tops.secAutos")}</div><div class="panel">${autos}</div>`;
    Array.prototype.forEach.call(document.querySelectorAll(".open"), (b: HTMLElement) => { b.onclick = () => openExercise(Number(b.getAttribute("data-id"))); });
    $("new-ex").onclick = newExercise;
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}
function bar(pct: number): string { return `<div class="bar"><i style="width:${Math.max(0, Math.min(100, pct))}%;background:${rateColor(pct)}"></i></div>`; }

const OUTCOMES = (): string[][] => [["prevented", T("tops.oc.prevented")], ["detected", T("tops.oc.detected")], ["logged", T("tops.oc.logged")], ["missed", T("tops.oc.missed")]];
function openExercise(id: number): void {
  fetch(`/api/team-ops/exercise/${id}`).then((r) => r.json()).then((d) => {
    const e = d.exercise;
    const rows = d.cases.map((c: any) => `<tr>
      <td class="mono">${esc(c.attackId)}</td><td><span class="nm">${esc(c.technique)}</span><div class="muted" style="font-size:11px">${esc(c.tactic)}</div></td>
      <td style="font-size:12px;color:#cbd5e1">${esc(c.offensive)}${c.tool ? ` <span class="muted">[${esc(c.tool)}]</span>` : ""}</td>
      <td><select class="oc-sel" data-id="${c.id}">${OUTCOMES().map(([v, l]) => `<option value="${v}"${c.outcome === v ? " selected" : ""}>${l}</option>`).join("")}</select></td>
      <td class="muted" style="font-size:11px">${c.detectionTimeMin != null ? c.detectionTimeMin + "m" : ""}${c.detectionSource ? " · " + esc(c.detectionSource) : ""}</td></tr>`).join("");
    $("dlg").innerHTML = `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px"><b style="font-size:16px;color:#e7ebf3">${esc(e.name)}</b><span class="tm ${tcls(e.type)}">${esc(e.type)}</span><span class="spacer" style="flex:1"></span><button class="btn-sm2" id="add-tc">${T("tops.addCase")}</button><button class="btn-sm2" id="close">${T("tops.close")}</button></div>
      <div class="muted" style="font-size:12px;margin-bottom:10px">${esc(e.objective)}${e.actor ? ` · ${T("tops.adversary")}: ${esc(e.actor)}` : ""}</div>
      <table class="t"><thead><tr><th>ATT&CK</th><th>${T("tops.thTechnique")}</th><th>${T("tops.thRedAction")}</th><th>${T("tops.thBlueOutcome")}</th><th>${T("tops.thDetectionCol")}</th></tr></thead><tbody>${rows}</tbody></table>`;
    $("modal").classList.add("show");
    $("close").onclick = () => $("modal").classList.remove("show");
    $("add-tc").onclick = () => {
      const attackId = prompt(T("tops.promptAttackId")) || "";
      const technique = prompt(T("tops.promptTechnique")); if (!technique) return;
      const tactic = prompt(T("tops.promptTactic")) || "";
      const offensiveAction = prompt(T("tops.promptOffensive")) || "";
      post(`/api/team-ops/exercise/${id}/testcase`, { attackId, technique, tactic, offensiveAction }, () => openExercise(id));
    };
    Array.prototype.forEach.call(document.querySelectorAll(".oc-sel"), (sel: HTMLSelectElement) => {
      sel.onchange = () => {
        const body: any = { outcome: sel.value };
        if (sel.value === "detected") { const m = prompt(T("tops.promptDetTime"), "10"); if (m) body.detectionTimeMin = Number(m); body.detectionSource = "EDR/SIEM"; }
        post(`/api/team-ops/testcase/${sel.getAttribute("data-id")}/outcome`, body, () => { openExercise(id); load(); });
      };
    });
  }).catch((e) => toast("⚠️ " + e));
}
function post(url: string, body: unknown, cb: () => void): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast(T("tops.saved")); cb(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function newExercise(): void {
  const name = prompt(T("tops.promptExName")); if (!name) return;
  const type = prompt(T("tops.promptExType"), "Purple") || "Purple";
  const actor = prompt(T("tops.promptExActor")) || "";
  post("/api/team-ops/exercise", { name, type, actor }, () => load());
}
document.addEventListener("DOMContentLoaded", () => { initI18n(); $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").classList.remove("show"); }); load(); });
