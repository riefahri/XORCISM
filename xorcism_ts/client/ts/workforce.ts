/** workforce.ts — NICE + ENISA ECSF workforce roles around PERSON (/workforce). Reads /api/workforce. */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
function toast(m: string): void { const el = $("toast"); el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2400); }

let DATA: any = null;
const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;

function load(): void {
  fetch("/api/workforce").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    DATA = d; const s = d.summary;
    const cards = [
      card(t("wf.cRoles"), String(s.roles), fmt("wf.cRoles.foot", { e: s.ecsf, n: s.nice })),
      card(t("wf.cCoverage"), `${s.coverage}%`, fmt("wf.cCoverage.foot", { c: s.covered, r: s.roles }), s.coverage >= 60 ? "#4ade80" : "#fbbf24"),
      card(t("wf.cMapped"), String(s.assigned), t("wf.cMapped.foot")),
      card(t("wf.cGaps"), String(s.gaps), t("wf.cGaps.foot"), s.gaps ? "#fbbf24" : "#4ade80"),
    ].join("");
    const people = d.people.length
      ? `<table class="t"><thead><tr><th>${t("wf.thPerson")}</th><th>${t("wf.thRoles")}</th></tr></thead><tbody>${d.people.map((p: any) => `<tr><td><span class="nm">${esc(p.name)}</span></td><td>${p.roles.map((r: any) => `<span class="role${r.primary ? " prim" : ""}"><span class="fw fw-${esc(r.framework)}">${esc(r.framework)}</span> ${esc(r.name)}${r.proficiency ? ` · ${esc(r.proficiency)}` : ""} <a style="cursor:pointer;color:#f87171" data-un="${r.id}">×</a></span>`).join("") || `<span class='muted'>${t("wf.none")}</span>`} <button class="btn-sm2" data-assign="${p.id}">${t("wf.addRole")}</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">${t("wf.noPeople")}</div>`;
    const gaps = d.gaps.length ? d.gaps.map((g: any) => `<span class="gap"><span class="fw fw-${esc(g.framework)}">${esc(g.framework)}</span> ${esc(g.name)} <a style="cursor:pointer" data-assign-role="${g.id}">${t("wf.assign")}</a></span>`).join("") : `<span class="muted">${t("wf.allCovered")}</span>`;
    const roles = d.roles.map((r: any) => `<tr><td><span class="fw fw-${esc(r.framework)}">${esc(r.framework)}</span> <span class="code">${esc(r.code)}</span></td><td><span class="nm">${esc(r.name)}</span><div class="muted" style="font-size:11px">${esc(r.description)}</div></td><td class="muted" style="font-size:11px">${esc(r.skills)}</td><td>${r.holders.length ? r.holders.map((h: any) => esc(h.person)).join(", ") : "<span class='muted'>—</span>"}</td></tr>`).join("");
    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">${fmt("wf.secPeople", { n: d.people.length })}</div>${people}
      <div class="sec">${fmt("wf.secGaps", { n: d.gaps.length })}</div><div style="margin-bottom:6px">${gaps}</div>
      <div class="sec">${fmt("wf.secCatalogue", { n: d.roles.length })}</div><table class="t"><thead><tr><th>${t("wf.thFramework")}</th><th>${t("wf.thRole")}</th><th>${t("wf.thSkills")}</th><th>${t("wf.thHolders")}</th></tr></thead><tbody>${roles}</tbody></table>`;
    wire();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function rolePicker(): number | null {
  const list = DATA.roles.map((r: any, i: number) => `${i + 1}. [${r.framework}] ${r.name}`).join("\n");
  const pick = prompt(t("wf.pickRole") + "\n\n" + list);
  if (!pick) return null;
  const r = DATA.roles[Number(pick) - 1];
  return r ? r.id : null;
}
function personPicker(): number | null {
  const list = DATA.people.map((p: any, i: number) => `${i + 1}. ${p.name}`).join("\n") || t("wf.assignFromRow");
  const pick = prompt(t("wf.pickPerson") + "\n\n" + list);
  if (!pick) return null;
  const p = DATA.people[Number(pick) - 1];
  return p ? p.id : null;
}
function assign(personId: number, workRoleId: number): void {
  fetch("/api/workforce/assign", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ personId, workRoleId, proficiency: "Proficient" }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; })).then(() => { toast(t("wf.roleAssigned")); load(); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function wire(): void {
  Array.prototype.forEach.call(document.querySelectorAll("[data-assign]"), (b: HTMLElement) => { b.onclick = () => { const w = rolePicker(); if (w) assign(Number(b.getAttribute("data-assign")), w); }; });
  Array.prototype.forEach.call(document.querySelectorAll("[data-assign-role]"), (b: HTMLElement) => { b.onclick = () => { const p = personPicker(); if (p) assign(p, Number(b.getAttribute("data-assign-role"))); }; });
  Array.prototype.forEach.call(document.querySelectorAll("[data-un]"), (b: HTMLElement) => { b.onclick = () => { if (!confirm(t("wf.confirmRemove"))) return; fetch(`/api/workforce/assign/${b.getAttribute("data-un")}`, { method: "DELETE" }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then(() => { toast(t("wf.removed")); load(); }).catch((e) => toast("⚠️ " + e)); }; });
}
document.addEventListener("DOMContentLoaded", () => { initI18n(); load(); });
