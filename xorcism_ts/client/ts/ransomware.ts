/**
 * ransomware.ts — Ransomware-to-$ scenario simulator (/ransomware).
 * Pick an ATT&CK ransomware group → quantified SLE/ALE, the blast radius, kill-chain
 * coverage, and the controls that break the chain. Data from /api/ransomware/*.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Group { attackId: string; name: string; techniques: number }
interface Scenario {
  group: { attackId: string; name: string } | null; techniques: number; hasEncryption: boolean; hasInhibitRecovery: boolean;
  phases: { name: string; covered: boolean }[]; phasesCovered: number; phasesTotal: number;
  impacted: { assetId: number; name: string; value: number }[]; currency: string;
  primaryLoss: number; ransom: number; recovery: number; sle: number; aro: number; ale: number; residualSle: number;
  controls: { name: string; source: string; effect: string }[]; assumptions: string[];
}

let CUR = "USD";
function money(n: number): string {
  try { return new Intl.NumberFormat(undefined, { style: "currency", currency: CUR, maximumFractionDigits: 0 }).format(n); }
  catch { return "$" + Math.round(n).toLocaleString(); }
}

async function jget(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }

function render(d: Scenario): void {
  CUR = d.currency || "USD";
  const cut = d.sle > 0 ? Math.round((1 - d.residualSle / d.sle) * 100) : 0;
  $("rw-sub").innerHTML = d.group
    ? fmt("rw.scenario", { name: esc(d.group.name), id: esc(d.group.attackId), n: d.techniques, c: d.phasesCovered, t: d.phasesTotal }) + (d.hasEncryption ? " " + t("rw.usesEncryption") : "") + "."
    : t("rw.noGroup");
  if (!d.impacted.length) {
    $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("rw.noAssets")}</div>`;
    return;
  }
  $("rw-body").innerHTML = `
    <div class="hero">
      <div class="card hcard sle"><div class="lbl">${t("rw.cSle")}</div><div class="big">${money(d.sle)}</div><div class="note">${t("rw.cSle.note")}</div></div>
      <div class="card hcard ale"><div class="lbl">${t("rw.cAle")}</div><div class="big">${money(d.ale)}</div><div class="note">${fmt("rw.cAle.note", { aro: d.aro })}</div></div>
      <div class="card hcard res"><div class="lbl">${t("rw.cRes")}</div><div class="big">${money(d.residualSle)}</div><div class="note">${fmt("rw.cRes.note", { cut })}</div></div>
    </div>

    <div class="hero">
      <div class="card hcard"><div class="lbl">${t("rw.lossBreakdown")}</div>
        <div class="brk" style="margin-top:8px">
          <div class="r"><span>${t("rw.primaryLoss")}</span><b>${money(d.primaryLoss)}</b></div>
          <div class="r"><span>${t("rw.ransom")}</span><b>${money(d.ransom)}</b></div>
          <div class="r"><span>${t("rw.recovery")}</span><b>${money(d.recovery)}</b></div>
          <div class="r tot"><span>${t("rw.cSle")}</span><span>${money(d.sle)}</span></div>
        </div>
      </div>
      <div class="card hcard"><div class="lbl">${fmt("rw.killchain", { c: d.phasesCovered, t: d.phasesTotal })}</div>
        <div class="phases">${d.phases.map((p) => `<span class="ph${p.covered ? " on" : ""}">${esc(p.name)}</span>`).join("")}</div>
        ${d.hasInhibitRecovery ? `<div class="note" style="margin-top:8px;color:#fca5a5">${t("rw.inhibitRecovery")}</div>` : ""}
      </div>
    </div>

    <h3>${fmt("rw.blastRadius", { n: d.impacted.length })}</h3>
    <table class="rw"><thead><tr><th>${t("rw.thAsset")}</th><th style="text-align:right">${t("rw.thValueAtRisk")}</th></tr></thead><tbody>${
      d.impacted.slice(0, 50).map((a) => `<tr><td>${esc(a.name)}</td><td class="v">${money(a.value)}</td></tr>`).join("")}</tbody></table>

    <h3>${t("rw.controlsTitle")}</h3>
    <div class="card">${d.controls.map((c) => `<div class="ctl"><b>${esc(c.name)}</b><span class="src">${esc(c.source)}</span><div class="muted" style="font-size:12px">${esc(c.effect)}</div></div>`).join("")}</div>

    <div class="assume"><b>${t("rw.assumptions")}</b><br>${d.assumptions.map(esc).join("<br>")}</div>`;
}

async function loadScenario(group?: string): Promise<void> {
  $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("rw.computing")}</div>`;
  try { render(await jget(`/api/ransomware/scenario${group ? `?group=${encodeURIComponent(group)}` : ""}`)); }
  catch (e) { $("rw-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("rw.loadFailed", { e: esc(e) })}</div>`; }
}

document.addEventListener("DOMContentLoaded", async () => {
  initI18n();
  const sel = $("rw-group") as HTMLSelectElement;
  try {
    const groups: Group[] = await jget("/api/ransomware/groups");
    sel.innerHTML = groups.map((g) => `<option value="${esc(g.attackId)}">${fmt("rw.groupOption", { name: esc(g.name), id: esc(g.attackId), n: g.techniques })}</option>`).join("");
  } catch { sel.innerHTML = `<option value="">${t("rw.groupsUnavailable")}</option>`; }
  sel.addEventListener("change", () => void loadScenario(sel.value));
  const q = new URLSearchParams(location.search).get("group");
  if (q) sel.value = q;
  void loadScenario(sel.value || undefined);
});
