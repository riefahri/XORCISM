/**
 * nist-800-30.ts — NIST SP 800-30 risk-assessment cockpit (/nist-800-30). Dashboard of 800-30
 * assessments (threat sources / events / vulnerabilities / risks + risk distribution) and a
 * guided "New assessment" modal, from /api/nist-800-30. The 800-30 counterpart of /ebios.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const levelName = (l: number): string => (l >= 1 && l <= 5 ? t("n3.lvl" + l) : "");
const ab = (i: number): string => (i >= 1 && i <= 5 ? t("n3.ab" + i) : "");

interface Assessment {
  id: number; name: string; description: string | null; status: string; date: string | null;
  counts: { threatSources: number; threatEvents: number; vulnerabilities: number; risks: number };
  byLevel: Record<string, number>; maxRisk: number;
}
interface Dashboard {
  assessments: Assessment[];
  stats: { total: number; threatSources: number; threatEvents: number; vulnerabilities: number; risks: number; highRisks: number };
}

const stClass = (s: string): string => (/complet|done|clos/i.test(s) ? "st-done" : /progress|review|scoping/i.test(s) ? "st-prog" : "st-draft");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="n3-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function riskBadge(level: number): string {
  return level ? `<span class="rl rl${level}">${esc(levelName(level))}</span>` : `<span class="muted">—</span>`;
}

function rowHtml(a: Assessment): string {
  const c = a.counts;
  return `<tr>
    <td><div class="aname">${esc(a.name)}</div><div class="muted" style="font-size:11px">${a.date ? esc(a.date) : ""}</div></td>
    <td><span class="st ${stClass(a.status)}">${esc(a.status || "Draft")}</span></td>
    <td><span class="chip">${fmt("n3.nSources", { n: c.threatSources })}</span><span class="chip">${fmt("n3.nEvents", { n: c.threatEvents })}</span><span class="chip">${fmt("n3.nVulns", { n: c.vulnerabilities })}</span></td>
    <td>${c.risks}</td>
    <td>${riskBadge(a.maxRisk)}</td>
    <td><a class="chip" href="/?db=XCOMPLIANCE&table=NIST80030RISK&filterCol=RiskAssessmentID&filterVal=${a.id}">${t("n3.risksLink")}</a>
        <a class="chip" href="/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${a.id}">${t("n3.editLink")}</a></td>
  </tr>`;
}

// The NIST SP 800-30 Rev.1 Table I-2 risk matrix (overall likelihood rows × impact cols).
const MATRIX: Record<number, number[]> = {
  5: [1, 2, 3, 4, 5], 4: [1, 2, 3, 4, 5], 3: [1, 2, 3, 3, 4], 2: [1, 2, 2, 2, 3], 1: [1, 1, 1, 2, 2],
};
function matrixHtml(): string {
  let rows = "";
  for (let l = 5; l >= 1; l--) {
    let tds = `<th>${ab(l)}</th>`;
    for (let i = 1; i <= 5; i++) { const r = MATRIX[l][i - 1]; tds += `<td class="rl rl${r}" style="border-radius:0">${ab(r)}</td>`; }
    rows += `<tr>${tds}</tr>`;
  }
  return `<table class="mx"><caption>${t("n3.matrixCaption")}</caption>
    <tr><th>${t("n3.matrixLI")}</th><th>${ab(1)}</th><th>${ab(2)}</th><th>${ab(3)}</th><th>${ab(4)}</th><th>${ab(5)}</th></tr>${rows}</table>`;
}

function referenceHtml(): string {
  return `<div class="ref">
    <div class="col"><h4>${t("n3.procTitle")}</h4><ul>
      <li><b>${t("n3.proc1")}</b> — ${t("n3.proc1d")}</li>
      <li><b>${t("n3.proc2")}</b> — ${t("n3.proc2d")}</li>
      <li><b>${t("n3.proc3")}</b> — ${t("n3.proc3d")}</li>
      <li><b>${t("n3.proc4")}</b> — ${t("n3.proc4d")}</li></ul></div>
    <div class="col"><h4>${t("n3.srcTitle")}</h4><ul>
      <li><b>${t("n3.srcAdv")}</b> — ${t("n3.srcAdvD")}</li>
      <li><b>${t("n3.srcNon")}</b> — ${t("n3.srcNonD")}</li></ul></div>
    <div class="col"><h4>${t("n3.scaleTitle")}</h4>
      <ul><li>${t("n3.scaleD")}</li></ul>
      ${matrixHtml()}</div>
  </div>`;
}

async function load(): Promise<void> {
  let d: Dashboard;
  try { const r = await fetch("/api/nist-800-30/dashboard"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("n3-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.stats;

  const cards = [
    card(t("n3.cAssessments"), String(s.total), "NIST SP 800-30"),
    card(t("n3.cSources"), String(s.threatSources), t("n3.cSources.foot")),
    card(t("n3.cEvents"), String(s.threatEvents), t("n3.cEvents.foot")),
    card(t("n3.cVulns"), String(s.vulnerabilities), t("n3.cVulns.foot")),
    card(t("n3.cRisks"), String(s.risks), t("n3.cRisks.foot")),
    card(t("n3.cHigh"), String(s.highRisks), t("n3.cHigh.foot"), s.highRisks ? "#f87171" : "#34d399"),
  ].join("");

  const table = d.assessments.length
    ? `<table class="n3"><thead><tr><th>${t("n3.thAssessment")}</th><th>${t("n3.thStatus")}</th><th>${t("n3.thInventory")}</th><th>${t("n3.thRisks")}</th><th>${t("n3.thMaxRisk")}</th><th></th></tr></thead>
        <tbody>${d.assessments.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:18px 0">${t("n3.noAssessments")}</div>`;

  $("n3-body").innerHTML = `<div class="n3-cards">${cards}</div>
    <div class="n3-section">${fmt("n3.secAssessments", { n: d.assessments.length })}</div>${table}
    <div class="n3-section">${t("n3.secReference")}</div>${referenceHtml()}
    <div class="legend">${t("n3.legendPrefix")} <span class="rl rl1">${levelName(1)}</span> <span class="rl rl2">${levelName(2)}</span>
      <span class="rl rl3">${levelName(3)}</span> <span class="rl rl4">${levelName(4)}</span> <span class="rl rl5">${levelName(5)}</span>.
      ${t("n3.legendSuffix")}</div>`;
}

// ── Guided "new assessment" modal ──────────────────────────────────────────────
async function loadAuthors(): Promise<void> {
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const sel = $("n3-f-author") as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; sel.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

function openModal(): void {
  for (const id of ["n3-f-name", "n3-f-desc"]) (document.getElementById(id) as HTMLInputElement).value = "";
  (document.getElementById("n3-f-status") as HTMLSelectElement).value = "Draft";
  (document.getElementById("n3-f-author") as HTMLSelectElement).value = "";
  (document.getElementById("n3-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("n3-f-err").textContent = "";
  $("n3-modal").classList.add("open");
  ($("n3-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("n3-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAssessment(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("n3-f-name").trim();
  const err = $("n3-f-err");
  if (!name) { err.textContent = t("n3.errName"); ($("n3-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("n3-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("n3.creating");
  try {
    const body = {
      name, status: v("n3-f-status"), date: v("n3-f-date") || undefined,
      authorPersonId: v("n3-f-author") || undefined, description: v("n3-f-desc").trim() || undefined,
    };
    const r = await fetch("/api/nist-800-30/assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${d.id}`;
    toast(fmt("n3.created", { link }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("n3-new").addEventListener("click", openModal);
  $("n3-cancel").addEventListener("click", closeModal);
  $("n3-create").addEventListener("click", () => void createAssessment());
  $("n3-modal").addEventListener("click", (e) => { if (e.target === $("n3-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("n3-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAssessment(); });
  void loadAuthors();
  void load();
});
