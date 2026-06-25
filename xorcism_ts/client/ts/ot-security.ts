/**
 * ot-security.ts — OT / ICS / SCADA / IoT Security cockpit (/ot-security). Dashboard of OT
 * assessments (IEC 62443 / NIST SP 800-82, over AUDIT), OT assets (by tag), IEC 62443 zones, the
 * findings worklist and the seeded requirement catalogues, + a guided "New OT assessment" modal.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Assessment { id: number; name: string; standard: string; status: string; date: string | null; findings: number; open: number; high: number; overdue: number; score: number; }
interface Finding { id: number; assessment: string; name: string; severity: string; overdue: boolean; }
interface OtAsset { id: number; name: string; criticality: string; tags: string[]; }
interface Zone { id: number; name: string; purdue: string | null; slt: number | null; sla: number | null; criticality: string | null; }
interface Inventory {
  assessments: Assessment[]; findings: Finding[]; otAssets: OtAsset[]; zones: Zone[];
  summary: {
    assessments: number; inProgress: number; completed: number; openFindings: number; highOpen: number; overdue: number;
    otAssets: number; byTag: Record<string, number>; zones: number; conduits: number; slGaps: number;
    catalogue: { iec62443?: number; nist80082?: number; total: number }; bySeverity: Record<string, number>; byStandard: Record<string, number>;
  };
}

const stClass = (s: string): string => (/complet|clos|done/i.test(s) ? "st-done" : /progress|review|field|scoping/i.test(s) ? "st-prog" : "st-plan");
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="ot-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

function assessmentRow(a: Assessment): string {
  const posture = a.open ? `<span class="chip">${fmt("ot.openN", { n: a.open })}</span>${a.high ? `<span class="chip" style="color:#fca5a5">${fmt("ot.highN", { n: a.high })}</span>` : ""}${a.overdue ? `<span class="chip" style="color:#fca5a5">${fmt("ot.overdueN", { n: a.overdue })}</span>` : ""}` : `<span class="chip" style="color:#86efac">${t("ot.clean")}</span>`;
  return `<tr>
    <td><div class="aname">${esc(a.name)}</div></td>
    <td><span class="chip">${esc(a.standard)}</span></td>
    <td><span class="st ${stClass(a.status)}">${esc(a.status)}</span></td>
    <td>${a.findings}</td><td>${posture}</td>
    <td class="score ${scoreClass(a.score)}">${a.score || ""}</td>
    <td><a class="chip" href="/?db=XCOMPLIANCE&table=AUDITFINDING&filterCol=AuditID&filterVal=${a.id}">${t("ot.findingsLink")}</a>
        <a class="chip" href="/?db=XCOMPLIANCE&table=AUDIT&editCol=AuditID&editVal=${a.id}">${t("ot.editLink")}</a></td>
  </tr>`;
}

function slCell(z: Zone): string {
  if (z.slt == null) return `<span class="muted">—</span>`;
  const gap = z.sla == null || z.sla < z.slt;
  return `<span class="sl ${gap ? "sl-gap" : "sl-ok"}">SL-A ${z.sla ?? "?"} / SL-T ${z.slt}</span>`;
}

function referenceHtml(cat: Inventory["summary"]["catalogue"]): string {
  return `<div class="ref">
    <div class="col"><h4>${t("ot.refFrTitle")}</h4><ul>
      <li><b>FR1</b> ${t("ot.fr1")}</li><li><b>FR2</b> ${t("ot.fr2")}</li>
      <li><b>FR3</b> ${t("ot.fr3")}</li><li><b>FR4</b> ${t("ot.fr4")}</li>
      <li><b>FR5</b> ${t("ot.fr5")}</li><li><b>FR6</b> ${t("ot.fr6")}</li>
      <li><b>FR7</b> ${t("ot.fr7")}</li></ul></div>
    <div class="col"><h4>${t("ot.refSlTitle")}</h4><ul>
      <li><b>SL 1</b> ${t("ot.sl1")}</li>
      <li><b>SL 2</b> ${t("ot.sl2")}</li>
      <li><b>SL 3</b> ${t("ot.sl3")}</li>
      <li><b>SL 4</b> ${t("ot.sl4")}</li></ul>
      <div class="muted" style="font-size:11px;margin-top:5px">${t("ot.slNote")}</div></div>
    <div class="col"><h4>${t("ot.refCatTitle")}</h4><ul>
      <li><b>IEC 62443-3-3</b>: ${fmt("ot.catIec", { n: cat.iec62443 ?? 0 })}</li>
      <li><b>NIST SP 800-82 Rev 3</b>: ${fmt("ot.catNist", { n: cat.nist80082 ?? 0 })}</li></ul>
      ${cat.total ? `<a class="chip" href="/?db=XCOMPLIANCE&table=REFERENCECONTROL">${t("ot.browseCat")}</a>`
        : `<div class="muted" style="font-size:11px">${t("ot.seedCat")}</div>`}</div>
  </div>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/ot-security"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("ot-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  const cards = [
    card(t("ot.cAssessments"), String(s.assessments), fmt("ot.cAssessments.foot", { p: s.inProgress, d: s.completed })),
    card(t("ot.cAssets"), String(s.otAssets), t("ot.cAssets.foot"), s.otAssets ? "#7dd3fc" : undefined),
    card(t("ot.cZones"), `${s.zones}/${s.conduits}`, t("ot.cZones.foot")),
    card(t("ot.cSlGaps"), String(s.slGaps), t("ot.cSlGaps.foot"), s.slGaps ? "#f87171" : "#34d399"),
    card(t("ot.cOpenFindings"), String(s.openFindings), fmt("ot.cOpenFindings.foot", { n: s.highOpen }), s.highOpen ? "#f87171" : s.openFindings ? "#fb923c" : "#34d399"),
    card(t("ot.cCatalogue"), String(s.catalogue.total), t("ot.cCatalogue.foot"), s.catalogue.total ? undefined : "#fbbf24"),
  ].join("");

  const byTag = Object.entries(s.byTag).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="chip"><span class="tag">${esc(k)}</span> ${n}</span>`).join("");
  const byStd = Object.entries(s.byStandard).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="chip">${esc(k)} <b>${n}</b></span>`).join("");

  const assessTable = d.assessments.length
    ? `<table class="ot"><thead><tr><th>${t("ot.thAssessment")}</th><th>${t("ot.thStandard")}</th><th>${t("ot.thStatus")}</th><th>${t("ot.thFindings")}</th><th>${t("ot.thPosture")}</th><th title="${t("ot.thScore.title")}">${t("ot.thScore")}</th><th></th></tr></thead>
        <tbody>${d.assessments.map(assessmentRow).join("")}</tbody></table>`
    : `<div class="muted" style="padding:16px 0">${t("ot.noAssessments")}</div>`;

  const assetTable = d.otAssets.length
    ? `<table class="ot"><thead><tr><th>${t("ot.thAsset")}</th><th>${t("ot.thCriticality")}</th><th>${t("ot.thTags")}</th></tr></thead>
        <tbody>${d.otAssets.map((a) => `<tr><td><a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${a.id}">${esc(a.name)}</a></td>
          <td>${esc(a.criticality) || "<span class='muted'>—</span>"}</td>
          <td>${a.tags.map((tg) => `<span class="tag">${esc(tg)}</span>`).join("")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">${t("ot.noAssets")}</div>`;

  const zonesTable = d.zones.length
    ? `<table class="ot"><thead><tr><th>${t("ot.thZone")}</th><th>Purdue</th><th>${t("ot.thCriticality")}</th><th>${t("ot.thSecLevel")}</th></tr></thead>
        <tbody>${d.zones.map((z) => `<tr><td class="aname">${esc(z.name)}</td><td>${esc(z.purdue ?? "") || "—"}</td>
          <td>${esc(z.criticality ?? "") || "—"}</td><td>${slCell(z)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">${t("ot.noZones")}</div>`;

  $("ot-body").innerHTML = `<div class="ot-cards">${cards}</div>
    ${byTag ? `<div class="ot-section">${t("ot.secByTag")}</div><div>${byTag}</div>` : ""}
    ${byStd ? `<div class="ot-section">${t("ot.secByStandard")}</div><div>${byStd}</div>` : ""}
    <div class="ot-section">${fmt("ot.secAssessments", { n: d.assessments.length })}</div>${assessTable}
    <div class="ot-section">${fmt("ot.secOpenFindings", { n: d.findings.length })}</div>${d.findings.length
      ? `<ul style="list-style:none;margin:0;padding:0">${d.findings.slice(0, 40).map((f) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="sev-${esc(f.severity)}">${esc(f.severity)}</span> · <a href="/?db=XCOMPLIANCE&table=AUDITFINDING">${esc(f.assessment)}</a> — ${esc(f.name)}${f.overdue ? ` <span class="chip" style="color:#fca5a5">${t("ot.overdue")}</span>` : ""}</li>`).join("")}</ul>`
      : `<div class="muted" style="padding:8px 0">${t("ot.noOpenFindings")}</div>`}
    <div class="ot-section">${fmt("ot.secAssets", { n: d.otAssets.length })}</div>${assetTable}
    <div class="ot-section">${fmt("ot.secZones", { n: d.zones.length })}</div>${zonesTable}
    <div class="ot-section">${t("ot.secReference")}</div>${referenceHtml(s.catalogue)}
    <div class="legend">${t("ot.legend")}</div>`;
}

// ── Guided "new OT assessment" modal ───────────────────────────────────────────
function openModal(): void {
  for (const id of ["ot-f-name", "ot-f-auditor", "ot-f-scope", "ot-f-desc"]) (document.getElementById(id) as HTMLInputElement).value = "";
  (document.getElementById("ot-f-standard") as HTMLSelectElement).value = "IEC 62443-3-3";
  (document.getElementById("ot-f-status") as HTMLSelectElement).value = "Planned";
  (document.getElementById("ot-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("ot-f-err").textContent = "";
  $("ot-modal").classList.add("open");
  ($("ot-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("ot-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createAssessment(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("ot-f-name").trim();
  const err = $("ot-f-err");
  if (!name) { err.textContent = t("ot.errName"); ($("ot-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("ot-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = t("ot.creating");
  try {
    const body = {
      name, standard: v("ot-f-standard"), status: v("ot-f-status"),
      auditor: v("ot-f-auditor").trim() || undefined, date: v("ot-f-date") || undefined,
      scope: v("ot-f-scope").trim() || undefined, description: v("ot-f-desc").trim() || undefined,
    };
    const r = await fetch("/api/ot-security/assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    toast(fmt("ot.created", { id: d.id }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("ot-new").addEventListener("click", openModal);
  $("ot-cancel").addEventListener("click", closeModal);
  $("ot-create").addEventListener("click", () => void createAssessment());
  $("ot-modal").addEventListener("click", (e) => { if (e.target === $("ot-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("ot-f-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createAssessment(); });
  void load();
});
