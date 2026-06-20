/**
 * ebios.ts — EBIOS Risk Manager dashboard. Lists the cyber risk-analysis studies
 * (XCOMPLIANCE.RISKASSESSMENT marked EBIOS) with, per study, the count of the
 * objects of each workshop (business values, feared events, risk sources,
 * stakeholders, scenarios) — via /api/ebios/dashboard. Editing in the Explorer.
 */
import { initI18n, t } from "./i18n";

interface Counts {
  businessValues: number; supportingAssets: number; fearedEvents: number;
  riskSources: number; stakeholders: number; strategicScenarios: number; operationalScenarios: number;
}
interface Study {
  id: number; name: string; description: string; status: string;
  workshop: number | null; express: number | null; date: string; counts: Counts; maxSeverity: number;
}
interface Dashboard { studies: Study[]; stats: { total: number; businessValues?: number; scenarios?: number; riskSources?: number } }

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string)); }

const STATUS_COLOR: Record<string, string> = {
  draft: "#64748b", "in progress": "#f59e0b", inprogress: "#f59e0b", review: "#a78bfa",
  "in review": "#a78bfa", done: "#22c55e", approved: "#22c55e", deprecated: "#f87171",
};
// EBIOS severity 1..4 (minor → critical).
const SEV: Record<number, { label: string; color: string }> = {
  1: { label: "G1", color: "#22c55e" }, 2: { label: "G2", color: "#eab308" },
  3: { label: "G3", color: "#f59e0b" }, 4: { label: "G4", color: "#f87171" },
};

function pill(val: string, colors: Record<string, string>): string {
  if (!val) return "";
  const c = colors[val.toLowerCase()] || "#94a3b8";
  return `<span class="pill" style="color:${c}">${esc(val)}</span>`;
}
function sevPill(n: number): string {
  const s = SEV[n];
  return s ? `<span class="pill" style="color:${s.color}">${s.label}</span>` : "";
}

let all: Study[] = [];

function renderStats(s: Dashboard["stats"]): void {
  const stat = (n: unknown, l: string): string => `<div class="eb-stat"><div class="n">${esc(n)}</div><div class="l">${l}</div></div>`;
  $("eb-stats").innerHTML = [
    stat(s.total, t("ebios.studies")),
    stat(s.businessValues ?? 0, t("ebios.col.businessValues")),
    stat(s.scenarios ?? 0, t("ebios.col.scenarios")),
    stat(s.riskSources ?? 0, t("ebios.col.riskSources")),
  ].join("");
}

function studyLink(id: number, label: string): string {
  const href = `/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${id}`;
  return `<a href="${href}">${esc(label || `#${id}`)}</a>`;
}

function renderTable(rows: Study[]): void {
  if (!rows.length) { $("eb-table").innerHTML = `<div style="padding:20px;color:#64748b">${esc(t("ebios.empty"))}</div>`; return; }
  const head = [
    t("ebios.col.study"), t("ebios.col.status"), t("ebios.col.businessValues"), t("ebios.col.fearedEvents"),
    t("ebios.col.riskSources"), t("ebios.col.stakeholders"), t("ebios.col.scenarios"), t("ebios.col.severity"),
  ].map((h, i) => `<th${i >= 2 && i <= 6 ? ' style="text-align:center"' : ""}>${esc(h)}</th>`).join("");
  const body = rows.map((a) => {
    const c = a.counts;
    const scen = c.strategicScenarios + c.operationalScenarios;
    return `<tr>
      <td>${studyLink(a.id, a.name)}${a.express ? ' <span class="ws">express</span>' : ""}${a.workshop ? ` <span class="ws">A${esc(a.workshop)}</span>` : ""}</td>
      <td>${pill(a.status, STATUS_COLOR)}</td>
      <td class="num">${c.businessValues || ""}</td>
      <td class="num">${c.fearedEvents || ""}</td>
      <td class="num">${c.riskSources || ""}</td>
      <td class="num">${c.stakeholders || ""}</td>
      <td class="num">${scen ? `${scen}` : ""}${scen ? `<span class="ws" title="${esc(t("ebios.col.scenarios"))}"> ${c.strategicScenarios}/${c.operationalScenarios}</span>` : ""}</td>
      <td>${sevPill(a.maxSeverity)}</td>
    </tr>`;
  }).join("");
  $("eb-table").innerHTML = `<table class="eb"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function applyFilter(): void {
  const q = ($("eb-search") as HTMLInputElement).value.trim().toLowerCase();
  renderTable(!q ? all : all.filter((a) =>
    `${a.name} ${a.description} ${a.status}`.toLowerCase().includes(q)));
}

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/ebios/dashboard");
    if (!r.ok) { $("eb-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(t("ebios.error"))} ${r.status}</div>`; return; }
    const d = (await r.json()) as Dashboard;
    all = d.studies || [];
    renderStats(d.stats || { total: all.length });
    renderTable(all);
    $("eb-hint").textContent = t("ebios.hint");
  } catch (e) {
    $("eb-table").innerHTML = `<div style="padding:20px;color:#f87171">${esc(e)}</div>`;
  }
}

// ── Guided "new risk assessment" modal ───────────────────────────────────────
const METHOD_NOTE: Record<string, { text: string; cls: string }> = {
  "EBIOS RM": { text: "EBIOS RM — this study appears on this dashboard; continue with its 5 workshops.", cls: "info" },
  "ISO/IEC 27005": { text: "General risk assessment — manage scenarios in the Risk explorer.", cls: "muted" },
  "NIST SP 800-30": { text: "General risk assessment — manage scenarios in the Risk explorer.", cls: "muted" },
  FAIR: { text: "Quantitative — pair with FAIR-MAM for a $ materiality breakdown.", cls: "fair" },
  Custom: { text: "Custom methodology — a general risk assessment in the Risk explorer.", cls: "muted" },
};
let ownersLoaded = false;

function methodNote(): void {
  const m = ($("eb-f-method") as HTMLSelectElement).value;
  const note = $("eb-method-note");
  const info = METHOD_NOTE[m];
  note.className = "eb-method-note" + (info ? " show" : "");
  note.style.color = info?.cls === "info" ? "#7dd3fc" : info?.cls === "fair" ? "#6ee7b7" : "#94a3b8";
  note.style.background = info ? "#0f1117" : "";
  note.style.border = info ? "1px solid #2d3250" : "";
  note.textContent = info ? info.text : "";
  // Express mode is EBIOS-specific
  ($("eb-express-wrap") as HTMLElement).style.display = /^ebios/i.test(m) ? "" : "none";
}

async function loadOwners(): Promise<void> {
  if (ownersLoaded) return;
  ownersLoaded = true;
  try {
    const r = await fetch("/api/lookup?db=XORCISM&table=PERSON&idCol=PersonID&labelCol=FullName");
    if (!r.ok) return;
    const list = (await r.json()) as { id: unknown; label: unknown }[];
    const sel = $("eb-f-owner") as HTMLSelectElement;
    for (const o of (Array.isArray(list) ? list : []).slice(0, 500)) {
      if (o.label == null || String(o.label).trim() === "") continue;
      const opt = document.createElement("option");
      opt.value = String(o.id); opt.textContent = String(o.label);
      sel.appendChild(opt);
    }
  } catch { /* optional */ }
}

function openModal(): void {
  ($("eb-f-name") as HTMLInputElement).value = "";
  ($("eb-f-desc") as HTMLTextAreaElement).value = "";
  ($("eb-f-method") as HTMLSelectElement).value = "EBIOS RM";
  ($("eb-f-status") as HTMLSelectElement).value = "Draft";
  ($("eb-f-owner") as HTMLSelectElement).value = "";
  ($("eb-f-express") as HTMLInputElement).checked = false;
  ($("eb-f-date") as HTMLInputElement).value = new Date().toISOString().slice(0, 10);
  $("eb-f-err").textContent = ""; $("eb-f-err2").textContent = "";
  methodNote();
  void loadOwners();
  $("eb-modal").classList.add("open");
  ($("eb-f-name") as HTMLInputElement).focus();
}
function closeModal(): void { $("eb-modal").classList.remove("open"); }

function toast(html: string): void {
  const el = $("toast");
  el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 8000);
}

async function createStudy(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const name = v("eb-f-name").trim();
  const err = $("eb-f-err");
  if (!name) { err.textContent = t("ebios.modal.err.name"); ($("eb-f-name") as HTMLInputElement).focus(); return; }
  const btn = $("eb-create") as HTMLButtonElement;
  btn.disabled = true; err.textContent = ""; $("eb-f-err2").textContent = t("ebios.modal.creating");
  try {
    const body = {
      name, description: v("eb-f-desc").trim() || undefined, methodology: v("eb-f-method"),
      status: v("eb-f-status"), expressMode: ($("eb-f-express") as HTMLInputElement).checked,
      authorPersonId: v("eb-f-owner") || undefined, date: v("eb-f-date") || undefined,
    };
    const r = await fetch("/api/ebios/assessment", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal();
    await load();
    const link = `/?db=XCOMPLIANCE&table=RISKASSESSMENT&editCol=RiskAssessmentID&editVal=${d.id}`;
    toast(`✅ ${esc(t("ebios.modal.created"))} — <a href="${link}" style="color:#7dd3fc">${esc(t("ebios.modal.open"))} ↗</a>`);
  } catch (e) { $("eb-f-err2").textContent = ""; err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("eb-search") as HTMLInputElement).oninput = applyFilter;
  $("eb-new").addEventListener("click", openModal);
  $("eb-cancel").addEventListener("click", closeModal);
  $("eb-create").addEventListener("click", () => void createStudy());
  ($("eb-f-method") as HTMLSelectElement).addEventListener("change", methodNote);
  $("eb-modal").addEventListener("click", (e) => { if (e.target === $("eb-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  ($("eb-f-name") as HTMLInputElement)?.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void createStudy(); });
  void load();
});
