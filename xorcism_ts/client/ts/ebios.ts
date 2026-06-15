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

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("eb-search") as HTMLInputElement).oninput = applyFilter;
  void load();
});
