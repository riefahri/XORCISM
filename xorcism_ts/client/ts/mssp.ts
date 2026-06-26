/** mssp.ts — client for the MSSP multi-tenant rollup (/mssp). KPI cards + per-tenant posture table. */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface TRow { tenant: number; name: string; posture: number; grade: string; enterpriseRisk: number; aoi: number | null; assets: number; openVulns: number; kev: number; openIncidents: number; openFindings: number; aiGaps: number }
interface Data { summary: { tenants: number; avgPosture: number; atRisk: number; avgAoi: number | null; totalKev: number; totalOpenIncidents: number; totalOpenFindings: number }; tenants: TRow[] }
const aoiColor = (n: number): string => (n >= 600 ? "#f87171" : n >= 300 ? "#fbbf24" : "#34d399");

const pColor = (p: number): string => p >= 70 ? "#34d399" : p >= 55 ? "#fbbf24" : p >= 40 ? "#fb923c" : "#f87171";
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
const num = (n: number, warnAt = 1): string => n >= warnAt ? `<b style="color:#fca5a5">${n}</b>` : `<span class="muted">${n}</span>`;

function row(t: TRow): string {
  return `<tr>
    <td><span class="g g-${esc(t.grade)}">${esc(t.grade)}</span></td>
    <td><span class="nm">${esc(t.name)}</span> <span class="muted">#${t.tenant}</span></td>
    <td><span class="bar" style="width:${Math.max(6, t.posture * 0.8)}px;background:${pColor(t.posture)}"></span> <b>${t.posture}</b><span class="muted">/100</span></td>
    <td>${t.enterpriseRisk}</td>
    <td>${t.aoi == null ? `<span class="muted">—</span>` : `<b style="color:${aoiColor(t.aoi)}">${t.aoi}</b>`}</td>
    <td>${t.assets}</td>
    <td>${num(t.openVulns)}</td>
    <td>${t.kev ? `<span class="pill" style="background:#7f1d1d;color:#fecaca">${t.kev} KEV</span>` : `<span class="muted">0</span>`}</td>
    <td>${num(t.openIncidents)}</td>
    <td>${num(t.openFindings)}</td>
    <td>${num(t.aiGaps)}</td>
  </tr>`;
}

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card(t("mssp.cTenants"), s.tenants, fmt("mssp.cTenants.f", { n: s.avgPosture })),
    card(t("mssp.cAtRisk"), s.atRisk, t("mssp.cAtRisk.f"), s.atRisk ? "#f87171" : "#34d399"),
    card(t("mssp.cAoi"), s.avgAoi == null ? "—" : s.avgAoi, t("mssp.cAoi.f"), s.avgAoi == null ? undefined : aoiColor(s.avgAoi)),
    card(t("mssp.cKev"), s.totalKev, t("mssp.cKev.f"), s.totalKev ? "#f87171" : "#34d399"),
    card(t("mssp.cIncidents"), s.totalOpenIncidents, t("mssp.cIncidents.f"), s.totalOpenIncidents ? "#fbbf24" : "#34d399"),
    card(t("mssp.cFindings"), s.totalOpenFindings, t("mssp.cFindings.f"), s.totalOpenFindings ? "#fbbf24" : undefined),
  ].join("");
  body.innerHTML = `<div class="cards">${cards}</div>
    <table class="t"><thead><tr><th>${t("mssp.thGrade")}</th><th>${t("mssp.thTenant")}</th><th>${t("mssp.thPosture")}</th><th>${t("mssp.thEntRisk")}</th><th>AOI</th><th>${t("mssp.thAssets")}</th><th>${t("mssp.thOpenVulns")}</th><th>KEV</th><th>${t("mssp.thIncidents")}</th><th>${t("mssp.thFindings")}</th><th>${t("mssp.thAiGaps")}</th></tr></thead>
    <tbody>${d.tenants.map(row).join("") || `<tr><td colspan="11" class="muted" style="padding:16px;text-align:center">${t("mssp.noTenants")}</td></tr>`}</tbody></table>`;
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  fetch("/api/mssp").then((r) => r.json().then((d) => { if (!r.ok) throw new Error(d.error || r.status); return d; }))
    .then(render)
    .catch((e) => { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message)}</div>`; });
});
