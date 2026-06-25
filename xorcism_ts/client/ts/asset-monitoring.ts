/**
 * asset-monitoring.ts — Asset Monitoring cockpit (/asset-monitoring). Uptime/health/SSL monitors
 * over assets with status, uptime %, response time, SSL expiry and incidents, from /api/asset-monitoring.
 * Create monitors (guided modal) and change a monitor's status inline.
 */
import { initI18n, t } from "./i18n";
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface Check { id: number; assetId: number | null; asset: string; name: string; type: string; target: string; enabled: boolean; status: string; uptime: number | null; responseTime: number | null; lastChecked: string | null; sslExpiry: string | null; sslDays: number | null; source: string; }
interface Incident { id: number; monitor: string; asset: string; title: string; status: string; severity: string; startedAt: string | null; resolvedAt: string | null; open: boolean; }
interface Data {
  checkTypes: string[]; statuses: string[]; checks: Check[]; incidents: Incident[]; worklist: { kind: string; id: number; monitor: string; asset: string; label: string; severity: string }[];
  summary: { total: number; up: number; down: number; warning: number; paused: number; avgUptime: number | null; sslExpiringSoon: number; openIncidents: number; byType: Record<string, number>; byStatus: Record<string, number> };
}

let DATA: Data | null = null;
let STATUSES: string[] = [];

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="mn-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}
function sslCell(c: Check): string {
  if (c.sslExpiry == null) return `<span class="muted">—</span>`;
  const cls = c.sslDays == null ? "ssl-ok" : c.sslDays < 0 ? "ssl-over" : c.sslDays <= 30 ? "ssl-soon" : "ssl-ok";
  const txt = c.sslDays != null ? (c.sslDays < 0 ? fmt("am.sslExpired", { n: -c.sslDays }) : fmt("am.sslDaysLeft", { n: c.sslDays })) : c.sslExpiry;
  return `<span class="${cls}" title="${esc(c.sslExpiry)}">${esc(txt)}</span>`;
}
function rowHtml(c: Check): string {
  const opts = STATUSES.map((s) => `<option${s === c.status ? " selected" : ""}>${esc(s)}</option>`).join("");
  return `<tr data-id="${c.id}">
    <td><span class="dot d-${c.status}"></span><span class="aname">${esc(c.name)}</span>${!c.enabled ? ` <span class="muted" style="font-size:10px">${t("am.disabled")}</span>` : ""}<div class="mono muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.target)}</div></td>
    <td>${c.asset ? `<a href="/?db=XORCISM&table=ASSET&editCol=AssetID&editVal=${c.assetId}">${esc(c.asset)}</a>` : "<span class='muted'>—</span>"}</td>
    <td><span class="ty">${esc(c.type)}</span></td>
    <td>${c.uptime != null ? `${c.uptime}%` : "<span class='muted'>—</span>"}</td>
    <td>${c.responseTime != null ? `${c.responseTime} ms` : "<span class='muted'>—</span>"}</td>
    <td>${sslCell(c)}</td>
    <td><select class="pst" data-id="${c.id}">${opts}</select></td>
  </tr>`;
}
function applyFilters(): Check[] {
  if (!DATA) return [];
  const q = (($("mn-search") as HTMLInputElement)?.value || "").trim().toLowerCase();
  const ty = ($("mn-type") as HTMLSelectElement)?.value || "";
  const st = ($("mn-status") as HTMLSelectElement)?.value || "";
  return DATA.checks.filter((c) => (!q || `${c.name} ${c.asset} ${c.target}`.toLowerCase().includes(q)) && (!ty || c.type === ty) && (!st || c.status === st));
}
function renderTable(): void {
  const rows = applyFilters();
  const host = $("mn-table-host");
  host.innerHTML = rows.length
    ? `<table class="mn"><thead><tr><th>${t("am.thMonitor")}</th><th>${t("am.thAsset")}</th><th>${t("am.thType")}</th><th>${t("am.thUptime")}</th><th>${t("am.thResponse")}</th><th>${t("am.thSsl")}</th><th>${t("am.thStatus")}</th></tr></thead><tbody>${rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:14px 0">${t("am.noMatch")}</div>`;
  host.querySelectorAll<HTMLSelectElement>("select.pst").forEach((sel) => sel.addEventListener("change", () => void setStatus(Number(sel.dataset.id), sel.value)));
  const cnt = $("mn-count"); if (cnt) cnt.textContent = `(${rows.length}/${DATA?.checks.length ?? 0})`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/asset-monitoring"); if (!r.ok) throw new Error(`HTTP ${r.status}`); DATA = await r.json(); }
  catch (e) { $("mn-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  STATUSES = DATA!.statuses || [];
  const s = DATA!.summary;
  if (!DATA!.checks.length) {
    $("mn-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("am.emptyState")}</div>`;
    return;
  }
  const cards = [
    card(t("am.cMonitors"), String(s.total), fmt("am.cMonitors.foot", { up: s.up, down: s.down })),
    card(t("am.cUpDown"), `${s.up} / ${s.down}`, t("am.cUpDown.foot"), s.down ? "#f87171" : "#34d399"),
    card(t("am.cAvgUptime"), s.avgUptime != null ? `${s.avgUptime}%` : "—", t("am.cAvgUptime.foot"), s.avgUptime != null ? (s.avgUptime >= 99.9 ? "#34d399" : s.avgUptime >= 99 ? "#fbbf24" : "#f87171") : undefined),
    card(t("am.cSslExpiring"), String(s.sslExpiringSoon), t("am.cSslExpiring.foot"), s.sslExpiringSoon ? "#fbbf24" : "#34d399"),
    card(t("am.cOpenIncidents"), String(s.openIncidents), t("am.cOpenIncidents.foot"), s.openIncidents ? "#f87171" : "#34d399"),
    card(t("am.cWarnPaused"), `${s.warning} / ${s.paused}`, t("am.cWarnPaused.foot")),
  ].join("");
  const byStatus = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="dot d-${esc(k)}"></span>${esc(k)} <b>${n}</b></span>`).join("");
  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="ty">${esc(k)}</span> <b>${n}</b></span>`).join("");

  const work = DATA!.worklist.length
    ? `<ul style="list-style:none;margin:0;padding:0">${DATA!.worklist.slice(0, 40).map((w) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="stt st-${w.kind === "down" ? "down" : w.kind === "ssl" ? "warning" : "warning"}">${esc(w.kind)}</span> ${esc(w.label)}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">${t("am.allHealthy")}</div>`;
  const inc = DATA!.incidents.length
    ? `<ul style="list-style:none;margin:0;padding:0">${DATA!.incidents.slice(0, 30).map((i) => `<li style="padding:5px 0;border-bottom:1px solid #1e2133;font-size:13px"><span class="stt st-${i.open ? "down" : "up"}">${i.open ? t("am.open") : t("am.resolved")}</span> ${esc(i.title)}${i.asset ? ` <span class="muted">· ${esc(i.asset)}</span>` : ""}${i.startedAt ? ` <span class="muted" style="font-size:11px">${esc(String(i.startedAt).slice(0, 16))}</span>` : ""}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">${t("am.noIncidents")}</div>`;

  const filters = `<div class="filters">
    <input id="mn-search" type="search" placeholder="${t("am.searchPh")}" style="flex:1;min-width:200px">
    <select id="mn-type"><option value="">${t("am.allTypes")}</option>${(DATA!.checkTypes || []).map((x) => `<option>${esc(x)}</option>`).join("")}</select>
    <select id="mn-status"><option value="">${t("am.allStatuses")}</option>${STATUSES.map((x) => `<option>${esc(x)}</option>`).join("")}</select>
    <span id="mn-count" class="muted" style="font-size:12px"></span></div>`;

  $("mn-body").innerHTML = `<div class="mn-cards">${cards}</div>
    <div class="mn-section">${t("am.secByStatus")}</div><div class="breakdown">${byStatus}</div>
    <div class="mn-section">${t("am.secByType")}</div><div class="breakdown">${byType}</div>
    <div class="mn-section">${fmt("am.secWorklist", { n: DATA!.worklist.length })}</div>${work}
    <div class="mn-section">${t("am.secMonitors")}</div>${filters}<div id="mn-table-host"></div>
    <div class="mn-section">${fmt("am.secIncidents", { n: DATA!.incidents.length })}</div>${inc}
    <div class="legend">${t("am.legend")}</div>`;
  for (const id of ["mn-search", "mn-type", "mn-status"]) $(id).addEventListener("input", renderTable);
  renderTable();
}

function toast(html: string): void {
  const el = $("toast"); el.innerHTML = html;
  el.style.cssText = "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid #34d399;color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100";
  window.setTimeout(() => { el.innerHTML = ""; el.style.cssText = ""; }, 6000);
}

async function setStatus(id: number, status: string): Promise<void> {
  try {
    const r = await fetch("/api/asset-monitoring/status", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ checkId: id, status }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    toast(fmt("am.toastStatus", { s: esc(status) })); await load();
  } catch (e) { toast(`⚠️ ${e}`); }
}

// ── add-monitor modal ───────────────────────────────────────────────────────────
async function loadLookup(table: string, sel: string): Promise<void> {
  try {
    const idCol = table === "ASSET" ? "AssetID" : "PersonID"; const labelCol = table === "ASSET" ? "AssetName" : "FullName";
    const r = await fetch(`/api/lookup?db=XORCISM&table=${table}&idCol=${idCol}&labelCol=${labelCol}`);
    if (!r.ok) return;
    const list = (await r.json()) as { id: number; label: string }[];
    const el = $(sel) as HTMLSelectElement;
    for (const p of list) { const o = document.createElement("option"); o.value = String(p.id); o.textContent = p.label || `#${p.id}`; el.appendChild(o); }
  } catch { /* lookup unavailable */ }
}

// Asset → candidate targets (URL / host / IP), used to pre-fill the monitor target.
const assetTargetMap = new Map<string, { url: string; host: string; ip: string }>();
async function loadAssetTargets(): Promise<void> {
  try {
    const r = await fetch("/api/asset-monitoring/asset-targets");
    if (!r.ok) { await loadLookup("ASSET", "mn-f-asset"); return; }
    const d = (await r.json()) as { assets: { id: number; name: string; url: string; host: string; ip: string }[] };
    const el = $("mn-f-asset") as HTMLSelectElement;
    for (const a of d.assets) {
      const o = document.createElement("option"); o.value = String(a.id); o.textContent = a.name || `#${a.id}`; el.appendChild(o);
      assetTargetMap.set(String(a.id), { url: a.url, host: a.host, ip: a.ip });
    }
  } catch { await loadLookup("ASSET", "mn-f-asset"); }
}
// On asset (or type) selection: an HTTP(S) monitor pre-fills the target with the asset's URL.
function applyAssetTarget(force: boolean): void {
  const assetId = ($("mn-f-asset") as HTMLSelectElement).value;
  if (!assetId) return;
  const t = assetTargetMap.get(assetId);
  if (!t) return;
  const type = ($("mn-f-type") as HTMLSelectElement).value;
  const tgt = $("mn-f-target") as HTMLInputElement;
  if (type === "http" && t.url && (force || !tgt.value.trim())) tgt.value = t.url;
}

// Simple cron builder → writes mn-f-cron (still editable). Modes map to a 5-field cron.
function buildCron(): void {
  const mode = ($("mn-cron-mode") as HTMLSelectElement).value;
  const show = (id: string, on: boolean): void => { ($(id) as HTMLElement).style.display = on ? "" : "none"; };
  show("mn-cron-n", mode === "min" || mode === "hour");
  show("mn-cron-time", mode === "daily" || mode === "weekly" || mode === "monthly");
  show("mn-cron-dow", mode === "weekly");
  show("mn-cron-dom", mode === "monthly");
  const cronEl = $("mn-f-cron") as HTMLInputElement;
  if (mode === "" ) { cronEl.value = ""; return; }
  if (mode === "custom") return; // leave whatever the user typed
  const n = Math.max(1, Number(($("mn-cron-n") as HTMLInputElement).value) || 1);
  const [hh, mm] = (($("mn-cron-time") as HTMLInputElement).value || "09:00").split(":");
  const H = Math.max(0, Math.min(23, Number(hh) || 0)), M = Math.max(0, Math.min(59, Number(mm) || 0));
  const dow = ($("mn-cron-dow") as HTMLSelectElement).value;
  const dom = Math.max(1, Math.min(31, Number(($("mn-cron-dom") as HTMLInputElement).value) || 1));
  if (mode === "min") cronEl.value = `*/${Math.min(59, n)} * * * *`;
  else if (mode === "hour") cronEl.value = `0 */${Math.min(23, n)} * * *`;
  else if (mode === "daily") cronEl.value = `${M} ${H} * * *`;
  else if (mode === "weekly") cronEl.value = `${M} ${H} * * ${dow}`;
  else if (mode === "monthly") cronEl.value = `${M} ${H} ${dom} * *`;
}

function openModal(): void {
  ($("mn-f-name") as HTMLInputElement).value = "";
  ($("mn-f-type") as HTMLSelectElement).value = "http";
  ($("mn-f-target") as HTMLInputElement).value = "";
  ($("mn-f-interval") as HTMLInputElement).value = "300";
  ($("mn-f-asset") as HTMLSelectElement).value = "";
  ($("mn-f-owner") as HTMLSelectElement).value = "";
  ($("mn-f-ssl") as HTMLInputElement).value = "";
  ($("mn-f-cron") as HTMLInputElement).value = "";
  ($("mn-cron-mode") as HTMLSelectElement).value = "";
  buildCron(); // hides builder inputs + clears cron
  $("mn-ssl-wrap").style.display = "none";
  $("mn-f-err").textContent = "";
  $("mn-modal").classList.add("open");
  ($("mn-f-name") as HTMLInputElement).focus();
}

// ── activate-from-asset modal ────────────────────────────────────────────────────
function openActivate(): void {
  ($("mn-act-asset") as HTMLSelectElement).value = "";
  ($("mn-act-interval") as HTMLInputElement).value = "300";
  ($("mn-act-cron") as HTMLInputElement).value = "";
  ($("mn-act-owner") as HTMLSelectElement).value = "";
  document.querySelectorAll<HTMLInputElement>(".mn-act-type").forEach((c) => { c.checked = true; });
  $("mn-act-err").textContent = "";
  $("mn-act-modal").classList.add("open");
}
function closeActivate(): void { $("mn-act-modal").classList.remove("open"); }
async function runActivate(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const assetId = v("mn-act-asset");
  const err = $("mn-act-err");
  if (!assetId) { err.textContent = t("am.pickAsset"); return; }
  const types = Array.from(document.querySelectorAll<HTMLInputElement>(".mn-act-type:checked")).map((c) => c.value);
  const btn = $("mn-act-go") as HTMLButtonElement; btn.disabled = true; err.textContent = t("am.activating");
  try {
    const body = { assetId, intervalSeconds: v("mn-act-interval") || undefined,
      cronExpression: v("mn-act-cron").trim() || undefined, ownerPersonId: v("mn-act-owner") || undefined, types };
    const r = await fetch("/api/asset-monitoring/activate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeActivate(); await load();
    toast(d.created ? `${fmt("am.toastActivated", { n: d.created })}${d.skipped ? ` · ${fmt("am.toastActivatedSkip", { n: d.skipped })}` : ""}`
      : fmt("am.toastNoNew", { n: d.skipped }));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}
function closeModal(): void { $("mn-modal").classList.remove("open"); }

async function createMonitor(): Promise<void> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const name = v("mn-f-name").trim();
  const err = $("mn-f-err");
  if (!name) { err.textContent = t("am.enterName"); return; }
  const btn = $("mn-create") as HTMLButtonElement; btn.disabled = true; err.textContent = t("am.adding");
  try {
    const body = {
      name, type: v("mn-f-type"), target: v("mn-f-target").trim() || undefined,
      intervalSeconds: v("mn-f-interval") || undefined, cronExpression: v("mn-f-cron").trim() || undefined,
      assetId: v("mn-f-asset") || undefined,
      ownerPersonId: v("mn-f-owner") || undefined, sslExpiryDate: v("mn-f-ssl") || undefined,
    };
    const r = await fetch("/api/asset-monitoring/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal(); await load(); toast(t("am.toastMonitorAdded"));
  } catch (e) { err.textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

async function runChecks(): Promise<void> {
  const btn = $("mn-run") as HTMLButtonElement; btn.disabled = true; const label = btn.textContent; btn.textContent = t("am.checking");
  try {
    const r = await fetch("/api/asset-monitoring/run-checks", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    await load();
    toast(d.checked ? fmt("am.toastProbed", { n: d.checked }) : t("am.toastNoneDue"));
  } catch (e) { toast(`⚠️ ${e}`); }
  finally { btn.disabled = false; btn.textContent = label; }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("mn-run").addEventListener("click", () => void runChecks());
  $("mn-new").addEventListener("click", openModal);
  $("mn-cancel").addEventListener("click", closeModal);
  $("mn-create").addEventListener("click", () => void createMonitor());
  $("mn-modal").addEventListener("click", (e) => { if (e.target === $("mn-modal")) closeModal(); });
  $("mn-activate").addEventListener("click", openActivate);
  $("mn-act-cancel").addEventListener("click", closeActivate);
  $("mn-act-go").addEventListener("click", () => void runActivate());
  $("mn-act-modal").addEventListener("click", (e) => { if (e.target === $("mn-act-modal")) closeActivate(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); closeActivate(); } });
  ($("mn-f-type") as HTMLSelectElement).addEventListener("change", (e) => {
    $("mn-ssl-wrap").style.display = (e.target as HTMLSelectElement).value === "ssl" ? "" : "none";
    applyAssetTarget(false); // switching to HTTP(S) with an asset chosen pre-fills an empty target
  });
  ($("mn-f-asset") as HTMLSelectElement).addEventListener("change", () => applyAssetTarget(true));
  ["mn-cron-mode", "mn-cron-n", "mn-cron-time", "mn-cron-dow", "mn-cron-dom"].forEach((id) =>
    $(id).addEventListener("change", buildCron));
  ($("mn-cron-n") as HTMLInputElement).addEventListener("input", buildCron);
  void loadAssetTargets();
  void loadLookup("PERSON", "mn-f-owner");
  void loadLookup("ASSET", "mn-act-asset");
  void loadLookup("PERSON", "mn-act-owner");
  void load();
});
