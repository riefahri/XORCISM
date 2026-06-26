/**
 * siem.ts — client for SIEM-lite (/siem). KPI cards, severity breakdown, recent SIEM alerts and
 * top-matched rules from /api/siem; a log-ingest box that posts events → Sigma detection → alerts.
 */
// NB: import as T — `t` is used as a map param in this file (.map((t) => t.trim())).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Alert { id: number; name: string; severity: string; attack: string | null; status: string; created: string }
interface Data {
  summary: { rulesLoaded: number; builtinRules: number; events24h: number; eventsTotal: number; alerts: number; critical: number; high: number };
  bySev: Record<string, number>; alerts: Alert[]; topRules: { name: string; n: number }[]; canIngest: boolean;
}
const sevc = (s: string): string => `sv-${s}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card(T("siem.cRules"), s.rulesLoaded, fmt("siem.cRules.f", { n: s.builtinRules })),
    card(T("siem.cEvents"), s.events24h, fmt("siem.cEvents.f", { n: s.eventsTotal })),
    card(T("siem.cAlerts"), s.alerts, T("siem.cAlerts.f"), s.alerts ? "#fbbf24" : "#34d399"),
    card(T("siem.cCritical"), s.critical, T("siem.cCritical.f"), s.critical ? "#f87171" : "#34d399"),
    card(T("siem.cHigh"), s.high, T("siem.cHigh.f"), s.high ? "#fbbf24" : undefined),
  ].join("");
  const alerts = d.alerts.length
    ? `<table class="t"><thead><tr><th>${T("siem.thSeverity")}</th><th>${T("siem.thDetection")}</th><th>ATT&CK</th><th>${T("siem.thStatus")}</th><th>${T("siem.thWhen")}</th></tr></thead><tbody>${d.alerts.map((a) => `<tr><td><span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span></td><td class="nm">${esc(a.name)}</td><td>${(a.attack || "").split(",").map((t) => t.trim()).filter(Boolean).map((t) => `<span class="chip">${esc(t)}</span>`).join("") || "<span class='muted'>—</span>"}</td><td>${esc(a.status)}</td><td class="muted" style="font-size:11px">${esc((a.created || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${T("siem.noAlerts")}</div>`;
  const top = d.topRules.length ? `<div style="margin-top:6px">${d.topRules.map((r) => `<span class="chip"><b>${r.n}</b> ${esc(r.name)}</span>`).join(" ")}</div>` : "";

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">${fmt("siem.secAlerts", { n: d.alerts.length })}</div>${alerts}
    ${top ? `<div class="sec">${T("siem.secTop")}</div>${top}` : ""}`;
  if (!d.canIngest) for (const id of ["ing", "samp"]) { const b = $(id) as HTMLButtonElement | null; if (b) { b.disabled = true; b.style.opacity = "0.5"; } }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/siem")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
function status(msg: string): void { const s = $("stat"); if (s) s.textContent = msg; }

async function ingest(): Promise<void> {
  const txt = ($("logs") as HTMLTextAreaElement).value.trim();
  if (!txt) { status(T("siem.pasteFirst")); return; }
  let events: any;
  try { events = JSON.parse(txt); if (!Array.isArray(events)) events = [events]; } catch { status(T("siem.invalidJson")); return; }
  try {
    const d = await getJson("/api/siem/ingest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }) });
    render(d); status(fmt("siem.ingested", { n: d.ingested, m: d.matched }));
    toast(d.matched ? fmt("siem.raised", { m: d.matched }) : T("siem.noDetections"));
  } catch (e) { status(`⚠️ ${(e as Error).message}`); }
}
async function sample(): Promise<void> {
  try { const d = await getJson("/api/siem/sample", { method: "POST" }); render(d); status(fmt("siem.sampleStat", { n: d.ingested, m: d.matched })); toast(fmt("siem.raised", { m: d.matched })); }
  catch (e) { status(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("ing")?.addEventListener("click", () => void ingest());
  $("samp")?.addEventListener("click", () => void sample());
  void load();
});
