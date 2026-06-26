/**
 * croc-orchestrator.ts — client for the agentic CROC orchestrator (/croc-orchestrator).
 * Renders KPI cards, the approval queue (proposed actions with verdict + recommended action +
 * approve/dismiss) and recently decided actions from /api/croc-orchestrator.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Action {
  id: number; loopEventId: number; eventType: string; severity: string; title: string; copilot: string;
  verdict: string; recommendedAction: string; rationale: string; confidence: number; status: string; createdDate: string;
  decidedDate?: string; executedOutcome?: string | null;
}
interface Data {
  summary: { proposed: number; approved: number; dismissed: number; critical: number; total: number };
  queue: Action[]; recent: Action[]; all: Action[]; canAct: boolean;
}
let DATA: Data | null = null;
const sevc = (s: string): string => `sv-${(s || "").toLowerCase()}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function queueItem(a: Action): string {
  const cls = (a.severity || "").toLowerCase() === "critical" ? "crit" : "high";
  const actions = DATA?.canAct
    ? `<div style="display:flex;gap:8px;margin-top:10px"><button class="btn btn-approve" data-approve="${a.id}">${t("cro.approve")}</button><button class="btn btn-dismiss" data-dismiss="${a.id}">${t("cro.dismiss")}</button></div>`
    : `<div class="muted" style="font-size:11px;margin-top:8px">${t("cro.readonly")}</div>`;
  return `<div class="item ${cls}">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span>
      <span class="nm" style="font-size:14px">${esc(a.title)}</span>
      <span class="spacer" style="flex:1"></span>
      <span class="pill">🤖 ${esc(a.copilot)}</span>
      <span class="muted" style="font-size:11px">conf <span class="conf" style="width:${Math.max(8, a.confidence * 0.5)}px"></span> ${a.confidence}%</span>
    </div>
    <div style="margin-top:6px;font-size:12.5px"><b style="color:#67e8f9">${t("cro.verdict")}</b> ${esc(a.verdict)}</div>
    <div class="rec"><b>${t("cro.recommended")}</b> ${esc(a.recommendedAction)}</div>
    <div class="rationale">${esc(a.rationale)} <span class="muted">· ${fmt("cro.eventRef", { n: a.loopEventId, type: esc(a.eventType) })}</span></div>
    ${actions}
  </div>`;
}

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card(t("cro.cQueue"), s.proposed, t("cro.cQueue.f"), s.proposed ? "#fbbf24" : "#34d399"),
    card(t("cro.cCritical"), s.critical, t("cro.cCritical.f"), s.critical ? "#f87171" : "#34d399"),
    card(t("cro.cApproved"), s.approved, t("cro.cApproved.f")),
    card(t("cro.cDismissed"), s.dismissed, t("cro.cDismissed.f")),
    card(t("cro.cTotal"), s.total, t("cro.cTotal.f")),
  ].join("");
  const queue = d.queue.length ? d.queue.map(queueItem).join("") : `<div class="muted" style="padding:10px 0">${t("cro.queueClear")}</div>`;
  const recent = d.recent.length
    ? `<table class="t"><thead><tr><th>${t("cro.thSeverity")}</th><th>${t("cro.thAction")}</th><th>${t("cro.thCopilot")}</th><th>${t("cro.thDecision")}</th><th>${t("cro.thWhen")}</th></tr></thead><tbody>${d.recent.map((a) => `<tr><td><span class="sev ${sevc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.title)}</td><td>${esc(a.copilot)}</td><td>${a.status === "approved" ? `<span style='color:#34d399'>${t("cro.approvedTag")}</span>${a.executedOutcome ? `<div class="muted" style="font-size:11px">↳ ${esc(a.executedOutcome)}</div>` : ""}` : `<span class='muted'>${t("cro.dismissedTag")}</span>`}</td><td class="muted" style="font-size:11px">${esc((a.decidedDate || a.createdDate || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("")}</tbody></table>`
    : "";

  body.innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">${fmt("cro.secQueue", { n: d.queue.length })}</div>${queue}
    ${recent ? `<div class="sec">${t("cro.secRecent")}</div>${recent}` : ""}`;

  body.querySelectorAll<HTMLElement>("[data-approve]").forEach((b) => b.addEventListener("click", () => void decide(Number(b.dataset.approve), "approved")));
  body.querySelectorAll<HTMLElement>("[data-dismiss]").forEach((b) => b.addEventListener("click", () => void decide(Number(b.dataset.dismiss), "dismissed")));
  for (const id of ["o-run", "o-demo"]) { const btn = $(id) as HTMLButtonElement | null; if (btn && !d.canAct) { btn.disabled = true; btn.style.opacity = "0.5"; } }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/croc-orchestrator")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
async function decide(id: number, decision: string): Promise<void> {
  try { render(await getJson(`/api/croc-orchestrator/${id}/decision`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision }) })); toast(decision === "approved" ? t("cro.toastApproved") : t("cro.toastDismissed")); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function run(): Promise<void> {
  try { const d = await getJson("/api/croc-orchestrator/run", { method: "POST" }); render(d); toast(fmt("cro.toastScanned", { n: d.scanned, m: d.proposed })); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}
async function demo(): Promise<void> {
  try { const d = await getJson("/api/croc-orchestrator/seed-demo", { method: "POST" }); render(d); toast(fmt("cro.toastEmitted", { n: d.emitted, m: d.proposed })); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("o-run")?.addEventListener("click", () => void run());
  $("o-demo")?.addEventListener("click", () => void demo());
  void load();
});
