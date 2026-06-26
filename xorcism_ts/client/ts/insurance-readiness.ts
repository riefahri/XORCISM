/**
 * insurance-readiness.ts — client for the Cyber Insurance Readiness cockpit (/insurance-readiness).
 * Renewal-readiness gauge + the underwriter control checklist (live-derived) + a gap worklist ordered
 * by underwriting weight + the self-attestation list. Reads /api/insurance-readiness.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Ctl { id: string; name: string; category: string; weight: number; insurerWhy: string; status: string; score: number | null; metric: string; evidence: string[] }
interface Policy { carrier: string; policyNumber: string; coverageLimit: number; retention: number; premium: number; currency: string; renewalDate: string; status: string; notes: string }
interface Program {
  policy: Policy | null;
  coverage: { limit: number; modeledLoss: number | null; currency: string; adequacy: string; gap: number; source: string };
  renewal: { date: string; daysToRenewal: number | null; status: string };
}
interface Data {
  score: number; grade: string; verdict: string; controls: Ctl[]; attest: Ctl[];
  summary: { met: number; partial: number; gap: number; attestPending: number; critical: number };
  worklist: { name: string; insurerWhy: string; metric: string; weight: number; impact: number }[];
  program: Program; canEdit: boolean;
}
let DATA: Data | null = null;
const money = (n: number, cur: string): string => `${cur} ${Math.round(n).toLocaleString()}`;
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
const gColor = (g: string): string => (g === "A" ? "#34d399" : g === "B" ? "#a3e635" : g === "C" ? "#fbbf24" : g === "D" ? "#fb923c" : "#f87171");
const scoreColor = (s: number | null): string => (s == null ? "#94a3b8" : s >= 80 ? "#34d399" : s >= 50 ? "#fbbf24" : "#f87171");

function ctlRow(c: Ctl): string {
  const w = c.score == null ? 0 : c.score;
  return `<tr>
    <td><span class="nm">${esc(c.name)}</span><div class="muted" style="font-size:11px;max-width:420px">${esc(c.insurerWhy)}</div></td>
    <td>${esc(c.category)}</td>
    <td><span class="st st-${esc(c.status)}">${esc(c.status)}</span></td>
    <td style="white-space:nowrap">${c.score == null ? `<span class="muted">—</span>` : `<span class="bar" style="width:${Math.max(6, w * 0.6)}px;background:${scoreColor(c.score)}"></span> <b>${c.score}</b>`}</td>
    <td class="muted" style="font-size:12px">${esc(c.metric)}</td>
    <td class="muted">${c.weight}</td>
  </tr>`;
}

function polPanel(d: Data): string {
  const p = d.program.policy, cov = d.program.coverage, ren = d.program.renewal;
  const editBtn = d.canEdit ? `<button class="btn-sm2" id="pol-edit">${p ? t("ir.editPolicy") : t("ir.addPolicy")}</button>` : "";
  const renCol = ren.status === "overdue" ? "#f87171" : ren.status === "due-soon" ? "#fbbf24" : "#34d399";
  const renTxt = ren.daysToRenewal == null ? `<span class='muted'>${t("ir.notSet")}</span>`
    : ren.daysToRenewal < 0 ? `<b style="color:${renCol}">${fmt("ir.overdueD", { n: Math.abs(ren.daysToRenewal) })}</b> (${esc(ren.date)})`
    : `<b style="color:${renCol}">${fmt("ir.daysD", { n: ren.daysToRenewal })}</b> (${esc(ren.date)})`;
  const adq = cov.adequacy === "covered" ? `<b style="color:#34d399">${t("ir.covered")}</b>`
    : cov.adequacy === "underinsured" ? `<b style="color:#f87171">${fmt("ir.underinsured", { money: money(cov.gap, cov.currency) })}</b>`
    : `<span class="muted">${t("ir.adqUnknown")}</span>`;
  const left = p
    ? `<div class="kv"><div class="lab">${t("ir.policy")}</div><b>${esc(p.carrier || "—")}</b>${p.policyNumber ? ` · ${esc(p.policyNumber)}` : ""} · ${esc(p.status)}<br>
        ${t("ir.limit")} <b>${money(p.coverageLimit, p.currency)}</b> · ${t("ir.retention")} ${money(p.retention, p.currency)}${p.premium ? ` · ${t("ir.premium")} ${money(p.premium, p.currency)}` : ""}</div>`
    : `<div class="kv"><div class="lab">${t("ir.policy")}</div><span class="muted">${t("ir.noPolicy")}</span></div>`;
  const right = `<div class="kv"><div class="lab">${t("ir.renewalAdq")}</div>
      ${t("ir.renewalIn")} ${renTxt}<br>
      ${t("ir.modeledLoss")} <b>${cov.modeledLoss == null ? "—" : money(cov.modeledLoss, cov.currency)}</b> → ${adq}</div>`;
  return `<div class="pol">${left}${right}<div style="grid-column:1/-1;display:flex;justify-content:flex-end">${editBtn}</div></div>`;
}

function render(d: Data): void {
  DATA = d;
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const hero = `<div class="hero">
    <div class="gauge"><div class="n" style="color:${gColor(d.grade)}">${d.score}<span style="font-size:20px;color:#64748b">/100</span></div>
      <div class="g">${fmt("ir.gradeReadiness", { g: `<b style="color:${gColor(d.grade)}">${esc(d.grade)}</b>` })}</div></div>
    <div><div class="nm" style="font-size:15px;margin-bottom:6px">${esc(d.verdict)}</div>
      <div class="muted" style="font-size:12.5px;line-height:1.6">${fmt("ir.heroMet", { met: s.met })} · ${fmt("ir.heroPartial", { n: s.partial })} · <span style="color:${s.gap ? "#f87171" : "#34d399"}">${fmt("ir.heroGaps", { n: s.gap })}</span>${s.critical ? ` · <span style="color:#f87171">${fmt("ir.heroCritical", { n: s.critical })}</span>` : ""} · ${fmt("ir.heroAttest", { n: s.attestPending })}</div></div>
  </div>`;

  const cards = `<div class="cards">${[
    card(t("ir.cReadiness"), `${d.score}/100`, fmt("ir.cReadiness.f", { g: d.grade }), gColor(d.grade)),
    card(t("ir.cMet"), s.met, t("ir.cMet.f"), "#34d399"),
    card(t("ir.cGaps"), s.gap, t("ir.cGaps.f"), s.gap ? "#f87171" : "#34d399"),
    card(t("ir.cCritical"), s.critical, t("ir.cCritical.f"), s.critical ? "#f87171" : "#34d399"),
    card(t("ir.cAttest"), s.attestPending, t("ir.cAttest.f")),
  ].join("")}</div>`;

  const work = `<div class="sec">${t("ir.secWork")}</div>` + (d.worklist.length
    ? `<table class="t"><thead><tr><th>${t("ir.thControl")}</th><th>${t("ir.thWhyCares")}</th><th>${t("ir.thCurrent")}</th><th>${t("ir.thImpact")}</th></tr></thead><tbody>${d.worklist.map((w) => `<tr><td><span class="nm">${esc(w.name)}</span></td><td class="muted" style="font-size:12px">${esc(w.insurerWhy)}</td><td class="muted" style="font-size:12px">${esc(w.metric)}</td><td><b style="color:#f87171">${w.impact}</b></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ir.workEmpty")}</div>`);

  const checklist = `<div class="sec">${t("ir.secChecklist")}</div>
    <table class="t"><thead><tr><th>${t("ir.thControl")}</th><th>${t("ir.thCategory")}</th><th>${t("ir.thStatus")}</th><th>${t("ir.thScore")}</th><th>${t("ir.thEvidence")}</th><th>${t("ir.thWt")}</th></tr></thead><tbody>${d.controls.map(ctlRow).join("")}</tbody></table>`;

  const attest = `<div class="sec">${t("ir.secAttest")}</div>
    <table class="t"><thead><tr><th>${t("ir.thControl")}</th><th>${t("ir.thCategory")}</th><th>${t("ir.thWhyAsks")}</th></tr></thead><tbody>${d.attest.map((c) => `<tr><td><span class="nm">${esc(c.name)}</span></td><td>${esc(c.category)}</td><td class="muted" style="font-size:12px">${esc(c.insurerWhy)}</td></tr>`).join("")}</tbody></table>`;

  body.innerHTML = hero + polPanel(d) + cards + work + checklist + attest;
  $("pol-edit")?.addEventListener("click", openModal);
}

function openModal(): void {
  const p = DATA?.program.policy;
  const set = (id: string, v: string | number) => { const el = $(id) as HTMLInputElement | null; if (el) el.value = String(v ?? ""); };
  set("pc-carrier", p?.carrier ?? ""); set("pc-policynum", p?.policyNumber ?? "");
  set("pc-limit", p?.coverageLimit || ""); set("pc-retention", p?.retention || ""); set("pc-premium", p?.premium || "");
  set("pc-currency", p?.currency ?? "USD"); set("pc-renewal", p?.renewalDate ?? "");
  const st = $("pc-status") as HTMLSelectElement | null; if (st) st.value = p?.status ?? "Active";
  set("pc-notes", p?.notes ?? "");
  const e = $("pc-err"); if (e) e.textContent = "";
  $("pol-modal")?.classList.add("open");
}
function closeModal(): void { $("pol-modal")?.classList.remove("open"); }

async function savePolicy(): Promise<void> {
  const v = (id: string): string => ($(id) as HTMLInputElement | HTMLSelectElement)?.value || "";
  const body = {
    carrier: v("pc-carrier").trim(), policyNumber: v("pc-policynum").trim(),
    coverageLimit: Number(v("pc-limit")) || 0, retention: Number(v("pc-retention")) || 0, premium: Number(v("pc-premium")) || 0,
    currency: v("pc-currency").trim() || "USD", renewalDate: v("pc-renewal"), status: v("pc-status"), notes: v("pc-notes").trim(),
  };
  try {
    const r = await fetch("/api/insurance-readiness/policy", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    closeModal(); render(d); toast(t("ir.policySaved"));
  } catch (e) { const el = $("pc-err"); if (el) el.textContent = `⚠️ ${(e as Error).message}`; }
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/insurance-readiness"); const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); render(d); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("pc-save")?.addEventListener("click", () => void savePolicy());
  $("pc-cancel")?.addEventListener("click", closeModal);
  $("pol-modal")?.addEventListener("click", (e) => { if (e.target === $("pol-modal")) closeModal(); });
  document.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Escape") closeModal(); });
  void load();
});
