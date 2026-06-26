/**
 * adversary-opportunity.ts — client for the Adversary Opportunity Index (AOI), XORCISM's renamed
 * "threat debt" top-line. Renders the index gauge + STOCK/FLOW, the 7 sources of debt, the
 * choke-point "price the fix" worklist, the top attack paths and the AOI history sparkline.
 */
import { initI18n, t } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Source { key: string; label: string; items: number; status: "live" | "tracked"; note: string }
interface Fix { label: string; paths: number; deltaEst: number; rationale: string }
interface Path { entry: string; jewel: string; hops: number; debt: number; cost: number }
interface Data {
  index: number; rawDebt: number; pathData: boolean;
  paths: { found: number; jewels: number; entries: number };
  factors: { tidScore: number; defenceResidual: number; assuranceCredit: number };
  bySource: Source[]; worklist: Fix[]; topPaths: Path[];
  sourceFixes: { source: string; label: string; items: number; debt: number }[];
  topItems: { source: string; label: string; debt: number }[];
  flow: { previous: number | null; net: number | null; since: string | null; accrued: number; paidDown: number; openItems: number };
  history: { date: string; aoi: number }[]; canAct: boolean;
}

function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
async function getJson(url: string, opts?: RequestInit): Promise<any> {
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
const band = (i: number): string => i >= 600 ? "#f87171" : i >= 300 ? "#fbbf24" : "#34d399";

function sparkline(hist: { date: string; aoi: number }[]): string {
  if (hist.length < 2) return `<span class="muted" style="font-size:11px">${t("ao.historyBuilds")}</span>`;
  const w = 220, h = 40, xs = hist.map((_, i) => i / (hist.length - 1) * w);
  const vals = hist.map((p) => p.aoi), mn = Math.min(...vals), mx = Math.max(...vals, mn + 1);
  const ys = vals.map((v) => h - ((v - mn) / (mx - mn)) * (h - 6) - 3);
  const pts = xs.map((x, i) => `${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline fill="none" stroke="#8b5cf6" stroke-width="2" points="${pts}"/></svg>`;
}

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const f = d.flow;
  const move = f.net == null ? `<span class="flat2">${t("ao.baseline")}</span>`
    : f.net < 0 ? `<span class="dn">▼ ${Math.abs(f.net)}</span> ${fmt("ao.since", { d: esc(f.since) })}`
    : f.net > 0 ? `<span class="up">▲ ${f.net}</span> ${fmt("ao.since", { d: esc(f.since) })}`
    : `<span class="flat2">${fmt("ao.unchanged", { d: esc(f.since) })}</span>`;
  // item-level ledger split (Phase 2): exact debt paid down vs accrued this period
  const split = (f.paidDown || f.accrued)
    ? ` · <span class="dn">${fmt("ao.paidDown", { n: f.paidDown })}</span> / <span class="up">${fmt("ao.accrued", { n: f.accrued })}</span>`
    : "";
  const flowHtml = `${move}${split}`;

  const hero = `<div class="hero">
    <div class="gauge"><div class="n" style="color:${band(d.index)}">${d.index}</div><div class="d">${t("ao.outOf1000")}</div>
      <div class="flow">${flowHtml}</div>${!d.pathData ? `<div class="muted" style="font-size:11px;margin-top:6px">${t("ao.noPathData")}</div>` : ""}</div>
    <div>
      <div style="display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end">
        <div><div class="muted" style="font-size:11px;text-transform:uppercase">${t("ao.trend")}</div>${sparkline(d.history)}</div>
        <div style="flex:1"></div>
        <div class="pill">${fmt("ao.pillDefence", { n: Math.round(d.factors.defenceResidual * 100) })}</div>
        <div class="pill">${fmt("ao.pillTid", { n: d.factors.tidScore })}</div>
        <div class="pill">${fmt("ao.pillControl", { n: Math.round(d.factors.assuranceCredit * 100) })}</div>
      </div>
      <div class="muted" style="font-size:12px;margin-top:10px;line-height:1.5">${fmt("ao.heroSummary", { found: d.paths.found, jewels: d.paths.jewels, entries: d.paths.entries, raw: d.rawDebt })}</div>
    </div></div>`;

  const cards = `<div class="cards">${[
    card(t("ao.card.aoi"), d.index, t("ao.card.aoi.f"), band(d.index)),
    card(t("ao.card.net"), f.net == null ? "—" : `${f.net <= 0 ? "" : "+"}${f.net}`, t("ao.card.net.f"), f.net == null ? undefined : f.net < 0 ? "#34d399" : f.net > 0 ? "#f87171" : undefined),
    card(t("ao.card.openItems"), f.openItems, t("ao.card.openItems.f")),
    card(t("ao.card.paths"), d.paths.found, fmt("ao.card.paths.f", { n: d.paths.jewels }), d.paths.found ? "#fbbf24" : "#34d399"),
    card(t("ao.card.defence"), `${Math.round(d.factors.defenceResidual * 100)}%`, t("ao.card.defence.f"), d.factors.defenceResidual >= 0.6 ? "#f87171" : d.factors.defenceResidual >= 0.3 ? "#fbbf24" : "#34d399"),
    card(t("ao.card.topFix"), d.worklist[0] ? `−${d.worklist[0].deltaEst}` : "—", d.worklist[0] ? fmt("ao.card.topFix.f", { label: d.worklist[0].label }) : t("ao.card.topFix.none")),
  ].join("")}</div>`;

  const src = `<div class="sec">${t("ao.sec.sources")}</div><div class="src">${d.bySource.map((s) => `
    <div class="srcc"><div class="h">${esc(s.label)} <span class="tag tag-${s.status}">${t("ao.status." + s.status)}</span><span class="n">${s.items}</span></div>
      <div class="x">${esc(s.note)}</div></div>`).join("")}</div>`;

  const work = `<div class="sec">${t("ao.sec.priceFix")}</div>` + (d.worklist.length
    ? `<table class="t"><thead><tr><th>${t("ao.th.harden")}</th><th>${t("ao.th.severed")}</th><th>${t("ao.th.paydown")}</th><th>${t("ao.th.why")}</th></tr></thead><tbody>${d.worklist.map((w) => `<tr><td><span class="nm">${esc(w.label)}</span></td><td>${w.paths}</td><td><span class="delta">−${w.deltaEst}</span></td><td class="muted" style="font-size:12px">${esc(w.rationale)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ao.empty.choke")}</div>`);

  const sfix = `<div class="sec">${t("ao.sec.bySource")}</div>` + (d.sourceFixes.length
    ? `<table class="t"><thead><tr><th>${t("ao.th.source")}</th><th>${t("ao.th.openItems")}</th><th>${t("ao.th.debtRetired")}</th></tr></thead><tbody>${d.sourceFixes.map((s) => `<tr><td><span class="nm">${esc(s.label)}</span></td><td>${s.items}</td><td><span class="delta">−${s.debt}</span></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ao.empty.ledger")}</div>`);

  const items = d.topItems.length
    ? `<div class="sec">${t("ao.sec.byFinding")}</div><table class="t"><thead><tr><th>${t("ao.th.finding")}</th><th>${t("ao.th.source")}</th><th>${t("ao.th.debtRetired2")}</th></tr></thead><tbody>${d.topItems.map((it) => `<tr><td><span class="nm">${esc(it.label)}</span></td><td class="muted">${esc(it.source)}</td><td><span class="delta">−${it.debt}</span></td></tr>`).join("")}</tbody></table>`
    : "";

  const paths = `<div class="sec">${t("ao.sec.topPaths")}</div>` + (d.topPaths.length
    ? `<table class="t"><thead><tr><th>${t("ao.th.foothold")}</th><th></th><th>${t("ao.th.crownJewel")}</th><th>${t("ao.th.hops")}</th><th>${t("ao.th.pathDebt")}</th></tr></thead><tbody>${d.topPaths.map((p) => `<tr><td>${esc(p.entry)}</td><td class="muted">→</td><td><span class="nm">${esc(p.jewel)}</span></td><td>${p.hops}</td><td><b>${p.debt}</b></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">${t("ao.empty.paths")}</div>`);

  body.innerHTML = hero + cards + src + work + sfix + items + paths;
  const snap = $("snap") as HTMLButtonElement | null;
  if (snap && !d.canAct) { snap.disabled = true; snap.style.opacity = "0.5"; }
}

async function load(): Promise<void> {
  try { render(await getJson("/api/threat-debt")); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
async function snapshot(): Promise<void> {
  try { render(await getJson("/api/threat-debt/snapshot", { method: "POST" })); toast(t("ao.snapDone")); }
  catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("snap")?.addEventListener("click", () => void snapshot());
  void load();
});
