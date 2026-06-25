/**
 * cyber-risk-hunting.ts — client for /cyber-risk-hunting.
 * A worklist of "where could an adversary succeed?": fused exposures + over-scoped non-human
 * identities, each with a hunt hypothesis, plus an "Escalate into the loop" action that re-enters
 * the CROC Continuous Defense Loop so the pre-authorization policies fire on the finding.
 */
import { initI18n, t } from "./i18n";

const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const gaugeColor = (n: number): string => n >= 70 ? "#b91c1c" : n >= 40 ? "#ca8a04" : "#3b82f6";

async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 2600); }

let data: any = null;
let hotOnly = false;

/** Hunt hypothesis for a fused exposure, assembled client-side from raw bits (i18n). */
function exposureHypothesis(e: any): string {
  let h = e.hot ? fmt("crh.hypHot", { n: e.assets || 0, ref: esc(e.ref) }) : fmt("crh.hypCold", { n: e.assets || 0, ref: esc(e.ref) });
  if (e.reach === "entry") h += fmt("crh.hypEntry", { label: esc(e.reachLabel) });
  else if (e.reach === "jewel") h += fmt("crh.hypJewel", { label: esc(e.reachLabel) });
  else if (e.reach === "choke") h += fmt("crh.hypChoke", { label: esc(e.reachLabel), n: e.reachChoke || 0 });
  else if (e.reach) h += fmt("crh.hypPath", { label: esc(e.reachLabel) });
  return h;
}

function tags(e: any): string {
  const exp = e.exploits ? `<span class="tag t-exp">${fmt(e.exploits === 1 ? "crh.tagExploit" : "crh.tagExploits", { n: e.exploits })}</span>` : "";
  const t1 = (e.kev ? `<span class="tag t-kev">KEV</span>` : "") + (e.itw ? `<span class="tag t-itw">ITW</span>` : "") + exp;
  const reach: Record<string, string> = {
    entry: `<span class="tag t-reach" style="background:#7f1d1d;color:#fecaca">${t("crh.reachEntry")}</span>`,
    jewel: `<span class="tag t-reach" style="background:#78350f;color:#fcd34d">${t("crh.reachJewel")}</span>`,
    choke: `<span class="tag t-reach" style="background:#3b2f63;color:#ddd6fe">${t("crh.reachChoke")}</span>`,
    onpath: `<span class="tag t-reach" style="background:#1e3a5f;color:#bfdbfe">${t("crh.reachOnpath")}</span>` };
  return t1 + (e.reach ? reach[e.reach] || "" : "");
}

/** The exposure reference — clickable to the ASSETVULNERABILITY rows for that CVE when we know its id. */
function refCell(e: any): string {
  if (e.vid) return `<a class="mono" href="/?db=XORCISM&table=ASSETVULNERABILITY&filterCol=VulnerabilityID&filterVal=${esc(e.vid)}" title="${t("crh.editAv")}">${esc(e.ref)}</a>`;
  return `<span class="mono">${esc(e.ref)}</span>`;
}

function render(d: any): string {
  const s = d.summary || {};
  let exposures = (d.exposures || []) as any[];
  const agentic = (d.agentic || []) as any[];
  const attackPaths = (d.attackPaths || []) as any[];
  const chokepoints = (d.chokepoints || []) as any[];
  if (hotOnly) exposures = exposures.filter((e) => e.hot);
  return `
  <div class="cards">
    <div class="card"><div class="lbl">${t("crh.cActivelyAttacked")}</div><div class="val" style="color:#f87171">${s.activelyAttacked || 0}</div><div class="foot">${t("crh.cActivelyAttacked.foot")}</div></div>
    <div class="card"><div class="lbl">${t("crh.cCrownReachable")}</div><div class="val" style="color:#fbbf24">${s.crownReachable || 0}</div><div class="foot">${t("crh.cCrownReachable.foot")}</div></div>
    <div class="card"><div class="lbl">${t("crh.cReachableJewels")}</div><div class="val" style="color:#fb7185">${s.reachableJewels || 0}</div><div class="foot">${fmt("crh.cReachableJewels.foot", { n: s.attackPaths || 0 })}</div></div>
    <div class="card"><div class="lbl">${t("crh.cOnPath")}</div><div class="val" style="color:#f472b6">${s.onAttackPath || 0}</div><div class="foot">${t("crh.cOnPath.foot")}</div></div>
    <div class="card"><div class="lbl">${t("crh.cOverScoped")}</div><div class="val" style="color:#c4b5fd">${s.overScopedIdentities || 0}</div><div class="foot">${t("crh.cOverScoped.foot")}</div></div>
  </div>
  <div class="sec">${t("crh.secWorklist")} <span class="spacer"></span><label class="filters"><input type="checkbox" id="hot" ${hotOnly ? "checked" : ""}> ${t("crh.filterHot")}</label></div>
  <table class="t"><thead><tr><th>${t("crh.thPriority")}</th><th>${t("crh.thExposure")}</th><th>${t("crh.thHypothesis")}</th><th>${t("crh.thAssets")}</th><th></th></tr></thead><tbody>
    ${exposures.map((e) => `<tr><td><span class="gauge" style="background:${gaugeColor(e.priority)}">${e.priority}</span></td><td>${refCell(e)}<div style="margin-top:3px">${tags(e)}</div><div class="why">${esc((e.factors || []).slice(0, 3).join(" · "))}</div></td><td class="hyp">${exposureHypothesis(e)}</td><td>${e.assets || 0}</td><td><button class="btn-sm2 esc" data-kind="exposure" data-ref="${esc(e.ref)}" data-pri="${e.priority}">${t("crh.escalate")}</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">${hotOnly ? t("crh.noExposuresFilter") : t("crh.noExposures")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("crh.secOverScoped")}</div>
  <table class="t"><thead><tr><th>${t("crh.thIdentity")}</th><th>${t("crh.thWhyRisk")}</th><th>${t("crh.thHypothesis")}</th><th></th></tr></thead><tbody>
    ${agentic.map((a) => `<tr><td><span class="nm">${esc(a.name)}</span><div class="muted" style="font-size:11px">${esc(a.privilege || a.type || "")}</div></td><td><span class="why">${esc((a.why || []).join(" · "))}</span></td><td class="hyp">${fmt("crh.hypAgentic", { type: esc(a.type || t("crh.nhiFallback")), name: esc(a.name) })}</td><td><button class="btn-sm2 esc" data-kind="identity" data-ref="${esc(a.name)}" data-pri="80">${t("crh.constrain")}</button></td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("crh.noAgentic")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("crh.secAttackPaths")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${t("crh.attackPathsHint")}</span></div>
  <table class="t"><thead><tr><th>${t("crh.thEntry")}</th><th></th><th>${t("crh.thCrownJewel")}</th><th>${t("crh.thHops")}</th><th>${t("crh.thCost")}</th></tr></thead><tbody>
    ${attackPaths.map((p) => `<tr><td class="nm">${esc(p.entry)}</td><td class="muted">→</td><td><span class="nm" style="color:#fbbf24">${esc(p.jewel)}</span></td><td>${p.hops}</td><td class="muted">${p.cost}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${t("crh.noPaths")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("crh.secChokepoints")}</div>
  <table class="t"><thead><tr><th>${t("crh.thAsset")}</th><th>${t("crh.thOnPaths")}</th><th>${t("crh.thHypothesis")}</th><th></th></tr></thead><tbody>
    ${chokepoints.map((c) => `<tr><td class="nm">${esc(c.label)}</td><td><span class="gauge" style="width:30px;height:30px;font-size:12px;background:#7f1d1d">${c.paths}</span></td><td class="hyp">${fmt("crh.hypChokepoint", { label: esc(c.label), n: c.paths })}</td><td><button class="btn-sm2 esc" data-kind="exposure" data-ref="choke point: ${esc(c.label)}" data-pri="75">${t("crh.escalate")}</button></td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("crh.noChokepoints")}</td></tr>`}
  </tbody></table>`;
}

function wire(): void {
  $("hot")?.addEventListener("change", (e) => { hotOnly = (e.target as HTMLInputElement).checked; draw(); });
  document.querySelectorAll<HTMLButtonElement>(".esc").forEach((b) => {
    b.addEventListener("click", async () => {
      const kind = b.dataset.kind, ref = b.dataset.ref, priority = Number(b.dataset.pri) || 0;
      b.disabled = true;
      try {
        const r = await (await fetch("/api/cyber-risk-hunting/escalate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, ref, priority }) })).json();
        toast(r.ok ? (kind === "identity" ? t("crh.escalatedConstrain") : t("crh.escalatedExposure")) : t("crh.failed"));
        b.textContent = t("crh.escalated");
      } catch { toast(t("crh.failed")); b.disabled = false; }
    });
  });
}

function draw(): void { const body = $("body"); if (body && data) { body.innerHTML = render(data); wire(); } }

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { data = await getJson("/api/cyber-risk-hunting"); draw(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("crh.loadFailed", { e: esc((e as Error).message) })}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
