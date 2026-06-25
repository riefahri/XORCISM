/**
 * configuration-management.ts — Configuration Management inventory + governance worklist
 * (/configuration-management). Secure-configuration content library (OVAL hardening
 * baselines) + verification worklist, from /api/configuration-management. Read-only.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));

interface ConfigRow { id: number; pattern: string; title: string; version: string; status: string; deprecated: boolean; hasCce: boolean; platforms: number; score: number; issues: string[]; }
interface Finding { id: number; name: string; kind: "definition" | "library" | "coverage"; severity: "High" | "Medium" | "Low"; reason: string; label: string; }
interface Inventory {
  rows: ConfigRow[]; findings: Finding[];
  summary: { definitions: number; compliance: number; patch: number; vulnerability: number; inventory: number; miscellaneous: number; deprecated: number; accepted: number; interim: number; withCce: number; cceTotal: number; scannedAssets: number; verdicts: number; complianceFail: number; compliancePass: number; passRate: number | null; lastScan: string | null; byClass: Record<string, number>; byStatus: Record<string, number>; };
}

const stClass = (s: string): string => {
  const v = (s || "").toLowerCase();
  return /accepted/.test(v) ? "st-accepted" : /deprecat/.test(v) ? "st-deprecated" : /interim|draft|incomplete/.test(v) ? "st-interim" : "";
};
const scoreClass = (n: number): string => (n >= 30 ? "s-hi" : n >= 10 ? "s-md" : "s-lo");
const dotColor = (k: string): string => (k === "coverage" ? "#38bdf8" : k === "library" ? "#c084fc" : "#fb923c");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="cf-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: ConfigRow): string {
  const issues = r.issues.length
    ? r.issues.map((i) => `<span class="tag${/no cce|status/.test(i.toLowerCase()) ? " tag-w" : ""}">${esc(i)}</span>`).join("")
    : `<span class="ok">${t("config.rowOk")}</span>`;
  return `<tr>
    <td><div class="cname">${esc(r.title)}</div>${r.pattern ? `<div class="muted" style="font-size:11px"><span class="ref">${esc(r.pattern)}</span></div>` : ""}</td>
    <td><span class="st ${stClass(r.status)}">${esc(r.status)}</span></td>
    <td>${esc(r.version)}</td>
    <td>${r.hasCce ? '<span class="ok">CCE ✓</span>' : '<span class="muted">—</span>'}</td>
    <td>${r.platforms || '<span class="muted">0</span>'}</td>
    <td>${issues}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  const href = f.kind === "coverage" ? "/oval-scan" : "/?db=XOVAL&table=OVALDEFINITION";
  return `<li><span class="dot" style="background:${dotColor(f.kind)}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> ·
    <a href="${href}">${esc(t("config.kind." + f.kind))}</a> — ${esc(f.label)}</li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/configuration-management"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!s.definitions) {
    $("cf-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("config.empty")}</div>`;
    return;
  }

  const cards = [
    card(t("config.card.baselines"), String(s.compliance), t("config.card.baselines.foot"), s.compliance ? undefined : "#64748b"),
    card(t("config.card.verified"), s.verdicts ? `${s.scannedAssets}` : "0", s.verdicts ? fmt("config.card.verified.foot", { n: s.scannedAssets }) : t("config.card.verified.none"), s.verdicts ? "#34d399" : "#fbbf24"),
    card(t("config.card.pass"), s.passRate != null ? `${s.passRate}%` : "—", s.verdicts ? fmt("config.card.pass.foot", { n: s.complianceFail }) : t("config.card.pass.none"), s.passRate != null ? (s.passRate >= 80 ? "#34d399" : s.passRate >= 50 ? "#fbbf24" : "#f87171") : undefined),
    card(t("config.card.deprecated"), String(s.deprecated), t("config.card.deprecated.foot"), s.deprecated ? "#fb923c" : "#34d399"),
    card(t("config.card.cce"), String(s.withCce), fmt("config.card.cce.foot", { n: s.definitions }), s.withCce ? "#34d399" : undefined),
    card(t("config.card.library"), String(s.definitions), t("config.card.library.foot")),
    card(t("config.card.patchvuln"), `${s.patch} / ${s.vulnerability}`, t("config.card.patchvuln.foot")),
    card(t("config.card.inventory"), String(s.inventory), t("config.card.inventory.foot")),
  ].join("");

  const byClass = Object.entries(s.byClass).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const byStatus = Object.entries(s.byStatus).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="bd"><span class="st ${stClass(k)}">${esc(k)}</span> <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("config.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("config.noFindings")}</div>`;

  const table = d.rows.length ? `<div class="cf-section">${fmt("config.sec.baselines", { n: d.rows.length })}</div>
    <table class="cf"><thead><tr>
      <th>${t("config.th.baseline")}</th><th>${t("config.th.status")}</th><th>${t("config.th.ver")}</th><th>${t("config.th.cce")}</th><th>${t("config.th.platforms")}</th><th>${t("config.th.gaps")}</th><th title="${t("config.th.score.title")}">${t("config.th.score")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>` : "";

  $("cf-body").innerHTML = `<div class="cf-cards">${cards}</div>
    <div class="cf-section">${fmt("config.sec.worklist", { n: d.findings.length })}</div>${findings}
    <div class="cf-section">${t("config.sec.byClass")}</div><div class="breakdown">${byClass}</div>
    <div class="cf-section">${t("config.sec.byStatus")}</div><div class="breakdown">${byStatus}</div>
    ${table}
    <div class="cf-section">${t("config.sec.cis")}</div><div id="cf-cis"><div class="muted">${t("config.cis.loading")}</div></div>
    <div class="legend">${t("config.legend")}</div>`;
  void loadCis();
}

// ── CIS Benchmarks panel (catalogue + CIS-CAT pass/fail posture) ─────────────────
async function loadCis(): Promise<void> {
  const host = document.getElementById("cf-cis"); if (!host) return;
  let d: { benchmarks: Record<string, any>[]; summary: Record<string, any> };
  try { const r = await fetch("/api/configuration/cis-benchmarks"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { host.innerHTML = `<div class="muted">⚠️ ${esc(e)}</div>`; return; }
  if (!d.benchmarks.length) { host.innerHTML = `<div class="muted">${t("config.cis.none")}</div>`; return; }
  const s = d.summary;
  const cats = Object.entries(s.byCategory || {}).map(([k, n]) => `<span class="bd">${esc(k)} <b>${n}</b></span>`).join("");
  const rows = d.benchmarks.map((b) => {
    const pr = b.passRate == null ? `<span class='muted'>${t("config.cis.notScanned")}</span>` : `<b style="color:${b.passRate >= 80 ? "#34d399" : b.passRate >= 50 ? "#fbbf24" : "#f87171"}">${b.passRate}%</b> (${b.pass}/${b.scored})`;
    return `<tr><td>${esc(b.name)}</td><td>${esc(b.version)}</td><td><span class="muted">${esc(b.platform)}</span></td><td>${esc(b.category)}</td><td>${b.recs ?? 0}</td><td>${pr}</td></tr>`;
  }).join("");
  host.innerHTML = `<div class="breakdown" style="margin-bottom:8px">
      <span class="bd">${fmt("config.cis.benchmarks", { n: s.total })}</span><span class="bd">${fmt("config.cis.recommendations", { n: s.recommendations })}</span>
      <span class="bd">${fmt("config.cis.scanned", { n: s.scanned })}</span>${s.passRate != null ? `<span class="bd">${fmt("config.cis.passrate", { n: s.passRate })}</span>` : ""}${cats}</div>
    <table class="cf"><thead><tr><th>${t("config.cis.th.benchmark")}</th><th>${t("config.cis.th.version")}</th><th>${t("config.cis.th.platform")}</th><th>${t("config.cis.th.category")}</th><th>${t("config.cis.th.recs")}</th><th>${t("config.cis.th.pass")}</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ── Launch an OVAL scan on an enrolled agent (localhost or remote) ───────────────
interface Target { name: string; asset: string | null; os: string | null; platform: string | null; lastSeen: string | null; online: boolean; isLocal: boolean; }

async function initLaunch(): Promise<void> {
  const sel = document.getElementById("cf-target") as HTMLSelectElement | null;
  const kindSel = document.getElementById("cf-kind") as HTMLSelectElement | null;
  const btn = document.getElementById("cf-launch-btn") as HTMLButtonElement | null;
  const stat = document.getElementById("cf-launch-stat");
  if (!sel || !kindSel || !btn || !stat) return;

  interface Sched { id: number; agent: string; ovalClass: string; cron: string; lastRun: string | null }
  let data: { localhost: string; agents: Target[]; scheduled?: Sched[] };
  try { const r = await fetch("/api/configuration/scan-targets"); if (!r.ok) throw new Error(`HTTP ${r.status}`); data = await r.json(); }
  catch (e) { sel.innerHTML = `<option value="">—</option>`; btn.disabled = true; stat.innerHTML = `⚠️ ${esc(e)}`; return; }

  const recurSel = document.getElementById("cf-recur") as HTMLSelectElement | null;
  const schedList = document.getElementById("cf-sched-list");
  const renderSchedules = (list: Sched[]) => {
    if (!schedList) return;
    schedList.innerHTML = list.length
      ? `${t("config.launch.recurringLabel")} ${list.map((s) => `${esc(s.agent)} · ${esc(s.ovalClass)} · <code>${esc(s.cron)}</code>${s.lastRun ? ` ${fmt("config.launch.lastRun", { t: esc(String(s.lastRun).slice(0, 16)) })}` : ""} <a href="/?db=XJOB&table=XSCHEDULE&filterCol=ScheduleID&filterVal=${esc(s.id)}" title="${t("config.launch.manage")}">#${esc(s.id)}</a>`).join(" &nbsp;·&nbsp; ")}`
      : "";
  };
  renderSchedules(data.scheduled || []);

  if (!data.agents.length) {
    sel.innerHTML = `<option value="">${t("config.launch.noAgentOpt")}</option>`;
    btn.disabled = true;
    stat.innerHTML = t("config.launch.noAgents");
    return;
  }

  sel.innerHTML = data.agents.map((a) => {
    const tag = a.isLocal ? " — localhost" : "";
    const status = a.online ? t("config.launch.online") : t("config.launch.offline");
    return `<option value="${esc(a.name)}">${esc(a.name)}${tag} · ${esc(a.os || "?")} · ${status}</option>`;
  }).join("");
  const local = data.agents.find((a) => a.isLocal);
  if (local) sel.value = local.name;

  // OVAL-class sub-select only applies to OVAL scans
  const classFld = document.getElementById("cf-class-fld");
  const classSel = document.getElementById("cf-class") as HTMLSelectElement | null;
  const syncClass = () => { if (classFld) classFld.style.display = kindSel.value === "oval" ? "" : "none"; };
  kindSel.onchange = syncClass;
  syncClass();

  // button label tracks the recurrence (Launch now vs Schedule)
  const syncBtn = () => { btn.textContent = recurSel && recurSel.value !== "once" ? t("config.launch.schedule") : t("config.launch.go"); };
  if (recurSel) { recurSel.onchange = syncBtn; syncBtn(); }

  btn.onclick = async () => {
    const agent = sel.value, kind = kindSel.value;
    if (!agent) return;
    const ovalClass = kind === "oval" && classSel ? classSel.value : "all";
    const recur = recurSel ? recurSel.value : "once";
    btn.disabled = true;
    try {
      if (recur !== "once") {
        // recurring → schedule it (XSCHEDULE). OVAL class only meaningful for OVAL scans.
        stat.textContent = t("config.launch.scheduling");
        const r = await fetch("/api/configuration/schedule-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, ovalClass, preset: recur }) });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
        const isLocal = data.agents.find((a) => a.name === agent)?.isLocal;
        stat.innerHTML = fmt("config.launch.scheduledMsg", { recur: esc(recur), cls: esc(ovalClass), agent: esc(agent) + (isLocal ? " (localhost)" : ""), id: esc(d.scheduleId), cron: esc(d.cron) });
        renderSchedules([...(data.scheduled || []), { id: d.scheduleId, agent, ovalClass, cron: d.cron, lastRun: null }]);
        return;
      }
      stat.textContent = t("config.launch.launching");
      const r = await fetch("/api/agent-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, kind, ovalClass }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      const isLocal = data.agents.find((a) => a.name === agent)?.isLocal;
      const clsTxt = d.ovalClass ? ` (${esc(d.ovalClass)})` : "";
      stat.innerHTML = fmt("config.launch.queuedMsg", { kind: esc(kind), cls: clsTxt, agent: esc(agent) + (isLocal ? " (localhost)" : ""), job: esc(d.jobId) });
    } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
    finally { btn.disabled = false; }
  };
}

// ── Deploy/enforce a compliance policy across the agent fleet ────────────────────
interface FleetAgent { name: string; os: string | null; online: boolean; lastSeen: string | null; }
async function initDeploy(): Promise<void> {
  const stat = document.getElementById("cf-dep-stat");
  const btn = document.getElementById("cf-dep-btn") as HTMLButtonElement | null;
  const scopeSel = document.getElementById("cf-dep-scope") as HTMLSelectElement | null;
  const pickFld = document.getElementById("cf-dep-pick-fld");
  const pick = document.getElementById("cf-dep-pick");
  const classSel = document.getElementById("cf-dep-class") as HTMLSelectElement | null;
  const recurSel = document.getElementById("cf-dep-recur") as HTMLSelectElement | null;
  if (!stat || !btn || !scopeSel || !pickFld || !pick || !classSel || !recurSel) return;

  let fleet: { agents: FleetAgent[]; online: number; total: number; baselines: { name: string; size: number }[]; results: { pass: number; fail: number; assets: number; passRate: number | null } | null };
  try { const r = await fetch("/api/configuration/fleet-compliance"); if (!r.ok) throw new Error(`HTTP ${r.status}`); fleet = await r.json(); }
  catch (e) { btn.disabled = true; stat.innerHTML = `⚠️ ${esc(e)}`; return; }

  if (!fleet.total) {
    btn.disabled = true;
    stat.innerHTML = t("config.deploy.noAgents");
    return;
  }
  // checkbox list of agents for the "Selected agents" scope
  pick.innerHTML = fleet.agents.map((a) =>
    `<label class="cf-dep-ag"><input type="checkbox" value="${esc(a.name)}"${a.online ? " checked" : ""}> ${a.online ? "🟢" : "⚪"} ${esc(a.name)} <span class="muted">· ${esc(a.os || "?")}</span></label>`).join("");
  scopeSel.onchange = () => { pickFld.style.display = scopeSel.value === "select" ? "" : "none"; };

  const baselineNote = fleet.baselines.length
    ? fmt("config.deploy.baselineNote", { n: fleet.baselines.length })
    : t("config.deploy.noBaseline");
  const resNote = fleet.results && (fleet.results.pass + fleet.results.fail)
    ? fmt("config.deploy.lastPosture", { r: fleet.results.passRate ?? "?", p: fleet.results.pass, f: fleet.results.fail, a: fleet.results.assets })
    : "";
  stat.innerHTML = `${fmt("config.deploy.fleetLine", { on: fleet.online, tot: fleet.total })}${baselineNote}${resNote}`;

  btn.onclick = async () => {
    const ovalClass = classSel.value;
    const recur = recurSel.value;
    let agents: string[] | undefined;
    if (scopeSel.value === "select") {
      agents = [...pick.querySelectorAll<HTMLInputElement>("input:checked")].map((c) => c.value);
      if (!agents.length) { stat.innerHTML = t("config.deploy.selectOne"); return; }
    }
    btn.disabled = true; stat.textContent = t("config.deploy.deploying");
    try {
      const body: Record<string, unknown> = { ovalClass };
      if (agents) body.agents = agents;
      if (recur !== "once") body.preset = recur;
      const r = await fetch("/api/configuration/deploy-compliance", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      const enforceTxt = d.preset ? fmt("config.deploy.scheduledSuffix", { p: esc(d.preset), n: esc(String(d.scheduleIds?.length || 0)) }) : "";
      stat.innerHTML = fmt("config.deploy.deployedMsg", { cls: esc(ovalClass), n: esc(String(d.deployed)), jobs: esc(String(d.jobIds.length)) }) + enforceTxt + t("config.deploy.deployedTail");
    } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
    finally { btn.disabled = false; }
  };
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); void initLaunch(); void initDeploy(); });
