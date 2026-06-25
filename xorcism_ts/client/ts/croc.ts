/**
 * croc.ts — client for the CROC Continuous Defense Loop cockpit (/croc).
 * Renders the loop pulse (events / machine-speed % / latency / health), the ∞ bidirectional flow,
 * the risk-weighted SOC alert queue (CROC→SOC), the cyber-risk-hunting worklist + over-scoped NHI,
 * the pre-authorization policies, and the live loop-event feed.
 */
import { initI18n, t } from "./i18n";
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), t(key));
const sevClass = (s: string): string => "sv-" + String(s || "info").toLowerCase();
const dirClass = (d: string): string => d === "croc->soc" ? "dir-croc" : d === "soc->croc" ? "dir-soc" : "dir-internal";
const dirLabel = (d: string): string => d === "croc->soc" ? "CROC→SOC" : d === "soc->croc" ? "SOC→CROC" : t("cr.internal");
const gaugeColor = (n: number): string => n >= 70 ? "#16a34a" : n >= 40 ? "#ca8a04" : "#b91c1c";

async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }

/** A tiny inline SVG sparkline from a numeric series (last value highlighted); optional SLA target line. */
function spark(series: any[], key: string, color: string, label: string, suffix = "", target?: number, dir?: "min" | "max"): string {
  const vals = series.map((s) => Number(s[key]) || 0);
  const w = 240, h = 44, pad = 3;
  const last = vals.length ? vals[vals.length - 1] : 0;
  const breach = target != null && vals.length ? (dir === "min" ? last < target : last > target) : false;
  let path = "", slaLine = "";
  if (vals.length >= 2) {
    const max = Math.max(...vals, target ?? 1, 1), min = Math.min(...vals, dir === "min" ? (target ?? 0) : 0, 0);
    const span = max - min || 1;
    const y = (v: number): number => h - pad - ((v - min) / span) * (h - 2 * pad);
    path = vals.map((v, i) => `${i === 0 ? "M" : "L"}${(pad + (i / (vals.length - 1)) * (w - 2 * pad)).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    if (target != null) slaLine = `<line x1="0" y1="${y(target).toFixed(1)}" x2="${w}" y2="${y(target).toFixed(1)}" stroke="#64748b" stroke-width="1" stroke-dasharray="3 3"/>`;
  }
  const body = vals.length >= 2
    ? `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:44px">${slaLine}<path d="${path}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/></svg>`
    : `<div class="muted" style="font-size:11px;padding:12px 0">${t("cr.notEnoughHistory")}</div>`;
  const sla = target != null ? `<span class="muted" style="font-size:10px;margin-left:6px">SLA ${dir === "min" ? "≥" : "≤"}${target}${suffix}${breach ? " · " + t("cr.breach") : ""}</span>` : "";
  return `<div class="panel" style="padding:10px 12px"><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">${esc(label)}</div><div style="font-size:20px;font-weight:700;color:${breach ? "#ef4444" : color}">${last}${suffix}${sla}</div>${body}</div>`;
}
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

let isAdmin = false;
let lastReasoning = ""; // persists the AI read across the 30s auto-refresh

/** Minimal Markdown → HTML for the AI reasoning panel (headings / bold / italic / bullets). */
function mdLite(md: string): string {
  const e = (s: string): string => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c] as string));
  return String(md || "").split("\n").map((ln) => {
    const t = e(ln).replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/_([^_]+)_/g, "<i>$1</i>");
    if (/^###\s+/.test(ln)) return `<div class="ai-h3">${t.replace(/^###\s+/, "")}</div>`;
    if (/^##\s+/.test(ln)) return `<div class="ai-h2">${t.replace(/^##\s+/, "")}</div>`;
    if (/^[-*]\s+/.test(ln)) return `<div class="ai-li">${t.replace(/^[-*]\s+/, "")}</div>`;
    if (ln.trim() === "") return `<div style="height:6px"></div>`;
    return `<div>${t}</div>`;
  }).join("");
}

function render(d: any): string {
  const s = d.summary || {};
  const hClass = s.loopHealth === "moving" ? "h-moving" : s.loopHealth === "still" ? "h-still" : "h-one";
  const hLabel = s.loopHealth === "moving" ? t("cr.hMoving") : s.loopHealth === "still" ? t("cr.hStill") : t("cr.hOne");
  const rwa = (d.riskWeightedAlerts || []) as any[];
  const hunting = (d.hunting || []) as any[];
  const agentic = (d.agentic || []) as any[];
  const policies = (d.policies || []) as any[];
  const feed = (d.feed || []) as any[];
  const fb = d.feedback || {};
  const ticketing = d.ticketing || {};
  const tgts = (ticketing.targets || []) as any[];
  const iam = d.iam || {};
  const iamTgts = (iam.targets || []) as any[];
  const soar = d.soar || {};
  const soarHooks = (soar.webhooks || []) as any[];
  const resilience = (d.resilience || []) as any[];
  const sla = d.resilienceSla || { machineSpeedMin: 60, latencyMaxMs: 1000, backlogMax: 25 };
  return `
  <div class="cards">
    <div class="card"><div class="lbl">${t("cr.cEvents")}</div><div class="val">${s.eventsToday || 0}</div><div class="foot">${fmt("cr.cEventsFoot", { n: s.lastHour || 0 })}</div></div>
    <div class="card"><div class="lbl">${t("cr.cMachineSpeed")}</div><div class="val" style="color:${gaugeColor(s.machineSpeedPct || 0)}">${s.machineSpeedPct || 0}%</div><div class="foot">${fmt("cr.firedByPolicy", { n: s.autoDecided || 0 })}${s.ticketsOpened ? fmt("cr.ticketsOpened", { n: s.ticketsOpened }) : ""}${s.externalTickets ? fmt("cr.toItsm", { n: s.externalTickets }) : ""}</div></div>
    <div class="card"><div class="lbl">${t("cr.cLatency")}</div><div class="val">${s.medianLatencyMs || 0}<span style="font-size:13px">ms</span></div><div class="foot">${fmt("cr.cLatencyFoot", { n: s.p95LatencyMs || 0 })}</div></div>
    <div class="card"><div class="lbl">${t("cr.cLoopHealth")}</div><div class="val" style="font-size:15px;margin-top:8px"><span class="health ${hClass}"><span class="dot"></span>${s.loopHealth || "?"}</span></div><div class="foot">${esc(hLabel)}</div></div>
  </div>
  <div class="sec">${t("cr.secInfinity")}</div>
  <div class="loop">
    <div class="loopbox"><div class="t">CROC</div><div class="n">${t("cr.crocSub")}</div></div>
    <div style="text-align:center"><div class="arr">${s.crocToSoc || 0} →</div><div class="muted" style="font-size:10px">${t("cr.expToPriority")}</div><div class="arr">← ${s.socToCroc || 0}</div><div class="muted" style="font-size:10px">${t("cr.incToReprioritize")}</div></div>
    <div class="loopbox"><div class="t">SOC</div><div class="n">${t("cr.socSub")}</div></div>
  </div>
  <div class="sec">${t("cr.secAi")} <span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${t("cr.aiSubtitle")}</span><span class="spacer"></span><button class="btn-sm2" id="ai-reason">${t("cr.reasonBtn")}</button></div>
  <div class="panel" id="ai-reason-out">${lastReasoning || `<span class="muted" style="font-size:12px">${t("cr.aiPlaceholder")}</span>`}</div>
  <div class="grid2" style="margin-top:14px">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">${t("cr.rwaTitle")}</div>
      <div class="muted" style="font-size:11px;margin-bottom:6px">${t("cr.rwaSub")}</div>
      <table class="t"><thead><tr><th>${t("cr.thWeight")}</th><th>${t("cr.thSev")}</th><th>${t("cr.thAlert")}</th></tr></thead><tbody>
      ${rwa.map((a) => `<tr><td><span class="gauge" style="width:34px;height:34px;font-size:13px;background:${gaugeColor(a.riskWeight)}">${a.riskWeight}</span></td><td><span class="sev ${sevClass(a.severity)}">${esc(a.severity)}</span></td><td><span class="nm">${esc(a.name)}</span><div class="muted" style="font-size:11px">${esc(a.category || "")}${a.attack ? " · " + esc(a.attack) : ""}</div></td></tr>`).join("") || `<tr><td colspan="3" class="muted">${t("cr.noAlerts")}</td></tr>`}
      </tbody></table>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">${t("cr.fbTitle")}</div>
      <div style="font-size:13px;color:#cbd5e1;margin-bottom:8px">${fmt("cr.fbLine", { m: fb.matchingExposures || 0, t: fb.totalExposures || 0 })}</div>
      <div class="muted" style="font-size:11px">${t("cr.techSeen")}</div>
      <div style="margin-top:5px">${(fb.techniquesSeen || []).map((x: string) => `<span class="mono" style="background:#1e2440;border-radius:5px;padding:1px 7px;margin:2px;display:inline-block">${esc(x)}</span>`).join("") || `<span class='muted'>${t("cr.none")}</span>`}</div>
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin:14px 0 6px">${t("cr.nhiTitle")}</div>
      <table class="t"><tbody>${agentic.map((a) => `<tr><td class="nm">${esc(a.name)}</td><td class="muted" style="font-size:11px">${esc(a.privilege || a.type || "")}</td><td><span class="why">${esc((a.why || []).join(" · "))}</span></td></tr>`).join("") || `<tr><td class="muted">${t("cr.noNhi")}</td></tr>`}</tbody></table>
    </div>
  </div>
  <div class="sec">${t("cr.secHunting")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${t("cr.topFused")}</span></div>
  <table class="t"><thead><tr><th>${t("cr.thPriority")}</th><th>${t("cr.thExposure")}</th><th>${t("cr.thWhy")}</th><th>${t("cr.thAssets")}</th></tr></thead><tbody>
    ${hunting.map((e) => `<tr><td><span class="gauge" style="width:32px;height:32px;font-size:12px;background:${gaugeColor(e.priority)}">${e.priority}</span></td><td class="mono">${esc(e.ref)}</td><td class="muted" style="font-size:11px">${esc((e.factors || []).slice(0, 3).join(" · "))}</td><td>${e.assets || 0}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">${t("cr.noFused")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("cr.secPreauth")} <span class="spacer"></span>${isAdmin ? `<button class="btn-sm2" id="pol-add">${t("cr.addPolicy")}</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">${t("cr.preauthSub")}</div>
  <table class="t"><thead><tr><th>${t("cr.thPolicy")}</th><th>${t("cr.thWhen")}</th><th>${t("cr.thMinSev")}</th><th>${t("cr.thDirection")}</th><th>${t("cr.thAction")}</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${policies.map((p) => `<tr data-pol="${p.id}"><td><span class="nm">${esc(p.name)}</span><div class="muted" style="font-size:11px">${esc(p.description || "")}</div></td><td class="mono">${esc(p.eventFilter)}</td><td><span class="sev ${sevClass(p.minSeverity)}">${esc(p.minSeverity)}</span></td><td><span class="dir ${dirClass(p.direction === "any" ? "internal" : p.direction)}">${p.direction === "any" ? t("cr.any") : dirLabel(p.direction)}</span></td><td><span class="act">${esc(p.action)}</span></td>${isAdmin ? `<td><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="pol-tog" ${p.enabled ? "checked" : ""}> ${t("cr.onLabel")}</label></td>` : ""}</tr>`).join("")}
  </tbody></table>
  <div class="sec">${t("cr.secTicketing")}${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="tkt-add">${t("cr.addDest")}</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">${t("cr.ticketingSub1")} ${ticketing.configured ? t("cr.ticketingConfigured") : t("cr.ticketingNone")}</div>
  <table class="t"><thead><tr><th>${t("cr.thSystem")}</th><th>${t("cr.thDestination")}</th><th>${t("cr.thProjectTable")}</th><th>${t("cr.thMinSev")}</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${tgts.map((x) => `<tr data-tkt="${x.id}"><td><span class="act">${esc(x.system)}</span></td><td><span class="nm">${esc(x.name)}</span><div class="muted" style="font-size:11px">${esc(x.host)}${x.authUser ? " · " + esc(x.authUser) : ""}</div></td><td class="mono">${esc(x.project || "")}${x.issueType ? " / " + esc(x.issueType) : ""}</td><td><span class="sev ${sevClass(x.minSeverity)}">${esc(x.minSeverity)}</span></td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="tkt-tog" ${x.enabled ? "checked" : ""}> ${t("cr.onLabel")}</label> <button class="btn-sm2 tkt-test">${t("cr.testBtn")}</button> <button class="btn-sm2 tkt-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 5 : 4}" class="muted">${t("cr.noDest")} ${isAdmin ? t("cr.noDestAdmin") : t("cr.byAdmin")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("cr.secResilience")} <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${fmt("cr.daysHistory", { n: resilience.length })}</span></div>
  <div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
    ${spark(resilience, "machineSpeedPct", "#16a34a", t("cr.sparkMachine"), "%", sla.machineSpeedMin, "min")}
    ${spark(resilience, "latencyMs", "#a78bfa", t("cr.sparkLatency"), "ms", sla.latencyMaxMs, "max")}
    ${spark(resilience, "backlog", "#ef4444", t("cr.sparkBacklog"), "", sla.backlogMax, "max")}
    ${spark(resilience, "score", "#f59e0b", t("cr.sparkScore"))}
  </div>
  <div class="sec">${t("cr.secIam")}${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="iam-add">${t("cr.addEntra")}</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">${t("cr.iamSub1")} ${iam.armed ? `<span style="color:#b91c1c;font-weight:600">${t("cr.armed")}</span> ${t("cr.iamArmed")}` : `<span style="color:#16a34a;font-weight:600">${t("cr.dryRun")}</span> ${t("cr.iamDryrun")}`}</div>
  <table class="t"><thead><tr><th>${t("cr.thTarget")}</th><th>${t("cr.thTenant")}</th><th>${t("cr.thMode")}</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${iamTgts.map((x) => `<tr data-iam="${x.id}"><td><span class="nm">${esc(x.name)}</span><div class="muted" style="font-size:11px">${esc(x.clientId || "")}</div></td><td class="mono">${esc(x.tenantRef || "")}</td><td><span class="act">${esc(x.mode)}</span>${x.mode !== "recommend" && !iam.armed ? ` <span class="muted" style="font-size:10px">${t("cr.disarmed")}</span>` : ""}</td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="iam-tog" ${x.enabled ? "checked" : ""}> ${t("cr.onLabel")}</label> <button class="btn-sm2 iam-test">${t("cr.testBtn")}</button> <button class="btn-sm2 iam-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 4 : 3}" class="muted">${t("cr.noEntra")} ${isAdmin ? t("cr.noEntraAdmin") : t("cr.byAdmin")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("cr.secSoar")}${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="soar-add">${t("cr.addWebhook")}</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">${t("cr.soarSub")}</div>
  <table class="t"><thead><tr><th>${t("cr.thWebhook")}</th><th>${t("cr.thMinSev")}</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${soarHooks.map((w) => `<tr data-soar="${w.id}"><td><span class="nm">${esc(w.name)}</span><div class="muted" style="font-size:11px">${esc(w.host)}${w.hasKey ? " · " + t("cr.keyed") : ""}</div></td><td><span class="sev ${sevClass(w.minSeverity)}">${esc(w.minSeverity)}</span></td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="soar-tog" ${w.enabled ? "checked" : ""}> ${t("cr.onLabel")}</label> <button class="btn-sm2 soar-test">${t("cr.testBtn")}</button> <button class="btn-sm2 soar-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 3 : 2}" class="muted">${t("cr.noWebhook")} ${isAdmin ? t("cr.noWebhookAdmin") : t("cr.byAdmin")}</td></tr>`}
  </tbody></table>
  <div class="sec">${t("cr.secFeed")}</div>
  <table class="t"><thead><tr><th>${t("cr.thWhen")}</th><th>${t("cr.thDir")}</th><th>${t("cr.thEvent")}</th><th>${t("cr.thSeverity")}</th><th>${t("cr.thAutoDecided")}</th></tr></thead><tbody>
    ${feed.map((e) => `<tr><td class="muted" style="font-size:11px">${esc((e.at || "").slice(11, 19))}</td><td><span class="dir ${dirClass(e.direction)}">${dirLabel(e.direction)}</span></td><td><span class="mono">${esc(e.type)}</span><div class="muted" style="font-size:11px">${esc(e.summary || "")}</div></td><td><span class="sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td><td>${e.decided ? `<span class="act">${esc(e.decided)}</span> <span class="muted" style="font-size:10px">${e.latencyMs ?? 0}ms</span>` : `<span class="muted" style="font-size:11px">${t("cr.toHuman")}</span>`}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${t("cr.noFeed")}</td></tr>`}
  </tbody></table>`;
}

function wire(): void {
  $("ai-reason")?.addEventListener("click", async () => {
    const out = $("ai-reason-out"); const btn = $("ai-reason") as HTMLButtonElement | null;
    if (!out) return;
    if (btn) btn.disabled = true;
    out.innerHTML = `<span class="muted" style="font-size:12px">${t("cr.reasoningLocal")}</span>`;
    try {
      const r = await getJson("/api/croc/reason");
      lastReasoning = `<div class="ai-md">${mdLite(r.reasoning || "")}</div><div class="muted" style="font-size:10px;margin-top:8px">${fmt("cr.model", { m: esc(r.model) })}${r.offline ? " · " + t("cr.offlineFallback") : ""}</div>`;
      const live = $("ai-reason-out"); if (live) live.innerHTML = lastReasoning; // re-query in case a refresh re-rendered
    } catch { const live = $("ai-reason-out"); if (live) live.innerHTML = `<span class="muted" style="font-size:12px">${t("cr.reasoningFailed")}</span>`; }
    finally { const b = $("ai-reason") as HTMLButtonElement | null; if (b) b.disabled = false; }
  });
  document.querySelectorAll<HTMLInputElement>(".pol-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.pol;
      try { await fetch(`/api/croc/policies/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? t("cr.policyOn") : t("cr.policyOff")); }
      catch { toast(t("cr.failed")); t.checked = !t.checked; }
    });
  });
  $("pol-add")?.addEventListener("click", async () => {
    const name = prompt(t("cr.pPolicyName")); if (!name) return;
    const eventFilter = prompt(t("cr.pEventFilter"), "*") || "*";
    const minSeverity = prompt(t("cr.pMinSeverity"), "high") || "high";
    const action = prompt(t("cr.pAction"), "escalate") || "escalate";
    try { const r = await fetch("/api/croc/policies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, eventFilter, minSeverity, action, direction: "any" }) });
      if ((await r.json()).ok) { toast(t("cr.policyAdded")); void load(); } } catch { toast(t("cr.failed")); }
  });
  // ── external ticketing destinations ──
  document.querySelectorAll<HTMLInputElement>(".tkt-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.tkt;
      try { await fetch(`/api/croc/ticketing/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? t("cr.destOn") : t("cr.destOff")); }
      catch { toast(t("cr.failed")); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".tkt-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.tkt;
      toast(t("cr.testingTicket"));
      try { const r = await (await fetch(`/api/croc/ticketing/${id}/test`, { method: "POST" })).json(); toast(r.ok ? fmt("cr.created", { ref: r.ref || t("cr.ticket") }) : t("cr.testFailedCred")); }
      catch { toast(t("cr.testFailed")); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".tkt-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.tkt;
      if (!confirm(t("cr.confirmRemoveDest"))) return;
      try { await fetch(`/api/croc/ticketing/${id}`, { method: "DELETE" }); toast(t("cr.removed")); void load(); } catch { toast(t("cr.failed")); }
    });
  });
  $("tkt-add")?.addEventListener("click", async () => {
    const system = (prompt(t("cr.pSystem"), "jira") || "jira").toLowerCase();
    const isJira = system !== "servicenow";
    const baseUrl = prompt(isJira ? t("cr.pJiraUrl") : t("cr.pSnowUrl")); if (!baseUrl) return;
    const authUser = prompt(isJira ? t("cr.pJiraUser") : t("cr.pSnowUser")) || "";
    const authSecret = prompt(isJira ? t("cr.pJiraSecret") : t("cr.pSnowSecret")); if (!authSecret) return;
    const project = prompt(isJira ? t("cr.pJiraProject") : t("cr.pSnowTable"), isJira ? "" : "incident") || "";
    const issueType = isJira ? (prompt(t("cr.pIssueType"), "Task") || "Task") : "";
    const minSeverity = prompt(t("cr.pPushSeverity"), "high") || "high";
    try { const r = await fetch("/api/croc/ticketing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ system, baseUrl, authUser, authSecret, project, issueType, minSeverity }) });
      if ((await r.json()).ok) { toast(t("cr.destAdded")); void load(); } else toast(t("cr.failed")); } catch { toast(t("cr.failed")); }
  });
  // ── IAM enforcement targets (Entra) ──
  document.querySelectorAll<HTMLInputElement>(".iam-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.iam;
      try { await fetch(`/api/croc/iam/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? t("cr.targetOn") : t("cr.targetOff")); }
      catch { toast(t("cr.failed")); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".iam-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.iam;
      toast(t("cr.testingProbe"));
      try { const r = await (await fetch(`/api/croc/iam/${id}/test`, { method: "POST" })).json(); toast(r.ok ? fmt("cr.authenticated", { armed: r.armed ? t("cr.armed") : t("cr.dryRunShort"), mode: r.mode }) : fmt("cr.authFailed", { note: r.note || t("cr.checkCreds") })); }
      catch { toast(t("cr.testFailed")); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".iam-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.iam;
      if (!confirm(t("cr.confirmRemoveEntra"))) return;
      try { await fetch(`/api/croc/iam/${id}`, { method: "DELETE" }); toast(t("cr.removed")); void load(); } catch { toast(t("cr.failed")); }
    });
  });
  $("iam-add")?.addEventListener("click", async () => {
    const tenantRef = prompt(t("cr.pTenant")); if (!tenantRef) return;
    const clientId = prompt(t("cr.pClientId")); if (!clientId) return;
    const clientSecret = prompt(t("cr.pClientSecret")); if (!clientSecret) return;
    const mode = (prompt(t("cr.pMode"), "recommend") || "recommend").toLowerCase();
    const eventFilter = prompt(t("cr.pEventFilterBlank"), "") || "";
    try { const r = await fetch("/api/croc/iam", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tenantRef, clientId, clientSecret, mode, eventFilter }) });
      if ((await r.json()).ok) { toast(t("cr.entraAdded")); void load(); } else toast(t("cr.failed")); } catch { toast(t("cr.failed")); }
  });
  // ── SOAR / n8n webhooks ──
  document.querySelectorAll<HTMLInputElement>(".soar-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.soar;
      try { await fetch(`/api/croc/soar/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? t("cr.webhookOn") : t("cr.webhookOff")); }
      catch { toast(t("cr.failed")); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".soar-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.soar;
      toast(t("cr.testing"));
      try { const r = await (await fetch(`/api/croc/soar/${id}/test`, { method: "POST" })).json(); toast(r.ok ? t("cr.webhookReachable") : t("cr.testFailedUrl")); }
      catch { toast(t("cr.testFailed")); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".soar-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.soar;
      if (!confirm(t("cr.confirmRemoveWebhook"))) return;
      try { await fetch(`/api/croc/soar/${id}`, { method: "DELETE" }); toast(t("cr.removed")); void load(); } catch { toast(t("cr.failed")); }
    });
  });
  $("soar-add")?.addEventListener("click", async () => {
    const url = prompt(t("cr.pWebhookUrl")); if (!url) return;
    const apiKey = prompt(t("cr.pApiKey"), "") || "";
    const minSeverity = prompt(t("cr.pDispatchSeverity"), "high") || "high";
    try { const r = await fetch("/api/croc/soar", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, apiKey, minSeverity }) });
      if ((await r.json()).ok) { toast(t("cr.webhookAdded")); void load(); } else toast(t("cr.failed")); } catch { toast(t("cr.failed")); }
  });
}

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try {
    const me = await getJson("/api/auth/me").catch(() => ({}));
    isAdmin = !!me.isAdmin;
    body.innerHTML = render(await getJson("/api/croc"));
    wire();
  } catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("cr.loadFailed", { e: esc((e as Error).message) })}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); setInterval(() => void load(), 30000); });
