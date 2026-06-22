/**
 * croc.ts — client for the CROC Continuous Defense Loop cockpit (/croc).
 * Renders the loop pulse (events / machine-speed % / latency / health), the ∞ bidirectional flow,
 * the risk-weighted SOC alert queue (CROC→SOC), the cyber-risk-hunting worklist + over-scoped NHI,
 * the pre-authorization policies, and the live loop-event feed.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
const sevClass = (s: string): string => "sv-" + String(s || "info").toLowerCase();
const dirClass = (d: string): string => d === "croc->soc" ? "dir-croc" : d === "soc->croc" ? "dir-soc" : "dir-internal";
const dirLabel = (d: string): string => d === "croc->soc" ? "CROC→SOC" : d === "soc->croc" ? "SOC→CROC" : "internal";
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
    : `<div class="muted" style="font-size:11px;padding:12px 0">Not enough history yet — a point accrues per day.</div>`;
  const sla = target != null ? `<span class="muted" style="font-size:10px;margin-left:6px">SLA ${dir === "min" ? "≥" : "≤"}${target}${suffix}${breach ? " · BREACH" : ""}</span>` : "";
  return `<div class="panel" style="padding:10px 12px"><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">${esc(label)}</div><div style="font-size:20px;font-weight:700;color:${breach ? "#ef4444" : color}">${last}${suffix}${sla}</div>${body}</div>`;
}
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

let isAdmin = false;

function render(d: any): string {
  const s = d.summary || {};
  const hClass = s.loopHealth === "moving" ? "h-moving" : s.loopHealth === "still" ? "h-still" : "h-one";
  const hLabel = s.loopHealth === "moving" ? "Loop is moving" : s.loopHealth === "still" ? "Loop is STILL (a diagram, not a loop)" : "One-directional (a handoff, not a loop)";
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
    <div class="card"><div class="lbl">Loop events (24h)</div><div class="val">${s.eventsToday || 0}</div><div class="foot">${s.lastHour || 0} in the last hour</div></div>
    <div class="card"><div class="lbl">Machine-speed</div><div class="val" style="color:${gaugeColor(s.machineSpeedPct || 0)}">${s.machineSpeedPct || 0}%</div><div class="foot">${s.autoDecided || 0} fired by policy${s.ticketsOpened ? ` · ${s.ticketsOpened} ticket${s.ticketsOpened === 1 ? "" : "s"} opened` : ""}${s.externalTickets ? ` · ${s.externalTickets} → ITSM` : ""}</div></div>
    <div class="card"><div class="lbl">Decision latency</div><div class="val">${s.medianLatencyMs || 0}<span style="font-size:13px">ms</span></div><div class="foot">p95 ${s.p95LatencyMs || 0}ms</div></div>
    <div class="card"><div class="lbl">Loop health</div><div class="val" style="font-size:15px;margin-top:8px"><span class="health ${hClass}"><span class="dot"></span>${s.loopHealth || "?"}</span></div><div class="foot">${esc(hLabel)}</div></div>
  </div>
  <div class="sec">The ∞ — does intelligence cross both ways?</div>
  <div class="loop">
    <div class="loopbox"><div class="t">CROC</div><div class="n">protects tomorrow · exposure</div></div>
    <div style="text-align:center"><div class="arr">${s.crocToSoc || 0} →</div><div class="muted" style="font-size:10px">exposure → detection priority</div><div class="arr">← ${s.socToCroc || 0}</div><div class="muted" style="font-size:10px">incident → reprioritize exposure</div></div>
    <div class="loopbox"><div class="t">SOC</div><div class="n">protects today · detection</div></div>
  </div>
  <div class="grid2" style="margin-top:14px">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">CROC→SOC · risk-weighted alert queue</div>
      <div class="muted" style="font-size:11px;margin-bottom:6px">The SOC hunts by risk (exposure × criticality), not by recency.</div>
      <table class="t"><thead><tr><th>Weight</th><th>Sev</th><th>Alert</th></tr></thead><tbody>
      ${rwa.map((a) => `<tr><td><span class="gauge" style="width:34px;height:34px;font-size:13px;background:${gaugeColor(a.riskWeight)}">${a.riskWeight}</span></td><td><span class="sev ${sevClass(a.severity)}">${esc(a.severity)}</span></td><td><span class="nm">${esc(a.name)}</span><div class="muted" style="font-size:11px">${esc(a.category || "")}${a.attack ? " · " + esc(a.attack) : ""}</div></td></tr>`).join("") || `<tr><td colspan="3" class="muted">No open alerts.</td></tr>`}
      </tbody></table>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">SOC→CROC · incident-driven feedback</div>
      <div style="font-size:13px;color:#cbd5e1;margin-bottom:8px">${(fb.matchingExposures || 0)} of ${fb.totalExposures || 0} estate exposures are actively attacked (KEV / exploited / seen in the wild) — reprioritized by what the SOC is seeing.</div>
      <div class="muted" style="font-size:11px">Techniques seen in recent incidents:</div>
      <div style="margin-top:5px">${(fb.techniquesSeen || []).map((t: string) => `<span class="mono" style="background:#1e2440;border-radius:5px;padding:1px 7px;margin:2px;display:inline-block">${esc(t)}</span>`).join("") || "<span class='muted'>none</span>"}</div>
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin:14px 0 6px">Over-scoped agent / NHI exposures</div>
      <table class="t"><tbody>${agentic.map((a) => `<tr><td class="nm">${esc(a.name)}</td><td class="muted" style="font-size:11px">${esc(a.privilege || a.type || "")}</td><td><span class="why">${esc((a.why || []).join(" · "))}</span></td></tr>`).join("") || `<tr><td class="muted">No over-scoped non-human identities found.</td></tr>`}</tbody></table>
    </div>
  </div>
  <div class="sec">Cyber-risk hunting — where could an adversary succeed? <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">top fused exposures</span></div>
  <table class="t"><thead><tr><th>Priority</th><th>Exposure</th><th>Why</th><th>Assets</th></tr></thead><tbody>
    ${hunting.map((e) => `<tr><td><span class="gauge" style="width:32px;height:32px;font-size:12px;background:${gaugeColor(e.priority)}">${e.priority}</span></td><td class="mono">${esc(e.ref)}</td><td class="muted" style="font-size:11px">${esc((e.factors || []).slice(0, 3).join(" · "))}</td><td>${e.assets || 0}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No fused exposures yet (run exposure imports + CVE matching).</td></tr>`}
  </tbody></table>
  <div class="sec">Pre-authorization — decide before the race begins <span class="spacer"></span>${isAdmin ? `<button class="btn-sm2" id="pol-add">+ Add policy</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">When an event fires, these run at machine speed — no deliberation while the decision still matters. Humans own the policy; the loop executes it.</div>
  <table class="t"><thead><tr><th>Policy</th><th>When</th><th>≥ Sev</th><th>Direction</th><th>Action</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${policies.map((p) => `<tr data-pol="${p.id}"><td><span class="nm">${esc(p.name)}</span><div class="muted" style="font-size:11px">${esc(p.description || "")}</div></td><td class="mono">${esc(p.eventFilter)}</td><td><span class="sev ${sevClass(p.minSeverity)}">${esc(p.minSeverity)}</span></td><td><span class="dir ${dirClass(p.direction === "any" ? "internal" : p.direction)}">${p.direction === "any" ? "any" : dirLabel(p.direction)}</span></td><td><span class="act">${esc(p.action)}</span></td>${isAdmin ? `<td><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="pol-tog" ${p.enabled ? "checked" : ""}> on</label></td>` : ""}</tr>`).join("")}
  </tbody></table>
  <div class="sec">External ticketing — act in Jira / ServiceNow${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="tkt-add">+ Add destination</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">When a <b>ticket</b> or <b>constrain</b> action fires, the loop also opens a real ticket in these systems (gated by severity). ${ticketing.configured ? "An external destination is configured — the loop acts outside XORCISM." : "None configured yet — the loop opens an internal XTICKET only. Add a destination or set the <span class='mono'>JIRA_*</span> / <span class='mono'>SERVICENOW_*</span> env."}</div>
  <table class="t"><thead><tr><th>System</th><th>Destination</th><th>Project / Table</th><th>≥ Sev</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${tgts.map((t) => `<tr data-tkt="${t.id}"><td><span class="act">${esc(t.system)}</span></td><td><span class="nm">${esc(t.name)}</span><div class="muted" style="font-size:11px">${esc(t.host)}${t.authUser ? " · " + esc(t.authUser) : ""}</div></td><td class="mono">${esc(t.project || "")}${t.issueType ? " / " + esc(t.issueType) : ""}</td><td><span class="sev ${sevClass(t.minSeverity)}">${esc(t.minSeverity)}</span></td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="tkt-tog" ${t.enabled ? "checked" : ""}> on</label> <button class="btn-sm2 tkt-test">Test</button> <button class="btn-sm2 tkt-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 5 : 4}" class="muted">No external destinations. ${isAdmin ? "Add Jira/ServiceNow to push tickets outbound." : "Configured by an admin."}</td></tr>`}
  </tbody></table>
  <div class="sec">Resilience over time — is the loop getting better? <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">${resilience.length} day${resilience.length === 1 ? "" : "s"} of history · reactive recompute</span></div>
  <div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
    ${spark(resilience, "machineSpeedPct", "#16a34a", "Machine-speed %", "%", sla.machineSpeedMin, "min")}
    ${spark(resilience, "latencyMs", "#a78bfa", "Median latency", "ms", sla.latencyMaxMs, "max")}
    ${spark(resilience, "backlog", "#ef4444", "Actively-attacked backlog", "", sla.backlogMax, "max")}
    ${spark(resilience, "score", "#f59e0b", "Enterprise risk score")}
  </div>
  <div class="sec">IAM enforcement — least-privilege on <code>constrain</code>${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="iam-add">+ Add Entra target</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">A <b>constrain</b> action can disable an over-scoped Entra principal or revoke its sessions. ${iam.armed ? `<span style="color:#b91c1c;font-weight:600">ARMED</span> — actionable targets will write to Entra (<span class="mono">XOR_ALLOW_IAM_ENFORCE=1</span>).` : `<span style="color:#16a34a;font-weight:600">DRY-RUN</span> — recommends only; set <span class="mono">XOR_ALLOW_IAM_ENFORCE=1</span> to arm real writes.`}</div>
  <table class="t"><thead><tr><th>Target</th><th>Tenant</th><th>Mode</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${iamTgts.map((t) => `<tr data-iam="${t.id}"><td><span class="nm">${esc(t.name)}</span><div class="muted" style="font-size:11px">${esc(t.clientId || "")}</div></td><td class="mono">${esc(t.tenantRef || "")}</td><td><span class="act">${esc(t.mode)}</span>${t.mode !== "recommend" && !iam.armed ? ` <span class="muted" style="font-size:10px">(disarmed)</span>` : ""}</td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="iam-tog" ${t.enabled ? "checked" : ""}> on</label> <button class="btn-sm2 iam-test">Test</button> <button class="btn-sm2 iam-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 4 : 3}" class="muted">No Entra target. ${isAdmin ? "Add one (or set ENTRA_* env) to enforce least-privilege on flagged identities." : "Configured by an admin."}</td></tr>`}
  </tbody></table>
  <div class="sec">SOAR automation — hand off to n8n${isAdmin ? `<span class="spacer"></span><button class="btn-sm2" id="soar-add">+ Add webhook</button>` : ""}</div>
  <div class="muted" style="font-size:11px;margin-bottom:6px">Every fired action is POSTed to these automation webhooks so a downstream playbook can run (enrich, quarantine, page…).</div>
  <table class="t"><thead><tr><th>Webhook</th><th>≥ Sev</th>${isAdmin ? "<th></th>" : ""}</tr></thead><tbody>
    ${soarHooks.map((w) => `<tr data-soar="${w.id}"><td><span class="nm">${esc(w.name)}</span><div class="muted" style="font-size:11px">${esc(w.host)}${w.hasKey ? " · keyed" : ""}</div></td><td><span class="sev ${sevClass(w.minSeverity)}">${esc(w.minSeverity)}</span></td>${isAdmin ? `<td style="white-space:nowrap"><label style="font-size:11px;cursor:pointer"><input type="checkbox" class="soar-tog" ${w.enabled ? "checked" : ""}> on</label> <button class="btn-sm2 soar-test">Test</button> <button class="btn-sm2 soar-del">✕</button></td>` : ""}</tr>`).join("") || `<tr><td colspan="${isAdmin ? 3 : 2}" class="muted">No automation webhook. ${isAdmin ? "Add an n8n/Tines/Shuffle webhook (or set N8N_WEBHOOK_URL)." : "Configured by an admin."}</td></tr>`}
  </tbody></table>
  <div class="sec">Live loop feed</div>
  <table class="t"><thead><tr><th>When</th><th>Dir</th><th>Event</th><th>Severity</th><th>Auto-decided</th></tr></thead><tbody>
    ${feed.map((e) => `<tr><td class="muted" style="font-size:11px">${esc((e.at || "").slice(11, 19))}</td><td><span class="dir ${dirClass(e.direction)}">${dirLabel(e.direction)}</span></td><td><span class="mono">${esc(e.type)}</span><div class="muted" style="font-size:11px">${esc(e.summary || "")}</div></td><td><span class="sev ${sevClass(e.severity)}">${esc(e.severity)}</span></td><td>${e.decided ? `<span class="act">${esc(e.decided)}</span> <span class="muted" style="font-size:10px">${e.latencyMs ?? 0}ms</span>` : `<span class="muted" style="font-size:11px">→ human</span>`}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No loop events in the last 24h. The loop is still — wire exposure/incident events to make it move.</td></tr>`}
  </tbody></table>`;
}

function wire(): void {
  document.querySelectorAll<HTMLInputElement>(".pol-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.pol;
      try { await fetch(`/api/croc/policies/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? "Policy enabled" : "Policy disabled"); }
      catch { toast("Failed"); t.checked = !t.checked; }
    });
  });
  $("pol-add")?.addEventListener("click", async () => {
    const name = prompt("Policy name:"); if (!name) return;
    const eventFilter = prompt("Event filter (comma substrings, e.g. cve,exposure or * for all):", "*") || "*";
    const minSeverity = prompt("Minimum severity (info/low/medium/high/critical):", "high") || "high";
    const action = prompt("Pre-authorized action (escalate/reprioritize/ticket/constrain/notify):", "escalate") || "escalate";
    try { const r = await fetch("/api/croc/policies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, eventFilter, minSeverity, action, direction: "any" }) });
      if ((await r.json()).ok) { toast("Policy added"); void load(); } } catch { toast("Failed"); }
  });
  // ── external ticketing destinations ──
  document.querySelectorAll<HTMLInputElement>(".tkt-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.tkt;
      try { await fetch(`/api/croc/ticketing/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? "Destination enabled" : "Destination disabled"); }
      catch { toast("Failed"); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".tkt-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.tkt;
      toast("Testing… (posts one real ticket)");
      try { const r = await (await fetch(`/api/croc/ticketing/${id}/test`, { method: "POST" })).json(); toast(r.ok ? `Created ${r.ref || "ticket"}` : "Test failed — check URL/credentials"); }
      catch { toast("Test failed"); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".tkt-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.tkt;
      if (!confirm("Remove this external ticketing destination?")) return;
      try { await fetch(`/api/croc/ticketing/${id}`, { method: "DELETE" }); toast("Removed"); void load(); } catch { toast("Failed"); }
    });
  });
  $("tkt-add")?.addEventListener("click", async () => {
    const system = (prompt("System — 'jira' or 'servicenow':", "jira") || "jira").toLowerCase();
    const isJira = system !== "servicenow";
    const baseUrl = prompt(isJira ? "Jira base URL (e.g. https://acme.atlassian.net):" : "ServiceNow instance (e.g. dev12345.service-now.com):"); if (!baseUrl) return;
    const authUser = prompt(isJira ? "Account email (Jira Cloud) — leave blank for a bearer PAT:" : "ServiceNow username:") || "";
    const authSecret = prompt(isJira ? "API token / PAT:" : "ServiceNow password:"); if (!authSecret) return;
    const project = prompt(isJira ? "Jira project key (e.g. SEC):" : "Table (default incident):", isJira ? "" : "incident") || "";
    const issueType = isJira ? (prompt("Jira issue type:", "Task") || "Task") : "";
    const minSeverity = prompt("Push for severity ≥ (low/medium/high/critical):", "high") || "high";
    try { const r = await fetch("/api/croc/ticketing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ system, baseUrl, authUser, authSecret, project, issueType, minSeverity }) });
      if ((await r.json()).ok) { toast("Destination added"); void load(); } else toast("Failed"); } catch { toast("Failed"); }
  });
  // ── IAM enforcement targets (Entra) ──
  document.querySelectorAll<HTMLInputElement>(".iam-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.iam;
      try { await fetch(`/api/croc/iam/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? "Target enabled" : "Target disabled"); }
      catch { toast("Failed"); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".iam-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.iam;
      toast("Testing… (read-only probe)");
      try { const r = await (await fetch(`/api/croc/iam/${id}/test`, { method: "POST" })).json(); toast(r.ok ? `Authenticated · ${r.armed ? "ARMED" : "dry-run"} · mode ${r.mode}` : `Failed — ${r.note || "check tenant/client/secret"}`); }
      catch { toast("Test failed"); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".iam-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.iam;
      if (!confirm("Remove this Entra IAM target?")) return;
      try { await fetch(`/api/croc/iam/${id}`, { method: "DELETE" }); toast("Removed"); void load(); } catch { toast("Failed"); }
    });
  });
  $("iam-add")?.addEventListener("click", async () => {
    const tenantRef = prompt("Entra tenant id (GUID) or primary domain:"); if (!tenantRef) return;
    const clientId = prompt("App (client) id:"); if (!clientId) return;
    const clientSecret = prompt("Client secret:"); if (!clientSecret) return;
    const mode = (prompt("Mode — 'recommend' (dry-run), 'revoke-roles' (surgical: strip app+directory roles), 'disable', or 'revoke-sessions':", "recommend") || "recommend").toLowerCase();
    const eventFilter = prompt("Event filter (comma substrings, blank = all):", "") || "";
    try { const r = await fetch("/api/croc/iam", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tenantRef, clientId, clientSecret, mode, eventFilter }) });
      if ((await r.json()).ok) { toast("Entra target added"); void load(); } else toast("Failed"); } catch { toast("Failed"); }
  });
  // ── SOAR / n8n webhooks ──
  document.querySelectorAll<HTMLInputElement>(".soar-tog").forEach((t) => {
    t.addEventListener("change", async () => {
      const id = (t.closest("tr") as HTMLElement)?.dataset.soar;
      try { await fetch(`/api/croc/soar/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: t.checked }) }); toast(t.checked ? "Webhook enabled" : "Webhook disabled"); }
      catch { toast("Failed"); t.checked = !t.checked; }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".soar-test").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.soar;
      toast("Testing…");
      try { const r = await (await fetch(`/api/croc/soar/${id}/test`, { method: "POST" })).json(); toast(r.ok ? "Webhook reachable" : "Test failed — check URL"); }
      catch { toast("Test failed"); }
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".soar-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const id = (b.closest("tr") as HTMLElement)?.dataset.soar;
      if (!confirm("Remove this SOAR webhook?")) return;
      try { await fetch(`/api/croc/soar/${id}`, { method: "DELETE" }); toast("Removed"); void load(); } catch { toast("Failed"); }
    });
  });
  $("soar-add")?.addEventListener("click", async () => {
    const url = prompt("Automation webhook URL (e.g. n8n https://…/webhook/…):"); if (!url) return;
    const apiKey = prompt("Optional API key (sent as X-API-Key header):", "") || "";
    const minSeverity = prompt("Dispatch for severity ≥ (low/medium/high/critical):", "high") || "high";
    try { const r = await fetch("/api/croc/soar", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, apiKey, minSeverity }) });
      if ((await r.json()).ok) { toast("Webhook added"); void load(); } else toast("Failed"); } catch { toast("Failed"); }
  });
}

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try {
    const me = await getJson("/api/auth/me").catch(() => ({}));
    isAdmin = !!me.isAdmin;
    body.innerHTML = render(await getJson("/api/croc"));
    wire();
  } catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load: ${esc((e as Error).message)}</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { void load(); setInterval(() => void load(), 30000); });
