/**
 * agents.ts — client for /agents. XOR agent fleet management: inventory (status / last-seen /
 * platform), recent jobs and events, and per-agent tasking (launch a scan → POST /api/agent-scan).
 * Consumes the existing agent admin API (/api/agents-overview, /api/agent-scan).
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }
function fmtBytes(n: number): string { if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(i ? 1 : 0)} ${u[i]}`; }

let kinds: string[] = ["inventory", "vuln", "oval", "av", "hunt", "full", "emulate", "forensics", "rustinel", "yara"];

/** "5m ago" / "3h ago" from a minutes-ago integer. */
function ago(mins: number | null): string {
  if (mins == null) return "never";
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

function render(d: any): string {
  const s = d.summary || {};
  const agents = (d.agents || []) as any[];
  const jobs = (d.jobs || []) as any[];
  const events = (d.events || []) as any[];
  const honeypot = (d.honeypot || []) as any[];
  const topPorts = (d.honeypotTopPorts || []) as any[];
  const memDumps = (d.memDumps || []) as any[];
  const logHunts = (d.logHunts || []) as any[];
  kinds = d.kinds && d.kinds.length ? d.kinds : kinds;
  const kindOpts = kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
  const healthColor = s.health == null ? "#94a3b8" : s.health >= 80 ? "#22c55e" : s.health >= 50 ? "#fbbf24" : "#f87171";
  const srColor = s.successRate == null ? "#94a3b8" : s.successRate >= 90 ? "#22c55e" : s.successRate >= 70 ? "#fbbf24" : "#f87171";
  return `
  <div class="cards">
    <div class="card"><div class="lbl">Agents</div><div class="val">${s.total || 0}</div><div class="foot">${s.online || 0} online · ${s.idle || 0} idle · ${s.offline || 0} offline</div></div>
    <div class="card"><div class="lbl">Fleet health</div><div class="val" style="color:${healthColor}">${s.health == null ? "—" : s.health + "%"}</div><div class="foot">online / enrolled</div></div>
    <div class="card"><div class="lbl">Jobs pending</div><div class="val" style="color:#60a5fa">${s.jobsPending || 0}</div><div class="foot">${s.jobsTotal || 0} in recent history</div></div>
    <div class="card"><div class="lbl">Success rate</div><div class="val" style="color:${srColor}">${s.successRate == null ? "—" : s.successRate + "%"}</div><div class="foot">${s.jobsDone || 0} done · ${s.jobsFailed || 0} failed</div></div>
    <div class="card"><div class="lbl">Scans (24h)</div><div class="val">${s.scans24h || 0}</div><div class="foot">jobs queued today</div></div>
    <div class="card"><div class="lbl">Alerts</div><div class="val" style="color:${s.alerts ? "#f87171" : "#22c55e"}">${s.alerts || 0}</div><div class="foot">critical / high events</div></div>
    <div class="card"><div class="lbl">Honeypot hits</div><div class="val" style="color:${s.honeypotHits ? "#fb923c" : "#94a3b8"}">${s.honeypotHits || 0}</div><div class="foot">${s.honeypotIps || 0} attacker IP${s.honeypotIps === 1 ? "" : "s"}</div></div>
    <div class="card"><div class="lbl">RAM dumps</div><div class="val" style="color:${s.memDumps ? "#a78bfa" : "#94a3b8"}">${s.memDumps || 0}</div><div class="foot">${s.memDumpsCompleted || 0} acquired · ${fmtBytes(s.memDumpBytes || 0)}</div></div>
    <div class="card"><div class="lbl">AI log hunts</div><div class="val" style="color:${s.logHuntsSuspicious ? "#f87171" : s.logHunts ? "#22c55e" : "#94a3b8"}">${s.logHunts || 0}</div><div class="foot">${s.logHuntsSuspicious || 0} suspicious · ${s.logHuntEvents || 0} events</div></div>
    <div class="card"><div class="lbl">Intel IOCs</div><div class="val">${s.iocs || 0}</div><div class="foot">served to the fleet</div></div>
  </div>

  <div class="sec">Agent fleet <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">launch a scan per agent — it runs at the next check-in</span></div>
  <table class="t"><thead><tr><th>Status</th><th>Agent</th><th>Platform</th><th>Address</th><th>Last seen</th><th>Launch scan</th></tr></thead><tbody>
    ${agents.map((a) => `<tr>
      <td><span class="st st-${esc(a.freshness)}"><span class="dot"></span>${esc(a.freshness)}</span></td>
      <td><span class="nm lnk" data-detail="${esc(a.name)}">${esc(a.name)}</span>${a.asset_name && a.asset_name !== a.name ? `<div class="muted" style="font-size:11px">asset: ${esc(a.asset_name)}</div>` : ""}${a.version ? `<div class="muted" style="font-size:11px">v${esc(a.version)}</div>` : ""}</td>
      <td>${esc(a.os || "")}${a.platform ? ` <span class="muted">/ ${esc(a.platform)}</span>` : ""}</td>
      <td class="mono">${esc(a.ip || a.fqdn || "—")}</td>
      <td class="muted" style="font-size:12px">${ago(a.minsAgo)}</td>
      <td style="white-space:nowrap"><select class="kind" data-agent="${esc(a.name)}">${kindOpts}</select> <button class="run" data-agent="${esc(a.name)}">Run ▸</button></td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">No agents enrolled yet. Enroll one with <span class="mono">xor_agent.py --enroll</span>.</td></tr>`}
  </tbody></table>

  <div class="sec">Recent jobs</div>
  <table class="t"><thead><tr><th>#</th><th>Agent</th><th>Scan</th><th>Status</th><th>Result</th><th>When</th></tr></thead><tbody>
    ${jobs.map((j) => `<tr><td class="muted">${j.AgentJobID}</td><td>${esc(j.agent)}</td><td><span class="mono">${esc(j.kind)}</span></td><td><span class="jb jb-${esc(j.status)}">${esc(j.status)}</span></td><td class="muted" style="font-size:12px">${esc((j.result_summary || "").slice(0, 120))}</td><td class="muted" style="font-size:11px">${esc((j.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No jobs yet — launch a scan above.</td></tr>`}
  </tbody></table>

  <div class="sec">Recent events</div>
  <table class="t"><thead><tr><th>Agent</th><th>Type</th><th>Severity</th><th>Title</th><th>When</th></tr></thead><tbody>
    ${events.map((e) => `<tr><td>${esc(e.agent)}</td><td><span class="mono">${esc(e.type)}</span></td><td><span class="sev sev-${esc(e.severity || "info")}">${esc(e.severity || "info")}</span></td><td>${esc(e.title || "")}</td><td class="muted" style="font-size:11px">${esc((e.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No events yet.</td></tr>`}
  </tbody></table>

  <div class="sec">🍯 Honeypot hits <span class="spacer"></span>${topPorts.length ? `<span class="muted" style="font-size:11px;text-transform:none">top ports: ${topPorts.map((p: any) => `${esc(p.port)} (${esc(p.hits)})`).join(" · ")}</span>` : ""}</div>
  <table class="t"><thead><tr><th>When</th><th>Agent</th><th>Source IP</th><th>→ Port</th><th>Service</th><th>Banner / payload</th></tr></thead><tbody>
    ${honeypot.map((h) => `<tr><td class="muted" style="font-size:11px">${esc((h.hit_at || h.created_at || "").slice(0, 19))}</td><td>${esc(h.agent)}</td><td class="mono">${esc(h.src_ip || "—")}${h.src_port ? `<span class="muted">:${esc(h.src_port)}</span>` : ""}</td><td class="mono">${esc(h.dst_port ?? "—")}</td><td>${esc(h.service || "")}</td><td class="muted mono" style="font-size:11px">${esc((h.banner || "").slice(0, 80))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No honeypot hits yet — launch a <span class="mono">honeypot</span> scan on an agent to deploy a decoy sensor. Connection attempts to the decoy ports appear here (and source IPs become IOCs).</td></tr>`}
  </tbody></table>

  <div class="sec">&#129516; Memory dumps (RAM acquisition for forensics)</div>
  <table class="t"><thead><tr><th>When</th><th>Agent</th><th>Status</th><th>Tool</th><th>Size</th><th>Image path · SHA-256</th></tr></thead><tbody>
    ${memDumps.map((m) => `<tr><td class="muted" style="font-size:11px">${esc((m.finished_at || m.created_at || "").slice(0, 19))}</td><td>${esc(m.agent)}</td><td><span class="sev sev-${m.status === "completed" ? "info" : m.status === "error" || m.status === "no-tool" ? "medium" : "low"}">${esc(m.status || "?")}</span></td><td class="mono">${esc(m.tool || "—")}</td><td>${m.size_bytes ? fmtBytes(m.size_bytes) : "—"}</td><td class="muted mono" style="font-size:11px;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(m.sha256 || "")}">${esc(m.path || m.error || "—")}${m.sha256 ? `<br>${esc(String(m.sha256).slice(0, 32))}…` : ""}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No memory acquisitions yet — launch a <span class="mono">memdump</span> scan on an agent to capture its RAM for forensics (needs winpmem / avml on the endpoint). The image stays on the host for chain of custody; the manifest (size + SHA-256) lands here.</td></tr>`}
  </tbody></table>

  <div class="sec">&#129302; AI log hunts <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none">local AI analyses host logs (Sysmon / PowerShell / Security) for threats</span></div>
  <table class="t"><thead><tr><th>When</th><th>Agent</th><th>Source</th><th>Severity</th><th>Events</th><th>ATT&amp;CK</th><th>AI verdict</th></tr></thead><tbody>
    ${logHunts.map((l) => `<tr><td class="muted" style="font-size:11px">${esc((l.created_at || "").slice(0, 19))}</td><td>${esc(l.agent)}</td><td class="mono" style="font-size:11px">${esc(l.source || "")}</td><td><span class="sev sev-${["critical", "high"].includes(String(l.severity || "").toLowerCase()) ? "high" : String(l.severity || "").toLowerCase() === "medium" ? "medium" : "info"}">${esc(l.severity || "info")}</span></td><td>${esc(l.event_count ?? 0)}</td><td class="mono" style="font-size:10px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(l.techniques || "")}">${esc(l.techniques || "—")}</td><td class="muted" style="font-size:11px;max-width:420px">${esc(String(l.summary || "").slice(0, 200))}${l.hunt_id ? ` <a href="/?db=XTHREAT&table=HUNT&filterCol=HuntID&filterVal=${esc(l.hunt_id)}">→ hunt #${esc(l.hunt_id)}</a>` : ""}${l.ai_used ? "" : ` <span class="muted">(heuristic)</span>`}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">No AI log hunts yet — launch a <span class="mono">loghunt</span> scan on an agent. It collects Sysmon / PowerShell / Security events and the <b>local AI</b> hunts them for threats (mapping to ATT&amp;CK); anything suspicious spawns a TaHiTI hunt.</td></tr>`}
  </tbody></table>`;
}

// ── per-agent detail drawer ──────────────────────────────────────────────────────────────
const jbBadge = (s: string): string => `<span class="jb jb-${esc(s)}">${esc(s)}</span>`;
function flagSev(s: string): string { const v = (s || "info").toLowerCase(); return `fl-${["critical", "high", "medium", "low"].includes(v) ? v : "info"}`; }

function drawerHtml(d: any): string {
  const a = d.agent || {}; const jobs = (d.jobs || []) as any[]; const events = (d.events || []) as any[];
  const forensics = (d.forensics || []) as any[]; const oval = d.oval || {}; const orow = oval.row; const ofind = (oval.findings || []) as any[];
  return `<div class="drawer" onclick="event.stopPropagation()">
    <h2><span class="st st-${esc(a.freshness)}"><span class="dot"></span></span> ${esc(a.name)} <span class="x" id="dw-close">&times;</span></h2>
    <div class="kv"><span><b>Status</b> ${esc(a.freshness)}</span><span><b>Last seen</b> ${ago(a.minsAgo)}</span><span><b>OS</b> ${esc(a.os || "—")}${a.platform ? " / " + esc(a.platform) : ""}</span><span><b>Version</b> ${esc(a.version || "—")}</span><span><b>Address</b> ${esc(a.ip || a.fqdn || "—")}</span></div>

    <div class="sec" style="margin-top:14px">OVAL verdicts</div>
    ${orow ? `<div class="kv"><span><b>Last scan</b> ${esc((orow.lastScan || "").slice(0, 19) || "—")}</span><span><b>Vuln</b> ${orow.vuln || 0}</span><span><b>Compliance</b> ${orow.compliancePass || 0} pass / ${orow.complianceFail || 0} fail</span><span><b>Total verdicts</b> ${orow.total || 0}</span></div>
      <table class="t"><thead><tr><th>Class</th><th>Finding</th><th>Severity</th></tr></thead><tbody>${ofind.map((f) => `<tr><td class="mono">${esc(f.cls)}</td><td>${esc(f.title || "")}</td><td><span class="fl ${flagSev(f.severity)}">${esc(f.severity || "—")}</span></td></tr>`).join("") || `<tr><td colspan="3" class="muted">No failing findings.</td></tr>`}</tbody></table>`
      : `<div class="muted" style="font-size:12px">No OVAL scan results for this agent yet — launch an <b>oval</b> scan.</div>`}

    <div class="sec" style="margin-top:14px">Forensic triage <span class="muted" style="font-size:11px;text-transform:none">click a row to load its flags</span></div>
    <table class="t"><thead><tr><th>#</th><th>OS</th><th>Collected</th><th>Flags</th></tr></thead><tbody>
      ${forensics.map((t) => `<tr class="triage" data-triage="${t.TriageID}"><td class="muted">${t.TriageID}</td><td>${esc(t.host_os || "")}</td><td class="muted" style="font-size:12px">${esc((t.collected_at || "").slice(0, 19))}</td><td>${t.flag_count || 0}</td></tr><tr><td colspan="4" style="padding:0;border:0"><div id="tri-${t.TriageID}"></div></td></tr>`).join("") || `<tr><td colspan="4" class="muted">No forensic triage yet — launch a <b>forensics</b> scan.</td></tr>`}
    </tbody></table>

    <div class="sec" style="margin-top:14px">Job history (${jobs.length})</div>
    <table class="t"><thead><tr><th>#</th><th>Scan</th><th>Status</th><th>Result</th><th>When</th></tr></thead><tbody>
      ${jobs.map((j) => `<tr><td class="muted">${j.AgentJobID}</td><td class="mono">${esc(j.kind)}</td><td>${jbBadge(j.status)}</td><td class="muted" style="font-size:12px">${esc((j.result_summary || "").slice(0, 140))}</td><td class="muted" style="font-size:11px">${esc((j.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">No jobs.</td></tr>`}
    </tbody></table>

    <div class="sec" style="margin-top:14px">Events (${events.length})</div>
    <table class="t"><thead><tr><th>Type</th><th>Severity</th><th>Title</th><th>When</th></tr></thead><tbody>
      ${events.map((e) => `<tr><td class="mono">${esc(e.type)}</td><td><span class="sev sev-${esc(e.severity || "info")}">${esc(e.severity || "info")}</span></td><td>${esc(e.title || "")}</td><td class="muted" style="font-size:11px">${esc((e.created_at || "").slice(0, 19))}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No events.</td></tr>`}
    </tbody></table>
  </div>`;
}

async function openDetail(name: string): Promise<void> {
  let ov = document.getElementById("agent-drawer");
  if (!ov) { ov = document.createElement("div"); ov.id = "agent-drawer"; ov.className = "ovl"; document.body.appendChild(ov); }
  ov.innerHTML = `<div class="drawer"><div class="muted" style="padding:20px">Loading ${esc(name)}…</div></div>`;
  const close = (): void => { ov!.remove(); };
  ov.onclick = close;
  try {
    const d = await getJson(`/api/agents/${encodeURIComponent(name)}/detail`);
    ov.innerHTML = drawerHtml(d);
    document.getElementById("dw-close")?.addEventListener("click", close);
    ov.querySelectorAll<HTMLElement>(".triage").forEach((row) => {
      row.addEventListener("click", async () => {
        const id = row.dataset.triage; const tgt = document.getElementById(`tri-${id}`); if (!tgt) return;
        if (tgt.innerHTML) { tgt.innerHTML = ""; return; } // toggle
        tgt.innerHTML = `<div class="muted" style="padding:6px 9px;font-size:12px">loading…</div>`;
        try {
          const b = await getJson(`/api/forensic-triage?id=${encodeURIComponent(id || "")}`);
          const flags = (() => { try { const fb = typeof b.artifacts === "string" ? JSON.parse(b.artifacts) : b.artifacts; return Array.isArray(b.flags) ? b.flags : (fb && Array.isArray(fb.flags) ? fb.flags : []); } catch { return []; } })();
          tgt.innerHTML = `<div style="padding:6px 9px 10px">${flags.length ? flags.map((f: any) => `<div style="font-size:12px;margin:3px 0"><span class="fl ${flagSev(f.severity)}">${esc(f.severity || "info")}</span> <b>${esc(f.category || "")}</b> — ${esc(f.detail || "")}</div>`).join("") : `<span class="muted" style="font-size:12px">No flags in this bundle.</span>`}</div>`;
        } catch { tgt.innerHTML = `<div class="muted" style="padding:6px 9px;font-size:12px">failed to load bundle.</div>`; }
      });
    });
  } catch (e) { ov.innerHTML = `<div class="drawer"><span class="x" id="dw-close">&times;</span><div class="muted" style="padding:20px">Failed to load ${esc(name)}: ${esc((e as Error).message)}</div></div>`; document.getElementById("dw-close")?.addEventListener("click", close); }
}

function wire(): void {
  document.querySelectorAll<HTMLElement>("[data-detail]").forEach((el) => {
    el.addEventListener("click", () => { void openDetail(el.dataset.detail || ""); });
  });
  document.querySelectorAll<HTMLButtonElement>("button.run").forEach((b) => {
    b.addEventListener("click", async () => {
      const agent = b.dataset.agent || "";
      const sel = b.parentElement?.querySelector<HTMLSelectElement>("select.kind");
      const kind = sel?.value || "full";
      b.disabled = true;
      try {
        const r = await fetch("/api/agent-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ agent, kind }) });
        const d = await r.json().catch(() => ({}));
        toast(r.ok ? `Queued ${kind} on ${agent} (job #${d.id ?? "?"}) — runs at next check-in` : `Failed: ${d.error || r.status}`);
        if (r.ok) setTimeout(() => void load(), 700);
      } catch { toast("Failed to queue scan"); }
      finally { b.disabled = false; }
    });
  });
}

async function load(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { body.innerHTML = render(await getJson("/api/agents-overview")); wire(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load agents: ${esc((e as Error).message)} — admin access required.</div>`; }
}

document.addEventListener("DOMContentLoaded", () => { void load(); setInterval(() => void load(), 30000); });
