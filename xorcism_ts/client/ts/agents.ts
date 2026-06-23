/**
 * agents.ts — client for /agents. XOR agent fleet management: inventory (status / last-seen /
 * platform), recent jobs and events, and per-agent tasking (launch a scan → POST /api/agent-scan).
 * Consumes the existing agent admin API (/api/agents-overview, /api/agent-scan).
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

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
  kinds = d.kinds && d.kinds.length ? d.kinds : kinds;
  const kindOpts = kinds.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
  return `
  <div class="cards">
    <div class="card"><div class="lbl">Agents</div><div class="val">${s.total || 0}</div><div class="foot">${s.online || 0} online · ${s.idle || 0} idle · ${s.offline || 0} offline</div></div>
    <div class="card"><div class="lbl">Online now</div><div class="val" style="color:#22c55e">${s.online || 0}</div><div class="foot">checked in &le; 5 min</div></div>
    <div class="card"><div class="lbl">Jobs pending</div><div class="val" style="color:#60a5fa">${s.jobsPending || 0}</div><div class="foot">${s.jobsTotal || 0} in recent history</div></div>
    <div class="card"><div class="lbl">Events</div><div class="val">${s.events || 0}</div><div class="foot">recent agent reports</div></div>
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
