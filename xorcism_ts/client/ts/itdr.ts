/**
 * itdr.ts — Identity Threat Detection & Response cockpit. Reads /api/itdr (which runs the detectors
 * then returns the dashboard): KPI strip, ATT&CK tactic coverage, and a detection worklist with a
 * per-detection status workflow and a "raise incident" action. Re-scan via /api/itdr/scan.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }

/** Minimal, safe Markdown → HTML (escapes first, then applies headings/bold/italic/bullets). */
function mdLite(md: string): string {
  const lines = esc(md).split("\n");
  const out: string[] = []; let inList = false;
  const inline = (s: string) => s.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/(^|[^*])\*([^*]+)\*/g, "$1<i>$2</i>").replace(/_([^_]+)_/g, "<i>$1</i>");
  for (let ln of lines) {
    if (/^\s*[-*]\s+/.test(ln)) { if (!inList) { out.push('<ul style="margin:4px 0 4px 16px;padding:0">'); inList = true; } out.push(`<li style="margin:2px 0">${inline(ln.replace(/^\s*[-*]\s+/, ""))}</li>`); continue; }
    if (inList) { out.push("</ul>"); inList = false; }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { out.push(`<div style="font-weight:700;color:#e7ebf3;font-size:${14 - h[1].length}px;margin:8px 0 3px">${inline(h[2])}</div>`); continue; }
    if (ln.trim() === "") { out.push('<div style="height:5px"></div>'); continue; }
    out.push(`<div style="margin:2px 0">${inline(ln)}</div>`);
  }
  if (inList) out.push("</ul>");
  return out.join("");
}

interface Detection {
  DetectionID: number; RuleKey: string; Title: string; Severity: string; Tactic: string; Technique: string;
  TechniqueName: string; IdentityName: string | null; SourceIP: string | null; Country: string | null;
  Evidence: string; EventCount: number; Status: string; ResponseAction: string;
  FirstSeen: string | null; LastSeen: string | null; IncidentAlertID: number | null; Notes: string | null;
}
interface Coverage { tactic: string; count: number; techniques: string[]; topSeverity: string }
interface Dash {
  summary: { total: number; open: number; critical: number; high: number; medium: number; low: number;
    identitiesAtRisk: number; tacticsCovered: number; techniquesCovered: number; mttrHours: number | null; raisedIncidents: number };
  coverage: Coverage[]; worklist: Detection[]; detections: Detection[];
}

const SEV_COLOR: Record<string, string> = { critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#60a5fa" };
const STATUSES = ["open", "investigating", "contained", "resolved", "dismissed"];

const card = (lbl: string, val: string | number, foot: string, color?: string): string =>
  `<div class="it-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(String(val))}</div><div class="foot">${esc(foot)}</div></div>`;

function tacticCard(c: Coverage): string {
  const col = SEV_COLOR[c.topSeverity] || "#60a5fa";
  return `<div class="tac" style="border-left-color:${col}">
    <div class="tn">${esc(c.tactic)}</div>
    <div class="tc" style="color:${col}">${c.count}</div>
    <div class="tt">${c.techniques.length} technique${c.techniques.length === 1 ? "" : "s"} · ${esc(c.techniques.join(", "))}</div>
  </div>`;
}

function detectionRow(d: Detection): string {
  const sev = (d.Severity || "low").toLowerCase();
  const closed = /resolved|dismissed/i.test(d.Status);
  const opts = STATUSES.map((s) => `<option value="${s}"${s === d.Status ? " selected" : ""}>${s}</option>`).join("");
  const who = d.IdentityName ? `<span class="who">${esc(d.IdentityName)}</span>` : (d.SourceIP ? `<span class="who">${esc(d.SourceIP)}</span>` : "");
  const inc = d.IncidentAlertID
    ? `<span class="lk">&#10697; incident #${d.IncidentAlertID}</span>`
    : `<button class="btnx inc" data-inc="${d.DetectionID}">Raise incident</button>`;
  return `<div class="de${closed ? " st-" + d.Status.toLowerCase() : ""}">
    <span class="sev sev-${sev}">${esc(d.Severity)}</span>
    <div class="body">
      <div class="dt">${esc(d.Title)}${who ? " — " : ""}${who}</div>
      <div class="ev">${esc(d.Evidence)}</div>
      <div class="resp"><b>Recommended response:</b> ${esc(d.ResponseAction)}</div>
      <div class="meta">
        <span class="chip att">${esc(d.Technique)} · ${esc(d.TechniqueName)}</span>
        <span class="chip">${esc(d.Tactic)}</span>
        ${d.Country ? `<span class="chip">${esc(d.Country)}</span>` : ""}
        ${d.LastSeen ? `<span class="chip">last ${esc(String(d.LastSeen).slice(0, 16).replace("T", " "))}</span>` : ""}
        <span class="spacer" style="flex:1"></span>
        <button class="btnx ai" data-ai="${d.DetectionID}">&#129302; AI investigate</button>
        <select class="stsel" data-st="${d.DetectionID}">${opts}</select>
        ${inc}
      </div>
      <div class="ai-panel" id="ai-${d.DetectionID}" style="display:none"></div>
    </div>
  </div>`;
}

function render(d: Dash): void {
  const s = d.summary;
  const html = `
    <div class="it-cards">
      ${card("Open detections", s.open, `${s.total} all-time`, s.open > 0 ? "#fb923c" : "#4ade80")}
      ${card("Critical", s.critical, "open · ATO-grade", s.critical > 0 ? "#f87171" : "#4ade80")}
      ${card("High", s.high, "open", s.high > 0 ? "#fb923c" : "#4ade80")}
      ${card("Identities at risk", s.identitiesAtRisk, "with an open detection", s.identitiesAtRisk > 0 ? "#fbbf24" : "#4ade80")}
      ${card("ATT&CK coverage", s.techniquesCovered, `${s.tacticsCovered} tactic${s.tacticsCovered === 1 ? "" : "s"}`, "#a78bfa")}
      ${card("MTTR", s.mttrHours != null ? `${s.mttrHours}h` : "—", "mean time to resolve")}
      ${card("Incidents raised", s.raisedIncidents, "→ SOC queue", "#7dd3fc")}
    </div>
    <div class="it-section">ATT&amp;CK tactic coverage<span class="spacer"></span>
      <button class="barbtn" id="rescan">&#8635; Re-scan now</button></div>
    ${d.coverage.length ? `<div class="tac-strip">${d.coverage.map(tacticCard).join("")}</div>`
      : `<div class="muted" style="padding:10px">No open detections — no ATT&amp;CK techniques observed in the window.</div>`}
    <div class="it-section">Detection worklist (${d.worklist.length})</div>
    ${d.worklist.length ? `<div class="dl">${d.worklist.map(detectionRow).join("")}</div>`
      : `<div class="dl"><div class="de"><div class="body muted">No open identity-threat detections. Telemetry is ingested via the entra-signin / okta-signin connectors into IDENTITYSIGNIN; posture is read from the IDENTITY inventory.</div></div></div>`}`;
  $("it-body").innerHTML = html;
  wire();
}

function wire(): void {
  const rescan = document.getElementById("rescan");
  if (rescan) rescan.onclick = async () => {
    rescan.setAttribute("disabled", "1");
    try {
      const r = await fetch("/api/itdr/scan", { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { toast(j.error || "Scan failed"); return; }
      toast(`Scan complete · ${j.created} new, ${j.updated} updated`);
      void load();
    } finally { rescan.removeAttribute("disabled"); }
  };
  document.querySelectorAll<HTMLSelectElement>("select.stsel").forEach((sel) => {
    sel.onchange = async () => {
      const id = sel.getAttribute("data-st");
      const status = sel.value;
      let notes: string | undefined;
      if (status === "dismissed") { const n = prompt("Reason for dismissing (optional):"); notes = n ?? undefined; }
      const r = await fetch(`/api/itdr/detection/${id}/status`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, notes }),
      });
      if (!r.ok) { const j = await r.json().catch(() => ({})); toast(j.error || "Update failed"); return; }
      toast(`Detection #${id} → ${status}`);
      void load();
    };
  });
  document.querySelectorAll<HTMLButtonElement>("button[data-ai]").forEach((b) => {
    b.onclick = async () => {
      const id = b.getAttribute("data-ai")!;
      const panel = document.getElementById(`ai-${id}`)!;
      if (panel.style.display !== "none" && panel.dataset.loaded) { panel.style.display = "none"; panel.dataset.loaded = ""; return; }
      panel.style.display = "block";
      panel.innerHTML = `<div class="muted" style="padding:6px">Investigating…</div>`;
      b.setAttribute("disabled", "1");
      try {
        const r = await fetch(`/api/itdr/detection/${id}/investigate`, { method: "POST" });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) { panel.innerHTML = `<div class="muted" style="padding:6px">${esc(j.error || "Failed")}</div>`; return; }
        panel.innerHTML = mdLite(String(j.content || "")) +
          `<div style="font-size:10px;color:#64748b;margin-top:6px">model: ${esc(j.model || "?")}${j.offline ? " · deterministic" : ""}</div>`;
        panel.dataset.loaded = "1";
      } finally { b.removeAttribute("disabled"); }
    };
  });
  document.querySelectorAll<HTMLButtonElement>("button[data-inc]").forEach((b) => {
    b.onclick = async () => {
      const id = b.getAttribute("data-inc");
      b.setAttribute("disabled", "1");
      const r = await fetch(`/api/itdr/detection/${id}/incident`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { toast(j.error || "Failed to raise incident"); b.removeAttribute("disabled"); return; }
      toast(`Incident #${j.alertId} raised`);
      void load();
    };
  });
}

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/itdr");
    if (r.status === 403) { $("it-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">You don't have access to identity data.</div>`; return; }
    if (!r.ok) throw new Error(String(r.status));
    render(await r.json() as Dash);
  } catch (e) {
    $("it-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load ITDR cockpit (${esc((e as Error).message)}).</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => { void load(); });
