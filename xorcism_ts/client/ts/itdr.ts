/**
 * itdr.ts — Identity Threat Detection & Response cockpit. Reads /api/itdr (which runs the detectors
 * then returns the dashboard): KPI strip, ATT&CK tactic coverage, and a detection worklist with a
 * per-detection status workflow and a "raise incident" action. Re-scan via /api/itdr/scan.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), t(key));

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
    <div class="tt">${fmt(c.techniques.length === 1 ? "itdr.technique" : "itdr.techniques", { n: c.techniques.length })} · ${esc(c.techniques.join(", "))}</div>
  </div>`;
}

function detectionRow(d: Detection): string {
  const sev = (d.Severity || "low").toLowerCase();
  const closed = /resolved|dismissed/i.test(d.Status);
  const opts = STATUSES.map((s) => `<option value="${s}"${s === d.Status ? " selected" : ""}>${t("itdr.st." + s)}</option>`).join("");
  const who = d.IdentityName ? `<span class="who">${esc(d.IdentityName)}</span>` : (d.SourceIP ? `<span class="who">${esc(d.SourceIP)}</span>` : "");
  const inc = d.IncidentAlertID
    ? `<span class="lk">&#10697; ${fmt("itdr.incidentN", { id: d.IncidentAlertID })}</span>`
    : `<button class="btnx inc" data-inc="${d.DetectionID}">${t("itdr.raiseIncident")}</button>`;
  return `<div class="de${closed ? " st-" + d.Status.toLowerCase() : ""}">
    <span class="sev sev-${sev}">${esc(d.Severity)}</span>
    <div class="body">
      <div class="dt">${esc(d.Title)}${who ? " — " : ""}${who}</div>
      <div class="ev">${esc(d.Evidence)}</div>
      <div class="resp"><b>${t("itdr.recommended")}</b> ${esc(d.ResponseAction)}</div>
      <div class="meta">
        <span class="chip att">${esc(d.Technique)} · ${esc(d.TechniqueName)}</span>
        <span class="chip">${esc(d.Tactic)}</span>
        ${d.Country ? `<span class="chip">${esc(d.Country)}</span>` : ""}
        ${d.LastSeen ? `<span class="chip">${fmt("itdr.last", { t: esc(String(d.LastSeen).slice(0, 16).replace("T", " ")) })}</span>` : ""}
        <span class="spacer" style="flex:1"></span>
        <button class="btnx ai" data-ai="${d.DetectionID}">&#129302; ${t("itdr.aiInvestigate")}</button>
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
      ${card(t("itdr.cOpen"), s.open, fmt("itdr.cOpenFoot", { n: s.total }), s.open > 0 ? "#fb923c" : "#4ade80")}
      ${card(t("itdr.cCritical"), s.critical, t("itdr.cCriticalFoot"), s.critical > 0 ? "#f87171" : "#4ade80")}
      ${card(t("itdr.cHigh"), s.high, t("itdr.cHighFoot"), s.high > 0 ? "#fb923c" : "#4ade80")}
      ${card(t("itdr.cAtRisk"), s.identitiesAtRisk, t("itdr.cAtRiskFoot"), s.identitiesAtRisk > 0 ? "#fbbf24" : "#4ade80")}
      ${card(t("itdr.cCoverage"), s.techniquesCovered, fmt(s.tacticsCovered === 1 ? "itdr.cCoverageFoot1" : "itdr.cCoverageFoot", { n: s.tacticsCovered }), "#a78bfa")}
      ${card(t("itdr.cMttr"), s.mttrHours != null ? `${s.mttrHours}h` : "—", t("itdr.cMttrFoot"))}
      ${card(t("itdr.cIncidents"), s.raisedIncidents, t("itdr.cIncidentsFoot"), "#7dd3fc")}
    </div>
    <div class="it-section">${t("itdr.secCoverage")}<span class="spacer"></span>
      <button class="barbtn" id="rescan">&#8635; ${t("itdr.rescan")}</button></div>
    ${d.coverage.length ? `<div class="tac-strip">${d.coverage.map(tacticCard).join("")}</div>`
      : `<div class="muted" style="padding:10px">${t("itdr.noCoverage")}</div>`}
    <div class="it-section">${t("itdr.secWorklist")} (${d.worklist.length})</div>
    ${d.worklist.length ? `<div class="dl">${d.worklist.map(detectionRow).join("")}</div>`
      : `<div class="dl"><div class="de"><div class="body muted">${t("itdr.noDetections")}</div></div></div>`}`;
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
      if (!r.ok) { toast(j.error || t("itdr.scanFailed")); return; }
      toast(fmt("itdr.scanDone", { n: j.created, m: j.updated }));
      void load();
    } finally { rescan.removeAttribute("disabled"); }
  };
  document.querySelectorAll<HTMLSelectElement>("select.stsel").forEach((sel) => {
    sel.onchange = async () => {
      const id = sel.getAttribute("data-st");
      const status = sel.value;
      let notes: string | undefined;
      if (status === "dismissed") { const n = prompt(t("itdr.dismissReason")); notes = n ?? undefined; }
      const r = await fetch(`/api/itdr/detection/${id}/status`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, notes }),
      });
      if (!r.ok) { const j = await r.json().catch(() => ({})); toast(j.error || t("itdr.updateFailed")); return; }
      toast(fmt("itdr.statusSet", { id: String(id), s: t("itdr.st." + status) }));
      void load();
    };
  });
  document.querySelectorAll<HTMLButtonElement>("button[data-ai]").forEach((b) => {
    b.onclick = async () => {
      const id = b.getAttribute("data-ai")!;
      const panel = document.getElementById(`ai-${id}`)!;
      if (panel.style.display !== "none" && panel.dataset.loaded) { panel.style.display = "none"; panel.dataset.loaded = ""; return; }
      panel.style.display = "block";
      panel.innerHTML = `<div class="muted" style="padding:6px">${t("itdr.investigating")}</div>`;
      b.setAttribute("disabled", "1");
      try {
        const r = await fetch(`/api/itdr/detection/${id}/investigate`, { method: "POST" });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) { panel.innerHTML = `<div class="muted" style="padding:6px">${esc(j.error || t("itdr.failed"))}</div>`; return; }
        panel.innerHTML = mdLite(String(j.content || "")) +
          `<div style="font-size:10px;color:#64748b;margin-top:6px">${t("itdr.model")}: ${esc(j.model || "?")}${j.offline ? " · " + t("itdr.deterministic") : ""}</div>`;
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
      if (!r.ok) { toast(j.error || t("itdr.raiseFailed")); b.removeAttribute("disabled"); return; }
      toast(fmt("itdr.incidentRaised", { id: String(j.alertId) }));
      void load();
    };
  });
}

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/itdr");
    if (r.status === 403) { $("it-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${t("itdr.noAccess")}</div>`; return; }
    if (!r.ok) throw new Error(String(r.status));
    render(await r.json() as Dash);
  } catch (e) {
    $("it-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">${fmt("itdr.loadFailed", { e: esc((e as Error).message) })}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
