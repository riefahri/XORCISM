/**
 * sla.ts — Incident SLA / RTO view (/incident-sla).
 * Each incident's Duration is measured against two recovery targets on the affected
 * asset: the resolution SLA (ASSET.SLAResolutionHours) and the BIA RTO (BIAENTRY.RTO).
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

type SlaStatus = "met" | "breached" | "no-target" | "no-duration";
interface SlaRow {
  incidentId: number; incidentName: string; severity: string | null;
  assetId: number; assetName: string; duration: number | null;
  slaHours: number | null; slaStatus: SlaStatus; slaOverage: number | null;
  rtoHours: number | null; rtoStatus: SlaStatus; rtoOverage: number | null;
}
interface TargetSummary { evaluated: number; met: number; breached: number; breachRate: number; noTarget: number; avg: number | null; }
interface SlaView {
  rows: SlaRow[];
  summary: { links: number; noDuration: number; avgDuration: number | null; sla: TargetSummary; rto: TargetSummary };
}

const STATUS_LABEL: Record<SlaStatus, string> = { met: "Met", breached: "Breached", "no-target": "—", "no-duration": "No duration" };
const fh = (v: number | null): string => (v == null ? "—" : `${Math.round(v * 10) / 10} h`);

function statusCell(status: SlaStatus, target: number | null, overage: number | null): string {
  if (status === "no-target") return `<td class="num muted">—</td><td><span class="badge b-no-target">no target</span></td>`;
  const over = overage == null ? "" : overage > 0
    ? ` <span class="over-late">+${fh(overage)}</span>` : ` <span class="over-ok">${fh(overage)}</span>`;
  const badge = status === "no-duration" ? `<span class="badge b-no-duration">no duration</span>`
    : `<span class="badge b-${status}">${STATUS_LABEL[status]}</span>`;
  return `<td class="num">${fh(target)}</td><td>${badge}${over}</td>`;
}

function rowHtml(r: SlaRow): string {
  return `<tr>
    <td><a href="/?db=XINCIDENT&table=INCIDENT">${esc(r.incidentName)}</a></td>
    <td class="sev">${esc(r.severity || "—")}</td>
    <td><a href="/?db=XORCISM&table=ASSET">${esc(r.assetName)}</a></td>
    <td class="num">${fh(r.duration)}</td>
    ${statusCell(r.slaStatus, r.slaHours, r.slaOverage)}
    ${statusCell(r.rtoStatus, r.rtoHours, r.rtoOverage)}
  </tr>`;
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="sl-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rateColor(rate: number, evaluated: number): string {
  if (!evaluated) return "var(--text-muted)";
  return rate === 0 ? "#34d399" : rate < 0.25 ? "#fbbf24" : "#f87171";
}

async function load(): Promise<void> {
  let d: SlaView;
  try { const r = await fetch("/api/sla/incidents"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("sl-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;
  const slaPct = Math.round(s.sla.breachRate * 100);
  const rtoPct = Math.round(s.rto.breachRate * 100);

  const cards = [
    card("SLA breach rate", s.sla.evaluated ? `${slaPct}%` : "—", `${s.sla.breached} of ${s.sla.evaluated} vs asset SLA`, rateColor(s.sla.breachRate, s.sla.evaluated)),
    card("RTO breach rate", s.rto.evaluated ? `${rtoPct}%` : "—", `${s.rto.breached} of ${s.rto.evaluated} vs BIA RTO`, rateColor(s.rto.breachRate, s.rto.evaluated)),
    card("Avg duration", fh(s.avgDuration), `SLA ${fh(s.sla.avg)} · RTO ${fh(s.rto.avg)}`),
    card("Links", String(s.links), `${s.noDuration} without a duration`),
  ].join("");

  const body = d.rows.length
    ? `<table class="sl"><thead><tr>
        <th>Incident</th><th>Severity</th><th>Asset</th>
        <th style="text-align:right">Duration</th>
        <th style="text-align:right">SLA target</th><th>SLA</th>
        <th style="text-align:right">RTO target</th><th>RTO</th>
       </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`
    : `<div class="muted" style="padding:24px;text-align:center">No incident↔asset links yet.
        Link incidents to assets (INCIDENTFORASSET), then set an SLA on the asset and/or an RTO in its BIA entry.</div>`;

  $("sl-body").innerHTML = `<div class="sl-cards">${cards}</div>${body}
    <div class="legend">↳ Duration uses <code>INCIDENT.Duration</code> when set, otherwise it is derived from
      <code>start_datetime → end_datetime</code>. SLA target = <code>ASSET.SLAResolutionHours</code>;
      RTO target = <code>BIAENTRY.RTO</code> (strictest BIA entry for the asset). All in hours.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
