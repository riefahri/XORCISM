/** ai-detection.ts — client for AI runtime anomaly detection (/ai-detection). KPI cards + the
 *  detection table (extraction / jailbreak / drift) from /api/ai-detection. */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Det { id: number; system: string; day: string; type: string; severity: string; detail: string; evidence: string; status: string }
interface Data { summary: { monitored: number; detections: number; open: number; extraction: number; jailbreak: number; drift: number; critical: number }; detections: Det[] }

function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}

function render(d: Data): void {
  const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("AI systems monitored", s.monitored, "with usage telemetry"),
    card("Detections", s.detections, `${s.open} open`, s.detections ? "#fbbf24" : "#34d399"),
    card("Extraction", s.extraction, "volume spikes", s.extraction ? "#f87171" : "#34d399"),
    card("Jailbreak", s.jailbreak, "injection/refusal", s.jailbreak ? "#f87171" : "#34d399"),
    card("Drift", s.drift, "behavior change", s.drift ? "#fbbf24" : "#34d399"),
    card("High/critical", s.critical, "feed the CROC loop", s.critical ? "#f87171" : "#34d399"),
  ].join("");
  const rows = d.detections.map((x) => `<tr>
    <td><span class="sev sv-${esc((x.severity || "").toLowerCase())}">${esc(x.severity)}</span></td>
    <td><span class="ty">${esc(x.type)}</span></td>
    <td><span class="nm">${esc(x.system)}</span><div class="muted" style="font-size:11px">${esc(x.day)}</div></td>
    <td>${esc(x.detail)}<div class="muted" style="font-size:11px">${esc(x.evidence)}</div></td>
  </tr>`).join("");
  body.innerHTML = `<div class="cards">${cards}</div>
    <table class="t"><thead><tr><th>Sev</th><th>Type</th><th>AI system</th><th>Detection</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="4" class="muted" style="padding:16px;text-align:center">No anomalies — usage is within baseline. (Telemetry is ingested from your AI agent / gateway; register AI systems in the <a href="/ai-systems">inventory</a>.)</td></tr>`}</tbody></table>`;
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/ai-detection"); const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); render(d); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
document.addEventListener("DOMContentLoaded", () => { void load(); });
