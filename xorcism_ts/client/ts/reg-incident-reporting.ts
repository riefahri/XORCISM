/** reg-incident-reporting.ts — client for regulatory incident-reporting obligations. KPI cards +
 *  a deadline worklist (regulator × stage × due date) with a "mark submitted" action. */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Obl { incidentId: number; incident: string; severity: string; regulator: string; regLabel: string; appliesIf: string; stage: string; note: string; dueDate: string; daysLeft: number | null; status: string }
interface Data { summary: { incidents: number; obligations: number; overdue: number; dueSoon: number; submitted: number }; worklist: Obl[]; byRegulator: Record<string, number>; canAct: boolean }

function toast(m: string): void { const el = $("toast"); if (!el) return; el.textContent = m; el.className = "show"; setTimeout(() => { el.className = ""; }, 3200); }
function card(lbl: string, val: string | number, foot: string, color?: string): string {
  return `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
let DATA: Data | null = null;

function render(d: Data): void {
  DATA = d; const body = $("body"); if (!body) return;
  const s = d.summary;
  const cards = [
    card("Incidents in scope", s.incidents, "with reporting duties"),
    card("Obligations", s.obligations, "regulator × stage"),
    card("Overdue", s.overdue, "past the deadline", s.overdue ? "#f87171" : "#34d399"),
    card("Due soon", s.dueSoon, "< 24h", s.dueSoon ? "#fbbf24" : "#34d399"),
    card("Submitted", s.submitted, "cleared", "#34d399"),
  ].join("");
  const rows = d.worklist.map((o) => {
    const due = new Date(o.dueDate);
    const left = o.daysLeft == null ? "" : o.daysLeft < 0 ? `<span style="color:#f87171">${Math.abs(o.daysLeft)}d late</span>` : `${o.daysLeft}d left`;
    const act = d.canAct && !/submit|done|sent|filed|n.?a/i.test(o.status)
      ? `<button class="btn-sm2" data-inc="${o.incidentId}" data-reg="${esc(o.regulator)}" data-stage="${esc(o.stage)}" data-due="${esc(o.dueDate)}">Mark submitted</button>` : "";
    return `<tr>
      <td><span class="st st-${esc(o.status)}">${esc(o.status)}</span></td>
      <td><span class="reg">${esc(o.regulator)}</span><div class="muted" style="font-size:10px">${esc(o.regLabel)}</div></td>
      <td><span class="nm">${esc(o.stage)}</span>${o.note ? `<div class="muted" style="font-size:11px">${esc(o.note)}</div>` : ""}</td>
      <td>${esc(o.incident)}<div class="muted" style="font-size:11px">${esc(o.severity)} · applies if ${esc(o.appliesIf)}</div></td>
      <td style="white-space:nowrap">${due.toISOString().slice(0, 16).replace("T", " ")}<div class="muted" style="font-size:11px">${left}</div></td>
      <td>${act}</td>
    </tr>`;
  }).join("");
  body.innerHTML = `<div class="cards">${cards}</div>
    <table class="t"><thead><tr><th>Status</th><th>Regulator</th><th>Stage</th><th>Incident</th><th>Deadline</th><th></th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted" style="padding:16px;text-align:center">✓ No regulatory reporting obligations from current incidents.</td></tr>`}</tbody></table>`;
  body.querySelectorAll<HTMLElement>("[data-inc]").forEach((b) => b.addEventListener("click", () => void mark(b)));
}

async function mark(b: HTMLElement): Promise<void> {
  const body = { incidentId: Number(b.dataset.inc), regulator: b.dataset.reg, stage: b.dataset.stage, dueDate: b.dataset.due, status: "submitted" };
  try {
    const r = await fetch("/api/reg-incident-reporting/report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); render(d); toast("Marked submitted");
  } catch (e) { toast(`⚠️ ${(e as Error).message}`); }
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/reg-incident-reporting"); const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); render(d); }
  catch (e) { const b = $("body"); if (b) b.innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; }
}
document.addEventListener("DOMContentLoaded", () => { void load(); });
