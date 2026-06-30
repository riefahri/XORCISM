/**
 * sprs.ts — SPRS / NIST 800-171 self-assessment cockpit (/sprs).
 * Renders the SPRS score gauge + per-family rollup + the 110 requirements with an inline status select
 * (and editable weight), from /api/sprs. Each change POSTs to /api/sprs/status and recomputes the score.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
async function getJSON(u: string): Promise<any> { const r = await fetch(u, { credentials: "same-origin" }); if (!r.ok) throw new Error(String(r.status)); return r.json(); }
async function postJSON(u: string, b?: any): Promise<any> { const r = await fetch(u, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json().catch(() => ({})); }

const scoreColor = (n: number): string => (n >= 88 ? "#22c55e" : n >= 0 ? "#fbbf24" : "#ef4444");
const pctColor = (n: number): string => (n >= 80 ? "#22c55e" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");
let STATUSES: string[] = ["implemented", "partial", "not-implemented", "na", "poam"];
function card(lbl: string, val: string, foot: string, color?: string, cls = "sp-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

async function load(): Promise<void> {
  let d: any;
  try { d = await getJSON("/api/sprs"); } catch (e) { $("sp-body").innerHTML = `<div class="muted" style="padding:20px">Failed to load: ${esc(String(e))}</div>`; return; }
  STATUSES = d.statuses || STATUSES;
  const s = d.summary;
  const cards = [
    card("SPRS score", `${s.score}`, `max ${s.max} · floor ${s.floor}`, scoreColor(s.score), "sp-card sp-score"),
    card("Implemented", `${s.met}/${s.assessable}`, "of assessable", pctColor(s.metPct)),
    card("Implementation", `${s.metPct}%`, "assessable met", pctColor(s.metPct)),
    card("POA&M", `${s.poam}`, "planned (still deducted)", s.poam ? "#fbbf24" : "#94a3b8"),
    card("Not implemented", `${s.notImplemented}`, "gaps", s.notImplemented ? "#f87171" : "#22c55e"),
    card("Points deducted", `${s.deducted}`, `of ${s.totalWeight}`, "#fb923c"),
  ].join("");

  const fam = (d.families || []).map((f: any) => `<div class="fam">
    <div class="nm">${esc(f.name)} <span class="c">${esc(f.code)}</span></div>
    <div class="track"><i style="width:${f.metPct}%;background:${pctColor(f.metPct)}"></i></div>
    <div class="meta"><b style="color:#e2e8f0">${f.met}/${f.total}</b> met · −${f.deducted}</div>
  </div>`).join("");

  // requirements grouped by family
  const byFam: Record<string, any[]> = {};
  for (const r of d.requirements) (byFam[r.family] ||= []).push(r);
  let rows = "";
  for (const f of d.families) {
    rows += `<tr class="fhead"><td colspan="5">${esc(f.code)} · ${esc(f.name)} — ${f.met}/${f.total} met</td></tr>`;
    for (const r of (byFam[f.code] || [])) {
      rows += `<tr>
        <td class="rid">${esc(r.id)}</td>
        <td class="w${r.weight}">${r.weight}</td>
        <td><select class="in st" data-id="${esc(r.id)}">${STATUSES.map((o) => `<option value="${o}"${r.status === o ? " selected" : ""}>${o}</option>`).join("")}</select></td>
        <td class="${r.deduction ? "ded" : "ded0"}">${r.deduction ? "−" + r.deduction : "0"}</td>
        <td class="muted">${esc(r.notes || "")}</td></tr>`;
    }
  }

  $("sp-body").innerHTML = `
    <div class="sp-cards">${cards}</div>
    <div class="row" style="margin-bottom:8px"><span class="muted" style="font-size:12px">Status: <b>${esc(s.level)}</b>. Set each requirement below — the score recomputes live.</span>
      <button class="btn sec" id="sp-seed" style="margin-left:auto">Seed demo profile</button></div>
    <div class="sp-sec">Per-family coverage</div>
    <div id="sp-fam">${fam}</div>
    <div class="sp-sec">Requirements (110)</div>
    <div style="overflow-x:auto"><table class="tt"><thead><tr><th>Req</th><th>Wt</th><th>Status</th><th>Pts</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div>`;

  $("sp-seed").onclick = async () => { await postJSON("/api/sprs/seed"); load(); };
  document.querySelectorAll<HTMLSelectElement>("select.st").forEach((sel) => {
    sel.onchange = async () => { await postJSON("/api/sprs/status", { reqId: sel.dataset.id, status: sel.value }); load(); };
  });
}

document.addEventListener("DOMContentLoaded", load);
