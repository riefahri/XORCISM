/**
 * ai-sbom.ts — AI SBOM minimum-elements conformance (/ai-sbom), CISA/G7.
 * List AI-SBOM instances + per-instance 50-element coverage editor + completeness rollup.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const scoreColor = (n: number): string => (n >= 80 ? "#10b981" : n >= 50 ? "#fbbf24" : n >= 25 ? "#fb923c" : "#ef4444");

interface Sb { id: number; name: string; producer: string; version: string; format: string; status: string; completeness: number; present: number; missing: number; applicable: number; }
interface Elem { id: number; cluster: string; clusterName: string; element: string; description: string; example: string; status: string; value: string; notes: string; }

function card(lbl: string, val: string, foot: string, color?: string, cls = "as-card"): string {
  return `<div class="${cls}"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
}

// ── list view ──────────────────────────────────────────────────────────────
async function loadList(): Promise<void> {
  let d: { catalogSize: number; sboms: Sb[] };
  try { const r = await fetch("/api/ai-sbom"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("as-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }

  const avg = d.sboms.length ? Math.round(d.sboms.reduce((a, s) => a + s.completeness, 0) / d.sboms.length) : 0;
  const cards = [
    card("AI SBOMs", String(d.sboms.length), "AI systems documented"),
    card("Avg completeness", `${avg}%`, "against the 50 minimum elements", scoreColor(avg), "as-card as-score"),
    card("Minimum elements", String(d.catalogSize), "7 clusters · CISA/G7"),
  ].join("");

  const form = `<div class="imp">
      <label>AI system name<input id="as-name" placeholder="e.g. Customer-support RAG assistant" style="min-width:240px"></label>
      <label>Producer<input id="as-prod" placeholder="vendor / team" style="width:150px"></label>
      <label>Version<input id="as-ver" placeholder="1.0" style="width:80px"></label>
      <label>Format<input id="as-fmt" placeholder="CycloneDX 1.6" style="width:120px"></label>
      <button class="as-go" id="as-create">Add AI SBOM</button>
      ${d.sboms.length === 0 ? `<button class="as-go alt" id="as-seed">Seed demo</button>` : ""}
      <span id="as-stat" class="muted" style="font-size:12px"></span>
    </div>`;

  const rows = d.sboms.length ? `<table class="as"><thead><tr><th>AI system</th><th>Producer</th><th>Format</th><th>Completeness</th><th>Present</th><th>Missing</th></tr></thead><tbody>${d.sboms.map((s) => `<tr class="sb" data-id="${s.id}">
      <td><b style="color:#e2e8f0">${esc(s.name)}</b>${s.version ? ` <span class="muted">v${esc(s.version)}</span>` : ""}</td>
      <td><span class="muted">${esc(s.producer || "—")}</span></td>
      <td><span class="muted">${esc(s.format || "—")}</span></td>
      <td><b style="color:${scoreColor(s.completeness)}">${s.completeness}%</b></td>
      <td>${s.present}/${s.applicable}</td>
      <td>${s.missing ? `<span class="sev-High">${s.missing}</span>` : "0"}</td>
    </tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:12px 0">No AI SBOMs yet — add one above (or seed a demo).</div>`;

  $("as-body").innerHTML = `<div class="as-cards">${cards}</div>${form}
    <div class="as-section">AI systems (${d.sboms.length})</div>${rows}
    <div class="legend">CISA / G7 "Software Bill of Materials for AI — Minimum Elements" (May 2026): 7 clusters, 50 elements, supplemental to the regular SBOM minimum elements.</div>`;

  ($("as-create") as HTMLButtonElement).onclick = createSbom;
  const seed = document.getElementById("as-seed") as HTMLButtonElement | null;
  if (seed) seed.onclick = () => seedDemo(seed);
  document.querySelectorAll<HTMLElement>("tr.sb").forEach((tr) => { tr.onclick = () => loadDetail(Number(tr.dataset.id)); });
}

async function createSbom(): Promise<void> {
  const name = ($("as-name") as HTMLInputElement).value.trim();
  const stat = $("as-stat");
  if (!name) { stat.textContent = "name required"; return; }
  stat.textContent = "Creating…";
  try {
    const body = { name, producer: ($("as-prod") as HTMLInputElement).value, version: ($("as-ver") as HTMLInputElement).value, format: ($("as-fmt") as HTMLInputElement).value };
    const r = await fetch("/api/ai-sbom", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    loadDetail(d.id);
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
}

async function seedDemo(btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true; btn.textContent = "Seeding…";
  try { const r = await fetch("/api/ai-sbom/seed", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); if (r.ok) { await loadList(); return; } } catch { /* */ }
  btn.disabled = false; btn.textContent = "Seed demo";
}

// ── detail view ────────────────────────────────────────────────────────────
async function loadDetail(id: number): Promise<void> {
  let d: { statuses: string[]; sbom: any; elements: Elem[]; byCluster: any[]; summary: any; worklist: any[] };
  try { const r = await fetch(`/api/ai-sbom?id=${id}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("as-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  const cards = [
    card("Completeness", `${s.overall}%`, `vs ${s.applicable} applicable elements`, scoreColor(s.overall), "as-card as-score"),
    card("Present", String(s.present), "fully documented", "#34d399"),
    card("Partial", String(s.partial), "partially documented", s.partial ? "#fbbf24" : "#64748b"),
    card("Missing", String(s.missing), "not documented", s.missing ? "#ef4444" : "#34d399"),
    card("N/A", String(s.na), "not applicable"),
  ].join("");

  const clusters = d.byCluster.map((c) => `<div class="fn">
      <div class="nm">${esc(c.name)} <span class="c">${esc(c.code)}</span></div>
      <div class="track"><i style="width:${c.completeness}%;background:${scoreColor(c.completeness)}"></i></div>
      <div class="meta"><b style="color:#e2e8f0">${c.completeness}%</b> · ${c.present}/${c.applicable}</div>
    </div>`).join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev-${esc(w.severity)}">${esc(w.severity)}</span> · <span class="muted">${esc(w.cluster)}</span> — ${esc(w.element)}</li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">No missing elements — full minimum-element coverage.</div>`;

  const opt = (cur: string): string => d.statuses.map((st) => `<option${st === cur ? " selected" : ""}>${esc(st)}</option>`).join("");
  let table = `<table class="as"><thead><tr><th>Element</th><th>Description</th><th>Coverage</th></tr></thead><tbody>`;
  for (const c of d.byCluster) {
    table += `<tr class="fhead"><td colspan="3">${esc(c.name)} (${esc(c.code)}) — ${c.completeness}% · ${c.present}/${c.applicable}</td></tr>`;
    for (const e of d.elements.filter((x) => x.cluster === c.code)) {
      table += `<tr>
        <td><b style="color:#e2e8f0">${esc(e.element)}</b></td>
        <td>${esc(e.description)}${e.example ? `<div class="ex">e.g. ${esc(e.example)}</div>` : ""}</td>
        <td><select class="stsel" data-el="${e.id}">${opt(e.status)}</select></td>
      </tr>`;
    }
  }
  table += `</tbody></table>`;

  $("as-body").innerHTML = `<div class="back" id="as-back">← All AI SBOMs</div>
    <h2 style="font-size:17px;margin:8px 0 2px">${esc(d.sbom.name)} <span class="muted" style="font-size:13px;font-weight:400">${esc(d.sbom.producer)}${d.sbom.version ? " · v" + esc(d.sbom.version) : ""}${d.sbom.format ? " · " + esc(d.sbom.format) : ""}</span></h2>
    <div class="as-cards" style="margin-top:10px">${cards}</div>
    <div class="as-section">Completeness by cluster</div>${clusters}
    <div class="as-section">Missing minimum elements (${d.worklist.length})</div>${work}
    <div class="as-section">Minimum elements — coverage</div>${table}`;

  ($("as-back") as HTMLElement).onclick = () => void loadList();
  document.querySelectorAll<HTMLSelectElement>("select.stsel").forEach((sel) => {
    sel.onchange = async () => {
      await fetch(`/api/ai-sbom/${id}/coverage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ elementId: Number(sel.dataset.el), status: sel.value }) });
      loadDetail(id); // refresh rollups
    };
  });
}

document.addEventListener("DOMContentLoaded", () => { void loadList(); });
