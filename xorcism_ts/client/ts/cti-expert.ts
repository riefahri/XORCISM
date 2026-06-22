/**
 * cti-expert.ts — client for the CTI-Expert AI OSINT investigation cockpit (/cti-expert).
 * Dashboard (KPIs, 4-phase flow, technique catalogue, recent investigations) + an "Investigate"
 * form that POSTs a target to the local-AI analyst and renders the graded INTSUM.
 */
const $ = (id: string): HTMLElement | null => document.getElementById(id);
const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

/** Minimal, safe Markdown → HTML (escape first, then a few inline/block rules). */
function md(src: string): string {
  const lines = esc(src).split(/\r?\n/);
  let html = "", inList = false;
  for (let ln of lines) {
    ln = ln.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    const h = ln.match(/^(#{2,3})\s+(.*)/);
    const li = ln.match(/^\s*[-*]\s+(.*)/);
    if (li) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${li[1]}</li>`; continue; }
    if (inList) { html += "</ul>"; inList = false; }
    if (h) html += `<h3>${h[2]}</h3>`;
    else if (ln.trim()) html += `<p>${ln}</p>`;
  }
  if (inList) html += "</ul>";
  return html;
}

const gaugeColor = (n: number): string => n >= 80 ? "#7f1d1d" : n >= 55 ? "#78350f" : n >= 30 ? "#1e3a5f" : "#1e2133";

async function getJson(url: string): Promise<any> { const r = await fetch(url); if (!r.ok) throw new Error(String(r.status)); return r.json(); }

function toast(msg: string): void {
  const t = $("toast"); if (!t) return;
  t.textContent = msg; t.className = "show";
  setTimeout(() => { t.className = ""; }, 3200);
}

function renderInvestigation(inv: any): string {
  const findings = (inv.findings || []) as { technique: string; phase: string; finding: string; reliability: string; severity: string }[];
  const obs = (inv.observables || []) as { type: string; value: string }[];
  const recs = (inv.recommendations || []) as string[];
  const tags = (inv.attackTags || []) as string[];
  const aiBadge = inv.offline ? `<span class="ai-badge" title="${esc(inv.model)}">methodology scaffold (local AI offline)</span>` : `<span class="ai-badge">🤖 ${esc(inv.model)}</span>`;
  return `
  <div class="sec">Investigation result <span class="spacer"></span>${aiBadge}</div>
  <div class="grid2" style="margin-bottom:14px">
    <div class="panel" style="display:flex;gap:14px;align-items:center">
      <div class="gauge" style="background:${gaugeColor(inv.exposureScore)}">${inv.exposureScore}</div>
      <div>
        <div class="nm" style="font-size:15px">${esc(inv.target)} <span class="muted">(${esc(inv.kind)})</span></div>
        <div style="margin-top:4px"><span class="sev sv-${esc(inv.severity)}">${esc(inv.severity)}</span> · exposure ${inv.exposureScore}/100</div>
        <div class="muted" style="font-size:11px;margin-top:4px">INTEL #${inv.intelId} · ${obs.length} observable(s) saved${inv.id ? ` · case #${inv.id}` : ""}</div>
      </div>
    </div>
    <div class="panel"><div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase">Executive brief</div><div class="md" style="margin-top:5px">${md(inv.brief || "")}</div></div>
  </div>
  ${tags.length ? `<div style="margin-bottom:10px">${tags.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div>` : ""}
  <div class="grid2">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">INTSUM</div>
      <div class="md">${md(inv.summary || "")}</div>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">Findings (${findings.length})</div>
      <table class="t"><thead><tr><th>Rel</th><th>Sev</th><th>Phase</th><th>Finding</th></tr></thead><tbody>
      ${findings.map((f) => `<tr><td><span class="rel rel-${esc((f.reliability || "F")[0])}">${esc(f.reliability)}</span></td><td><span class="sev sv-${esc(f.severity)}">${esc(f.severity)}</span></td><td><span class="ph ph-${esc(f.phase)}">${esc(f.phase)}</span></td><td><span class="nm">${esc(f.technique)}</span><div class="muted" style="font-size:11.5px">${esc(f.finding)}</div></td></tr>`).join("") || `<tr><td colspan="4" class="muted">No findings.</td></tr>`}
      </tbody></table>
    </div>
  </div>
  <div class="grid2" style="margin-top:14px">
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">STIX observables / IOCs (${obs.length})</div>
      <table class="t"><tbody>${obs.map((o) => `<tr><td style="width:120px"><span class="ph ph-Acquire">${esc(o.type)}</span></td><td class="mono">${esc(o.value)}</td></tr>`).join("") || `<tr><td class="muted">none</td></tr>`}</tbody></table>
    </div>
    <div class="panel">
      <div class="lbl" style="font-size:11px;color:#94a3b8;text-transform:uppercase;margin-bottom:6px">Recommendations</div>
      <ul class="md" style="padding-left:18px">${recs.map((r) => `<li>${esc(r)}</li>`).join("") || "<li class='muted'>none</li>"}</ul>
    </div>
  </div>`;
}

function renderDashboard(d: any): string {
  const s = d.summary || {};
  const recent = (d.recent || []) as any[];
  const phaseDesc: Record<string, string> = { Acquire: "Collect raw OSINT", Enrich: "Pivot & correlate", Assess: "Score & validate", Deliver: "INTSUM, brief, STIX" };
  return `
  <div class="cards">
    <div class="card"><div class="lbl">Investigations</div><div class="val">${s.investigations || 0}</div><div class="foot">avg exposure ${s.avgExposure || 0}/100</div></div>
    <div class="card"><div class="lbl">Critical</div><div class="val" style="color:#fca5a5">${s.critical || 0}</div><div class="foot">${s.high || 0} high</div></div>
    <div class="card"><div class="lbl">Observables (IOCs)</div><div class="val">${s.observables || 0}</div><div class="foot">→ XTHREAT.OBSERVABLE</div></div>
    <div class="card"><div class="lbl">Techniques</div><div class="val">${s.techniques || 0}</div><div class="foot">${s.kinds || 0} target types</div></div>
  </div>
  <div class="sec">The 4-phase CTI methodology</div>
  <div class="flow">
    ${(d.phases || []).map((p: any) => `<div class="stage s-${esc(p.phase)}"><div class="n" style="font-size:18px">${esc(p.phase)}</div><div class="d">${esc(phaseDesc[p.phase] || "")}</div><div class="t" style="margin-top:6px">${p.techniques} techniques</div></div>`).join('<div class="arrow">→</div>')}
  </div>
  <div class="sec">Recent investigations</div>
  <table class="t"><thead><tr><th>Target</th><th>Type</th><th>Exposure</th><th>Severity</th><th>Findings</th><th>When</th></tr></thead><tbody>
    ${recent.map((i) => `<tr style="cursor:pointer" data-inv="${i.id}"><td class="nm">${esc(i.target)}</td><td><span class="ph ph-Acquire">${esc(i.kind)}</span></td><td>${i.exposureScore}/100</td><td><span class="sev sv-${esc(i.severity)}">${esc(i.severity)}</span></td><td>${(i.findings || []).length}</td><td class="muted" style="font-size:11px">${esc((i.createdDate || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No investigations yet — enter a target above to run your first one.</td></tr>`}
  </tbody></table>
  <div class="sec">Technique catalogue (${(d.techniqueCatalogue || []).length})</div>
  <div class="tcat">
    ${(d.techniqueCatalogue || []).map((t: any) => `<div class="tc"><div class="tn">${esc(t.name)}</div><div class="tm"><span class="ph ph-${esc(t.phase)}">${esc(t.phase)}</span> ${t.connector ? `· <span class="mono">${esc(t.connector)}</span>` : ""}</div></div>`).join("")}
  </div>`;
}

async function loadDashboard(): Promise<void> {
  const body = $("body"); if (!body) return;
  try { body.innerHTML = renderDashboard(await getJson("/api/cti-expert")); wireRows(); }
  catch (e) { body.innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load: ${esc((e as Error).message)}</div>`; }
}

function wireRows(): void {
  document.querySelectorAll<HTMLElement>("tr[data-inv]").forEach((tr) => {
    tr.addEventListener("click", async () => {
      try {
        const inv = await getJson(`/api/cti-expert/${tr.dataset.inv}`);
        const r = $("result"); if (r) { r.innerHTML = renderInvestigation(inv); r.scrollIntoView({ behavior: "smooth" }); }
      } catch { toast("Could not load investigation"); }
    });
  });
}

async function investigate(): Promise<void> {
  const target = ($("t-target") as HTMLInputElement)?.value.trim();
  const kind = ($("t-kind") as HTMLSelectElement)?.value;
  const btn = $("t-go") as HTMLButtonElement;
  if (!target) { toast("Enter a target"); return; }
  btn.disabled = true; btn.textContent = "⏳ Investigating…";
  try {
    const r = await fetch("/api/cti-expert/investigate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, kind: kind || undefined }),
    });
    const d = await r.json();
    if (!r.ok || d.error) throw new Error(d.error || String(r.status));
    const out = $("result"); if (out) { out.innerHTML = renderInvestigation(d); out.scrollIntoView({ behavior: "smooth" }); }
    toast(d.offline ? "Plan ready (local AI offline)" : "Investigation complete");
    void loadDashboard();
  } catch (e) { toast("Failed: " + (e as Error).message); }
  finally { btn.disabled = false; btn.innerHTML = "🔍 Investigate"; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("t-go")?.addEventListener("click", () => void investigate());
  $("t-target")?.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void investigate(); });
  void loadDashboard();
});
