/**
 * chain.ts — Attack-chain run viewer (/pentest/chain?run=<id>).
 *
 * Polls /api/pentest/chain/:runId and draws the playbook execution as a live tree:
 * each node is a tool run against a target; edges are "this step's facts triggered
 * the next tool". Nodes are coloured by status and flag vulnerabilities found.
 */
declare const d3: any;

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}
function toast(msg: string): void { const el = $("ch-toast"); el.textContent = msg; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }
function mdLite(s: string): string {
  return String(s || "").split(/\n/).map((raw) => {
    const l = esc(raw).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
    if (/^#{1,6}\s/.test(raw)) return `<div style="font-weight:600;color:#e2e8f0;margin:8px 0 3px">${l.replace(/^#{1,6}\s*/, "")}</div>`;
    if (/^\s*[-*]\s/.test(raw)) return `<div style="margin-left:8px">• ${l.replace(/^\s*[-*]\s*/, "")}</div>`;
    if (!raw.trim()) return '<div style="height:6px"></div>';
    return `<div>${l}</div>`;
  }).join("");
}

const params = new URLSearchParams(location.search);
const runId = Number(params.get("run"));
const engagementId = Number(params.get("engagement"));

interface Facts { services: { port: number; proto: string; name: string; product?: string; version?: string }[]; tech: string[]; vulns: { ref: string; severity: string; name?: string }[]; hosts: string[]; emails: string[]; leaks: { ref: string; severity: string; name?: string }[]; }
interface Step { ChainStepID: number; ParentStepID: number | null; Depth: number; Connector: string; Target: string; RuleID: string | null; RuleLabel: string | null; JobID: number | null; Status: string; FactsJSON: string | null; Summary: string | null; }
interface Run { ChainRunID: number; AuditID: number; PlaybookName: string; Name: string; SeedTarget: string; SeedKind: string; Mode: string; Status: string; StepsTotal: number; FindingsTotal: number; AssetsTotal?: number; CreatedDate: string; FinishedDate: string | null; }

let steps: Step[] = [];
let selected = 0;
let pollTimer: number | null = null;
let gRoot: any = null;
let zoom: any = null;

function facts(s: Step): Facts {
  try { const f = JSON.parse(s.FactsJSON || "{}"); return { services: f.services || [], tech: f.tech || [], vulns: f.vulns || [], hosts: f.hosts || [], emails: f.emails || [], leaks: f.leaks || [] }; }
  catch { return { services: [], tech: [], vulns: [], hosts: [], emails: [], leaks: [] }; }
}
function vulnCount(s: Step): number { const f = facts(s); return f.vulns.length + f.leaks.length; }

function statusFill(s: Step): string {
  switch (s.Status) {
    case "pending": return "#475569";
    case "running": return "#f59e0b";
    case "error": return "#7f1d1d";
    case "skipped": return "#1e2133";
    default: return "#16a34a"; // done
  }
}
function statusStroke(s: Step): string {
  if (s.Status === "done" && vulnCount(s) > 0) return "#ef4444";
  if (s.Status === "error") return "#ef4444";
  return "#0008";
}

function renderHeader(run: Run): void {
  $("ch-run-name").textContent = run.Name || run.PlaybookName;
  const badge = run.Status === "running" ? "b-run" : run.Status === "done" ? "b-done" : run.Status === "stopped" ? "b-stop" : "b-err";
  const mode = run.Mode === "live" ? "b-live" : "b-sim";
  $("ch-meta").innerHTML =
    `<div class="kv"><span>Status</span><span class="badge ${badge}">${esc(run.Status)}</span></div>
     <div class="kv"><span>Mode</span><span class="badge ${mode}">${esc(run.Mode)}${run.Mode === "simulate" ? " (no real scan)" : ""}</span></div>
     <div class="kv"><span>Playbook</span><b>${esc(run.PlaybookName)}</b></div>
     <div class="kv"><span>Seed</span><b>${esc(run.SeedTarget)}</b></div>
     <div class="kv"><span>Steps</span><b>${steps.length}</b></div>
     <div class="kv"><span>Findings</span><b style="color:${run.FindingsTotal ? "#fca5a5" : "#e2e8f0"}">${run.FindingsTotal}</b></div>` +
    (run.AssetsTotal ? `<div class="kv"><span>Assets discovered</span><b style="color:#6ee7b7">${run.AssetsTotal}</b></div>` : "");
  ($("ch-stop") as HTMLButtonElement).style.display = run.Status === "running" ? "inline-block" : "none";
}

function renderDetail(s: Step | null): void {
  const box = $("ch-detail");
  if (!s) { box.innerHTML = `<span class="muted">Click a node to inspect its findings.</span>`; return; }
  const f = facts(s);
  let h = `<div class="kv"><span>Tool</span><b>${esc(s.Connector)}</b></div>
           <div class="kv"><span>Target</span><b style="font-family:ui-monospace,monospace;font-size:11px">${esc(s.Target)}</b></div>
           <div class="kv"><span>Status</span><b>${esc(s.Status)}</b></div>`;
  if (s.RuleLabel && s.RuleID !== "seed") h += `<div class="muted" style="margin:4px 0">▸ ${esc(s.RuleLabel)}</div>`;
  if (f.services.length) h += `<div class="t">Open services (${f.services.length})</div>` + f.services.map((sv) => `<span class="chip">${sv.port}/${esc(sv.name || sv.proto)}${sv.product ? " · " + esc(sv.product) : ""}</span>`).join("");
  if (f.tech.length) h += `<div class="t">Technologies</div>` + f.tech.map((t) => `<span class="chip">${esc(t)}</span>`).join("");
  if (f.vulns.length) h += `<div class="t">Vulnerabilities (${f.vulns.length})</div>` + f.vulns.map((v) => `<span class="v">⚠️ [${esc(v.severity)}] ${esc(v.ref)}${v.name ? " — " + esc(v.name) : ""}</span>`).join("");
  if (f.hosts.length > 1) h += `<div class="t">Hosts / subdomains (${f.hosts.length})</div>` + f.hosts.slice(0, 40).map((hn) => `<span class="chip">${esc(hn)}</span>`).join("");
  if (f.emails.length) h += `<div class="t">Emails (${f.emails.length})</div>` + f.emails.slice(0, 40).map((e) => `<span class="chip">${esc(e)}</span>`).join("");
  if (f.leaks.length) h += `<div class="t">Breach / leak (${f.leaks.length})</div>` + f.leaks.map((v) => `<span class="v">⚠️ [${esc(v.severity)}] ${esc(v.name || v.ref)}</span>`).join("");
  if (!f.services.length && !f.tech.length && !f.vulns.length && f.hosts.length <= 1 && !f.emails.length && !f.leaks.length) h += `<div class="muted" style="margin-top:6px">${esc(s.Summary || "no result yet")}</div>`;
  if (s.JobID) h += `<div class="muted" style="margin-top:8px">job #${s.JobID}</div>`;
  box.innerHTML = h;
}

function buildHierarchy(): any {
  // virtual root (id 0) gathers the seed steps (ParentStepID null)
  const rows = [{ ChainStepID: 0, ParentStepID: null as number | null } as any, ...steps];
  const stratify = d3.stratify().id((d: any) => String(d.ChainStepID)).parentId((d: any) => d.ChainStepID === 0 ? null : String(d.ParentStepID ?? 0));
  return stratify(rows);
}

const NW = 168, NH = 50;
function renderGraph(): void {
  const svg = d3.select("#ch-svg");
  svg.selectAll("*").remove();
  if (!steps.length) return;
  const root = d3.hierarchy(buildHierarchy());
  const tree = d3.tree().nodeSize([NH + 18, NW + 56]);
  tree(root);
  const nodes = root.descendants().filter((n: any) => n.data.data.ChainStepID !== 0);
  const links = root.links().filter((l: any) => l.source.data.data.ChainStepID !== 0);

  gRoot = svg.append("g");
  zoom = d3.zoom().scaleExtent([0.3, 2]).on("zoom", (e: any) => gRoot.attr("transform", e.transform));
  svg.call(zoom);

  gRoot.append("g").selectAll("path").data(links).join("path")
    .attr("class", "nlink")
    .attr("d", (l: any) => {
      const sx = l.source.x, sy = l.source.y + NW / 2, tx = l.target.x, ty = l.target.y - NW / 2;
      const mid = (sy + ty) / 2;
      return `M${sy},${sx} C${mid},${sx} ${mid},${tx} ${ty},${tx}`;
    });

  const g = gRoot.append("g").selectAll("g.node").data(nodes).join("g")
    .attr("class", "node")
    .attr("transform", (n: any) => `translate(${n.y - NW / 2},${n.x - NH / 2})`)
    .on("click", (_e: any, n: any) => { selected = n.data.data.ChainStepID; renderDetail(n.data.data); paintSelection(); });

  g.append("rect").attr("width", NW).attr("height", NH)
    .attr("fill", (n: any) => statusFill(n.data.data))
    .attr("stroke", (n: any) => statusStroke(n.data.data))
    .attr("stroke-width", (n: any) => (n.data.data.Status === "done" && vulnCount(n.data.data) > 0) ? 2.5 : 1.5)
    .attr("class", (n: any) => n.data.data.Status === "running" ? "pulsing" : "");
  g.append("text").attr("class", "tool").attr("x", 9).attr("y", 16).text((n: any) => n.data.data.Connector + (vulnCount(n.data.data) ? `  ⚠️${vulnCount(n.data.data)}` : ""));
  g.append("text").attr("class", "tgt").attr("x", 9).attr("y", 30).text((n: any) => clip(n.data.data.Target, 26));
  g.append("text").attr("class", "sum").attr("x", 9).attr("y", 43).text((n: any) => clip(n.data.data.Summary || statusWord(n.data.data.Status), 30));

  paintSelection();
  fit();
}

function statusWord(s: string): string { return s === "pending" ? "queued…" : s === "running" ? "running…" : s; }
function clip(s: string, n: number): string { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
function paintSelection(): void {
  if (!gRoot) return;
  gRoot.selectAll("g.node rect").attr("stroke-dasharray", (n: any) => n.data.data.ChainStepID === selected ? "4,3" : null);
}

function fit(): void {
  if (!gRoot || !zoom) return;
  const svg = $("ch-svg"); const W = svg.clientWidth || 900, H = svg.clientHeight || 600;
  const b = gRoot.node().getBBox();
  if (!b.width || !b.height) return;
  const scale = Math.min(1.4, 0.92 * Math.min(W / b.width, H / b.height));
  const tx = (W - b.width * scale) / 2 - b.x * scale;
  const ty = (H - b.height * scale) / 2 - b.y * scale;
  d3.select("#ch-svg").transition().duration(300).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

async function load(): Promise<void> {
  let d: any;
  try { const r = await fetch(`/api/pentest/chain/${runId}`); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { toast(String(e)); return; }
  steps = d.steps || [];
  const run: Run = d.run;
  renderHeader(run);
  renderGraph();
  if (selected) { const s = steps.find((x) => x.ChainStepID === selected); renderDetail(s || null); }
  if (run.Status === "running") { if (!pollTimer) pollTimer = window.setInterval(load, 1500); }
  else if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

document.addEventListener("DOMContentLoaded", () => {
  if (Number.isFinite(engagementId) && engagementId > 0) ($("ch-back") as HTMLAnchorElement).href = `/pentest?id=${engagementId}`;
  $("ch-fit").addEventListener("click", fit);
  $("ch-zin").addEventListener("click", () => { if (zoom) d3.select("#ch-svg").transition().duration(200).call(zoom.scaleBy, 1.3); });
  $("ch-zout").addEventListener("click", () => { if (zoom) d3.select("#ch-svg").transition().duration(200).call(zoom.scaleBy, 0.75); });
  $("ch-purple").addEventListener("click", () => window.open(`/purple-team?run=${runId}${Number.isFinite(engagementId) && engagementId > 0 ? `&engagement=${engagementId}` : ""}`, "_blank", "noopener"));
  $("ch-ai").addEventListener("click", async () => {
    const btn = $("ch-ai") as HTMLButtonElement; btn.disabled = true;
    $("ch-detail").innerHTML = `<span class="muted">🧠 Analyzing…</span>`;
    try {
      const r = await fetch(`/api/ai/chain/${runId}/analyze`, { method: "POST" });
      const d = await r.json(); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      $("ch-detail").innerHTML = `<div class="muted" style="margin-bottom:5px">${d.offline ? "AI offline — data summary" : "model: " + esc(d.model)}</div>` + mdLite(d.analysis);
    } catch (e) { $("ch-detail").innerHTML = `<span class="muted">⚠️ ${esc(e)}</span>`; }
    finally { btn.disabled = false; }
  });
  $("ch-stop").addEventListener("click", async () => {
    try { await fetch(`/api/pentest/chain/${runId}/stop`, { method: "POST" }); toast("Run stopped"); await load(); }
    catch (e) { toast(String(e)); }
  });
  $("ch-export").addEventListener("click", () => {
    const svg = $("ch-svg"); const clone = svg.cloneNode(true) as SVGElement;
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const blob = new Blob([`<?xml version="1.0"?>\n` + clone.outerHTML], { type: "image/svg+xml" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `attack-chain-${runId}.svg`; a.click();
  });
  if (!Number.isFinite(runId) || runId <= 0) { toast("No run id"); return; }
  void load();
});
