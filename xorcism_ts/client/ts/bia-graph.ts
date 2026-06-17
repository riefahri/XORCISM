/**
 * bia-graph.ts — BIA dependency graph (/bia-graph?audit=).
 * Force-directed, directed graph of a BIA study's entries (assets / processes,
 * coloured by criticality) and their dependencies (XORCISM.BIADEPENDENCY:
 * "From depends on To"). Click an entry to see impact propagation — everything
 * that fails if it goes down. Dependencies are editable in place.
 */
import { initI18n } from "./i18n";

declare const d3: any;
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}

interface BNode { id: number; label: string; type: string; criticality: string; rto: string; rpo: string; mtd: string; riskLevel: string; owner: string; impacts: { fin: string; ops: string; legal: string; rep: string }; x?: number; y?: number }
interface BLink { id: number; source: any; target: any; type: string }
interface Graph { audit: { BIAAuditID: number; BIAAuditName: string } | null; nodes: BNode[]; links: BLink[] }

const CRIT: { key: string; color: string; label: string }[] = [
  { key: "very high", color: "#dc2626", label: "Very High" },
  { key: "critical", color: "#ef4444", label: "Critical" },
  { key: "high", color: "#f97316", label: "High" },
  { key: "medium", color: "#f59e0b", label: "Medium" },
  { key: "moderate", color: "#f59e0b", label: "Moderate" },
  { key: "low", color: "#22c55e", label: "Low" },
  { key: "very low", color: "#84cc16", label: "Very Low" },
];
function critColor(c: string): string {
  const e = CRIT.find((x) => x.key === String(c || "").toLowerCase());
  return e ? e.color : "#6b7280";
}
function critRank(c: string): number {
  const i = ["very low", "low", "medium", "moderate", "high", "critical", "very high"].indexOf(String(c || "").toLowerCase());
  return i < 0 ? 0 : i;
}

let data: Graph = { audit: null, nodes: [], links: [] };
let auditId = 0;
let sim: any = null, zoomB: any = null, gRoot: any = null, selected: number | null = null;

function toast(m: string): void { const el = $("bg-toast"); el.textContent = m; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }
async function jget(u: string): Promise<any> { const r = await fetch(u); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }
async function jsend(method: string, u: string, b?: unknown): Promise<any> {
  const r = await fetch(u, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(b ?? {}) });
  const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`); return d;
}

async function loadAudits(): Promise<void> {
  let audits: { BIAAuditID: number; BIAAuditName: string }[] = [];
  try { audits = await jget("/api/bia/audits"); } catch { /* ignore */ }
  const sel = $("bg-audit") as HTMLSelectElement;
  sel.innerHTML = audits.length ? audits.map((a) => `<option value="${a.BIAAuditID}">${esc(a.BIAAuditName)}</option>`).join("") : `<option value="">No BIA study</option>`;
  const q = Number(new URLSearchParams(location.search).get("audit"));
  if (q && audits.some((a) => a.BIAAuditID === q)) sel.value = String(q);
  auditId = Number(sel.value) || 0;
}

async function loadGraph(): Promise<void> {
  if (!auditId) { data = { audit: null, nodes: [], links: [] }; render(); return; }
  try { data = await jget(`/api/bia/graph?auditId=${auditId}`); } catch (e) { toast(String(e)); return; }
  fillEntrySelects();
  render();
}
function fillEntrySelects(): void {
  const opts = data.nodes.map((n) => `<option value="${n.id}">${esc(n.label)}</option>`).join("");
  ($("bg-from") as HTMLSelectElement).innerHTML = opts;
  ($("bg-to") as HTMLSelectElement).innerHTML = opts;
}

// Impact propagation: dependentsOf[t] = nodes that depend on t (edge s→t). BFS from a
// failed node over those edges = everything transitively impacted.
function impactedBy(start: number): { nodes: Set<number>; links: Set<number> } {
  const depOf = new Map<number, { from: number; link: number }[]>();
  for (const l of data.links) {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    (depOf.get(t) || depOf.set(t, []).get(t)!).push({ from: s, link: l.id });
  }
  const nodes = new Set<number>(), links = new Set<number>(), queue = [start];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of depOf.get(cur) || []) {
      links.add(e.link);
      if (!nodes.has(e.from)) { nodes.add(e.from); queue.push(e.from); }
    }
  }
  return { nodes, links };
}

function render(): void {
  const showLabels = ($("bg-labels") as HTMLInputElement).checked;
  const svgEl = $("bg-svg") as unknown as SVGSVGElement;
  const W = svgEl.clientWidth || 800, H = svgEl.clientHeight || 600;
  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  svg.append("defs").append("marker").attr("id", "bg-arrow").attr("viewBox", "0 -5 10 10")
    .attr("refX", 20).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
    .append("path").attr("d", "M0,-4L8,0L0,4").attr("fill", "#64748b");
  gRoot = svg.append("g");
  zoomB = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (ev: any) => gRoot.attr("transform", ev.transform));
  svg.call(zoomB);
  svg.on("click", (ev: any) => { if (ev.target === svgEl) clearImpact(); });

  const link = gRoot.append("g").selectAll("line").data(data.links, (d: BLink) => d.id).join("line")
    .attr("class", "link").attr("marker-end", "url(#bg-arrow)")
    .on("click", (ev: any, d: BLink) => { ev.stopPropagation(); void removeDep(d); });
  const linkLabel = gRoot.append("g").selectAll("text").data(data.links).join("text")
    .attr("class", "linklabel").style("display", showLabels ? null : "none").text((d: BLink) => d.type);

  const node = gRoot.append("g").selectAll("g").data(data.nodes, (d: BNode) => d.id).join("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (ev: any, d: any) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (ev: any, d: any) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev: any) => { if (!ev.active) sim.alphaTarget(0); }))
    .on("click", (ev: any, d: BNode) => { ev.stopPropagation(); showImpact(d); });

  node.append("circle").attr("r", (d: BNode) => 8 + critRank(d.criticality) * 1.6).attr("fill", (d: BNode) => critColor(d.criticality));
  node.append("text").attr("x", 12).attr("y", 3).text((d: BNode) => (d.label.length > 26 ? d.label.slice(0, 25) + "…" : d.label));
  node.append("title").text((d: BNode) => `${d.label}\n${d.type || ""}\ncriticality: ${d.criticality}\nRTO ${d.rto} · RPO ${d.rpo}`);

  sim = d3.forceSimulation(data.nodes)
    .force("link", d3.forceLink(data.links).id((d: BNode) => d.id).distance(110).strength(0.5))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(26))
    .on("tick", () => {
      link.attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y).attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y);
      linkLabel.attr("x", (d: any) => (d.source.x + d.target.x) / 2).attr("y", (d: any) => (d.source.y + d.target.y) / 2);
      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

  buildLegend();
  $("bg-counts").textContent = data.audit ? `${data.nodes.length} entries · ${data.links.length} dependencies` : "Select a BIA study.";
  if (selected != null && data.nodes.some((n) => n.id === selected)) { const n = data.nodes.find((x) => x.id === selected)!; showImpact(n); } else clearImpact();
}

function buildLegend(): void {
  const present = new Set(data.nodes.map((n) => String(n.criticality || "").toLowerCase()));
  const seen = new Set<string>();
  const items = CRIT.filter((c) => present.has(c.key) && !seen.has(c.color) && seen.add(c.color));
  $("bg-legend").innerHTML = (items.length ? items : CRIT.filter((c) => ["critical", "high", "medium", "low"].includes(c.key)))
    .map((c) => `<div class="it"><span class="dot" style="background:${c.color}"></span>${c.label}</div>`).join("");
}

function clearImpact(): void {
  selected = null;
  d3.selectAll(".node").classed("sel", false).classed("impacted", false).classed("dim", false);
  d3.selectAll(".link").classed("impacted", false).classed("dim", false);
  $("bg-impact").innerHTML = "Click an entry to see what fails if it goes down.";
  $("bg-details").style.display = "none";
}

function showImpact(d: BNode): void {
  selected = d.id;
  const imp = impactedBy(d.id);
  d3.selectAll(".node").classed("sel", (n: BNode) => n.id === d.id)
    .classed("impacted", (n: BNode) => imp.nodes.has(n.id))
    .classed("dim", (n: BNode) => n.id !== d.id && !imp.nodes.has(n.id));
  d3.selectAll(".link").classed("impacted", (l: BLink) => imp.links.has(l.id)).classed("dim", (l: BLink) => !imp.links.has(l.id));

  const impNodes = data.nodes.filter((n) => imp.nodes.has(n.id));
  const rtos = impNodes.map((n) => parseFloat(n.rto)).filter((x) => Number.isFinite(x));
  let worst = "", worstR = -1;
  for (const n of impNodes) { const r = critRank(n.criticality); if (n.criticality && r > worstR) { worstR = r; worst = n.criticality; } }
  $("bg-impact").innerHTML = imp.nodes.size
    ? `If <b>${esc(d.label)}</b> fails: <b>${imp.nodes.size}</b> dependent ${imp.nodes.size === 1 ? "entry" : "entries"} impacted.` +
      (rtos.length ? `<br>Tightest RTO among them: <b>${Math.min(...rtos)}</b> h.` : "") +
      (worst ? `<br>Worst impacted criticality: <b>${esc(worst)}</b>.` : "")
    : `<b>${esc(d.label)}</b> has no dependents — nothing else fails if it goes down.`;
  showDetails(d, imp.nodes.size);
}

function showDetails(d: BNode, impacted: number): void {
  const box = $("bg-details"); box.style.display = "block";
  box.innerHTML = `<span class="close" id="bg-det-close">&#10005;</span>
    <h4 style="color:${critColor(d.criticality)}">${esc(d.label)}</h4>
    <div class="bg-stat">${esc(d.type || "—")}</div>
    <div class="kv">
      <div class="k">Criticality</div><div>${esc(d.criticality || "—")}</div>
      <div class="k">Risk level</div><div>${esc(d.riskLevel || "—")}</div>
      <div class="k">MTD / RTO / RPO</div><div>${esc(d.mtd || "—")} / ${esc(d.rto || "—")} / ${esc(d.rpo || "—")} h</div>
      <div class="k">Owner</div><div>${esc(d.owner || "—")}</div>
      <div class="k">Impact (F/O/L/R)</div><div>${esc(d.impacts.fin || "—")} / ${esc(d.impacts.ops || "—")} / ${esc(d.impacts.legal || "—")} / ${esc(d.impacts.rep || "—")}</div>
      <div class="k">Dependents</div><div>${impacted}</div>
    </div>
    <a href="/?db=XORCISM&table=BIAENTRY&editCol=BIAEntryID&editVal=${d.id}" target="_blank" rel="noopener" style="color:#7c83fd;font-size:12px">Open BIA entry ↗</a>`;
  $("bg-det-close").onclick = () => { box.style.display = "none"; };
}

async function addDep(): Promise<void> {
  const from = Number(($("bg-from") as HTMLSelectElement).value), to = Number(($("bg-to") as HTMLSelectElement).value);
  if (!from || !to) return;
  if (from === to) { toast("An entry cannot depend on itself."); return; }
  try {
    await jsend("POST", "/api/bia/dependencies", { auditId, fromEntryId: from, toEntryId: to, type: ($("bg-type") as HTMLInputElement).value.trim() || "depends-on" });
    await loadGraph();
  } catch (e) { toast(String(e)); }
}
async function removeDep(l: BLink): Promise<void> {
  if (!confirm("Remove this dependency?")) return;
  try { await jsend("DELETE", `/api/bia/dependencies/${l.id}`); await loadGraph(); } catch (e) { toast(String(e)); }
}

function fitView(): void { if (zoomB) d3.select($("bg-svg")).transition().duration(400).call(zoomB.transform, d3.zoomIdentity); }
function exportSvg(): void {
  const clone = $("bg-svg").cloneNode(true) as SVGElement;
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  const blob = new Blob(['<?xml version="1.0"?>\n' + clone.outerHTML], { type: "image/svg+xml" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "bia-dependency-graph.svg"; a.click();
}

document.addEventListener("DOMContentLoaded", async () => {
  initI18n();
  ($("bg-audit") as HTMLSelectElement).onchange = () => { auditId = Number(($("bg-audit") as HTMLSelectElement).value) || 0; selected = null; void loadGraph(); };
  $("bg-add").onclick = () => void addDep();
  $("bg-zin").onclick = () => { if (zoomB) d3.select($("bg-svg")).transition().duration(200).call(zoomB.scaleBy, 1.3); };
  $("bg-zout").onclick = () => { if (zoomB) d3.select($("bg-svg")).transition().duration(200).call(zoomB.scaleBy, 0.75); };
  $("bg-fit").onclick = fitView;
  $("bg-export").onclick = exportSvg;
  $("bg-reload").onclick = () => void loadGraph();
  ($("bg-labels") as HTMLInputElement).onchange = () => {
    d3.selectAll(".linklabel").style("display", ($("bg-labels") as HTMLInputElement).checked ? null : "none");
  };
  await loadAudits();
  void loadGraph();
});
