/**
 * attack-path.ts — Attack-path & choke-point graph (/attack-path).
 * Force-directed reachability graph from /api/attack-path: internet-exposed entries,
 * crown jewels, hosts; red edges = easiest attack paths; choke points ranked. Localized via ap.* keys.
 */
import { initI18n, t } from "./i18n";
declare const d3: any;

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const el = $("ap-toast"); el.textContent = m; el.style.display = "block"; setTimeout(() => (el.style.display = "none"), 3500); }

interface ApNode { id: number; label: string; ip: string | null; role: string; exposure: number; value: number; onPath: boolean; choke: number; }
interface ApLink { source: any; target: any; kind: string; onPath: boolean; }
interface ApPath { jewel: number; jewelLabel: string; entry: number; entryLabel: string; cost: number; nodes: number[]; steps: string[]; }
interface Graph { nodes: ApNode[]; links: ApLink[]; paths: ApPath[]; chokepoints: { id: number; label: string; paths: number }[]; stats: any; }

let data: Graph; let gRoot: any; let zoom: any; let highlight: Set<number> | null = null;
const ROLE_FILL: Record<string, string> = { entry: "#3b82f6", jewel: "#f59e0b", node: "#475569" };

function radius(n: ApNode): number { return 6 + Math.min(14, (n.exposure / 100) * 14) + (n.role === "jewel" ? 3 : 0); }

function render(): void {
  const svg = d3.select("#ap-svg"); svg.selectAll("*").remove();
  const W = ($("ap-svg").clientWidth) || 900, H = ($("ap-svg").clientHeight) || 600;
  gRoot = svg.append("g");
  zoom = d3.zoom().scaleExtent([0.2, 3]).on("zoom", (e: any) => gRoot.attr("transform", e.transform));
  svg.call(zoom);

  const sim = d3.forceSimulation(data.nodes)
    .force("link", d3.forceLink(data.links).id((d: any) => d.id).distance((l: any) => l.onPath ? 70 : 90).strength(0.4))
    .force("charge", d3.forceManyBody().strength(-220))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide().radius((d: any) => radius(d) + 6));

  const lk = gRoot.append("g").selectAll("line").data(data.links).join("line")
    .attr("stroke", (l: ApLink) => l.onPath ? "#ef4444" : (l.kind === "bia" ? "#7c3aed" : "#334155"))
    .attr("stroke-width", (l: ApLink) => l.onPath ? 2.4 : 1)
    .attr("stroke-dasharray", (l: ApLink) => l.kind === "bia" ? "4,4" : null)
    .attr("opacity", (l: ApLink) => l.onPath ? 0.95 : 0.5);

  const nd = gRoot.append("g").selectAll("g").data(data.nodes).join("g")
    .attr("class", "node").style("cursor", "pointer")
    .call(d3.drag()
      .on("start", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e: any, d: any) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }))
    .on("click", (_e: any, d: ApNode) => { highlight = new Set([d.id]); paint(); });

  nd.append("circle")
    .attr("r", (d: ApNode) => radius(d))
    .attr("fill", (d: ApNode) => ROLE_FILL[d.role] || "#475569")
    .attr("stroke", (d: ApNode) => d.choke ? "#ef4444" : (d.onPath ? "#fca5a5" : "#0b0d18"))
    .attr("stroke-width", (d: ApNode) => d.choke ? 3 : (d.onPath ? 2 : 1));
  // square badge marker for choke points
  nd.filter((d: ApNode) => d.choke > 0).append("rect").attr("x", (d: ApNode) => radius(d) - 2).attr("y", (d: ApNode) => -radius(d) - 8).attr("width", 14).attr("height", 12).attr("rx", 2).attr("fill", "#ef4444");
  nd.filter((d: ApNode) => d.choke > 0).append("text").attr("x", (d: ApNode) => radius(d) + 5).attr("y", (d: ApNode) => -radius(d) + 2).attr("font-size", "9px").attr("fill", "#fff").attr("text-anchor", "middle").text((d: ApNode) => d.choke);
  nd.append("text").attr("class", "node-label").attr("x", (d: ApNode) => radius(d) + 3).attr("y", 3).text((d: ApNode) => d.label.length > 22 ? d.label.slice(0, 21) + "…" : d.label);

  sim.on("tick", () => {
    lk.attr("x1", (l: any) => l.source.x).attr("y1", (l: any) => l.source.y).attr("x2", (l: any) => l.target.x).attr("y2", (l: any) => l.target.y);
    nd.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
  });
  setTimeout(fit, 900);
  (window as any).__nd = nd; (window as any).__lk = lk;
}

function paint(): void {
  const nd = (window as any).__nd, lk = (window as any).__lk; if (!nd) return;
  nd.attr("opacity", (d: ApNode) => !highlight || highlight.has(d.id) ? 1 : 0.18);
  lk.attr("opacity", (l: ApLink) => {
    if (!highlight) return l.onPath ? 0.95 : 0.5;
    const s = (l.source.id ?? l.source), tg = (l.target.id ?? l.target);
    return highlight.has(s) && highlight.has(tg) ? 1 : 0.06;
  });
}

function fit(): void {
  if (!gRoot || !zoom) return;
  const svg = $("ap-svg"); const W = svg.clientWidth || 900, H = svg.clientHeight || 600;
  const b = gRoot.node().getBBox(); if (!b.width || !b.height) return;
  const scale = Math.min(1.6, 0.9 * Math.min(W / b.width, H / b.height));
  d3.select("#ap-svg").transition().duration(300).call(zoom.transform, d3.zoomIdentity.translate((W - b.width * scale) / 2 - b.x * scale, (H - b.height * scale) / 2 - b.y * scale).scale(scale));
}

function renderSidebar(): void {
  const st = data.stats;
  $("ap-stats").innerHTML =
    `<div class="kv"><span>${esc(t("ap.assets"))}</span><b>${st.assets}</b></div>
     <div class="kv"><span>${esc(t("ap.entriesN"))}</span><b style="color:#93c5fd">${st.entries}</b></div>
     <div class="kv"><span>${esc(t("ap.jewelsN"))}</span><b style="color:#fcd34d">${st.jewels}</b></div>
     <div class="kv"><span>${esc(t("ap.edges"))}</span><b>${st.edges}</b></div>
     <div class="kv"><span>${esc(t("ap.pathsFound"))}</span><b style="color:#fca5a5">${st.pathsFound}</b></div>`;
  $("ap-chokes").innerHTML = data.chokepoints.length
    ? data.chokepoints.map((c) => `<div class="choke" data-id="${c.id}"><b>${esc(c.label)}</b> — ${c.paths} ${esc(t("ap.onPaths"))}</div>`).join("")
    : `<span class="muted">${esc(t("ap.noChoke"))}</span>`;
  $("ap-paths").innerHTML = data.paths.length
    ? data.paths.slice(0, 30).map((p, i) => `<div class="path" data-ids="${p.nodes.join(",")}">
        <span class="c">${esc(t("ap.cost"))} ${p.cost}</span> → <b>${esc(p.jewelLabel)}</b>
        <div class="route">${esc(p.steps.join(" → "))}</div></div>`).join("")
    : `<span class="muted">${esc(t("ap.noPath"))}</span>`;
  $("ap-chokes").querySelectorAll(".choke").forEach((el) => el.addEventListener("click", () => { highlight = new Set([Number((el as HTMLElement).dataset.id)]); paint(); }));
  $("ap-paths").querySelectorAll(".path").forEach((el) => el.addEventListener("click", () => { highlight = new Set(((el as HTMLElement).dataset.ids || "").split(",").map(Number)); paint(); }));
}

async function load(): Promise<void> {
  try { const r = await fetch("/api/attack-path"); if (!r.ok) throw new Error(`HTTP ${r.status}`); data = await r.json(); }
  catch (e) { toast(String(e)); return; }
  renderSidebar();
  if (!data.nodes.length) { toast(t("ap.empty")); return; }
  render();
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  $("ap-fit").addEventListener("click", () => { highlight = null; paint(); fit(); });
  $("ap-zin").addEventListener("click", () => { if (zoom) d3.select("#ap-svg").transition().duration(200).call(zoom.scaleBy, 1.3); });
  $("ap-zout").addEventListener("click", () => { if (zoom) d3.select("#ap-svg").transition().duration(200).call(zoom.scaleBy, 0.75); });
  $("ap-export").addEventListener("click", () => {
    const clone = $("ap-svg").cloneNode(true) as SVGElement; clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([clone.outerHTML], { type: "image/svg+xml" })); a.download = "attack-paths.svg"; a.click();
  });
  void load();
});
