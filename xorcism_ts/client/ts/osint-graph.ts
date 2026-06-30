/** osint-graph.ts — Palantir-style OSINT link analysis (/osint-graph). d3 force graph over
 * INTELEXCHANGE intel items + extracted entities (CVE/actor/malware/ATT&CK/IOC), with type
 * legend filter, search, and click-to-pivot. d3 is loaded from CDN (global). */
declare const d3: any;
// NB: import as T — `t` is used as a param name in this file (legend()'s .map(([t,n])=>…)).
import { initI18n, t as T } from "./i18n";
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.split(`{${k}}`).join(String(v)), T(key));
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

const COLOR: Record<string, string> = {
  intel: "#38bdf8", cve: "#f87171", actor: "#fb923c", malware: "#c084fc", attack: "#fbbf24",
  domain: "#34d399", ip: "#60a5fa", email: "#f472b6", hash: "#94a3b8", onion: "#a855f7",
};
const TYPE_LABEL: Record<string, string> = { intel: "Intel report", cve: "CVE", actor: "Threat actor", malware: "Malware", attack: "ATT&CK", domain: "Domain", ip: "IP", email: "Email", hash: "Hash", onion: ".onion" };
// Node types whose entity maps to a record in another table → "open the matching form" deep-link
// (Explorer editCol/editVal → getRowById → edit modal). The node label is the lookup value.
const FORM_LINK: Record<string, { db: string; table: string; editCol: string; key: string }> = {
  cve: { db: "XVULNERABILITY", table: "VULNERABILITY", editCol: "VULReferentialID", key: "og.openVuln" },
  actor: { db: "XTHREAT", table: "THREATACTOR", editCol: "ThreatActorName", key: "og.openActor" },
};
const typeLabel = (tp: string): string => { const k = `og.type.${tp}`; const v = T(k); return v === k ? (TYPE_LABEL[tp] || tp) : v; };

interface N { id: string; type: string; label: string; degree: number; source?: string; date?: string; ref?: string; x?: number; y?: number; }
interface L { source: any; target: any; kind: string; }

let NODES: N[] = []; let LINKS: L[] = [];
const hidden = new Set<string>();
let sim: any, nodeSel: any, linkSel: any, labelSel: any;
let zoomBehavior: any, svgSel: any; // retained so the +/−/reset buttons can drive the same transform
const adj = new Map<string, Set<string>>();

function buildAdj(): void {
  adj.clear();
  for (const l of LINKS) {
    const s = typeof l.source === "object" ? l.source.id : l.source;
    const t = typeof l.target === "object" ? l.target.id : l.target;
    (adj.get(s) || adj.set(s, new Set()).get(s)!).add(t);
    (adj.get(t) || adj.set(t, new Set()).get(t)!).add(s);
  }
}

function render(): void {
  const host = $("og-graph"); host.innerHTML = "";
  const W = host.clientWidth, H = host.clientHeight;
  const svg = d3.select(host).append("svg").attr("width", W).attr("height", H);
  const g = svg.append("g");
  zoomBehavior = d3.zoom().scaleExtent([0.15, 4]).on("zoom", (e: any) => g.attr("transform", e.transform));
  svgSel = svg;
  svg.call(zoomBehavior); // wheel / pinch / drag-pan

  // Visible zoom controls (+ / − / reset) — drive the same d3.zoom transform as the wheel.
  const ctrl = document.createElement("div");
  ctrl.className = "og-zoom";
  ctrl.innerHTML =
    `<button data-z="in" title="${esc(T("og.zoomIn"))}" aria-label="${esc(T("og.zoomIn"))}">+</button>` +
    `<button data-z="out" title="${esc(T("og.zoomOut"))}" aria-label="${esc(T("og.zoomOut"))}">&minus;</button>` +
    `<button data-z="reset" class="reset" title="${esc(T("og.zoomReset"))}" aria-label="${esc(T("og.zoomReset"))}">&#9974;</button>`;
  host.appendChild(ctrl);
  ctrl.querySelectorAll<HTMLButtonElement>("button").forEach((b) => {
    b.onclick = (ev) => {
      ev.preventDefault();
      const z = b.dataset.z;
      if (z === "reset") svgSel.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity);
      else svgSel.transition().duration(200).call(zoomBehavior.scaleBy, z === "in" ? 1.4 : 1 / 1.4);
    };
  });

  const visN = NODES.filter((n) => !hidden.has(n.type));
  const visIds = new Set(visN.map((n) => n.id));
  const visL = LINKS.filter((l) => { const s = typeof l.source === "object" ? l.source.id : l.source, t = typeof l.target === "object" ? l.target.id : l.target; return visIds.has(s) && visIds.has(t); });

  linkSel = g.append("g").selectAll("line").data(visL).join("line").attr("class", "link").attr("stroke-width", 1);
  nodeSel = g.append("g").selectAll("g").data(visN).join("g").attr("class", "node")
    .call(d3.drag().on("start", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e: any, d: any) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e: any, d: any) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));
  nodeSel.append("circle").attr("r", (d: N) => (d.type === "intel" ? 7 : Math.min(5 + d.degree, 13))).attr("fill", (d: N) => COLOR[d.type] || "#64748b")
    .on("click", (_e: any, d: N) => focus(d));
  labelSel = nodeSel.append("text").text((d: N) => (d.type === "intel" || d.degree >= 2 ? d.label : "")).attr("x", 10).attr("y", 4).attr("font-size", "9px").attr("fill", "#cbd5e1");

  sim = d3.forceSimulation(visN)
    .force("link", d3.forceLink(visL).id((d: N) => d.id).distance((l: L) => (l.kind === "indicator" ? 40 : 55)).strength(0.3))
    .force("charge", d3.forceManyBody().strength(-90))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force("collide", d3.forceCollide(14))
    .on("tick", () => {
      linkSel.attr("x1", (d: L) => (d.source as any).x).attr("y1", (d: L) => (d.source as any).y).attr("x2", (d: L) => (d.target as any).x).attr("y2", (d: L) => (d.target as any).y);
      nodeSel.attr("transform", (d: N) => `translate(${d.x},${d.y})`);
    });
  buildAdj();
}

function focus(d: N): void {
  const neigh = adj.get(d.id) || new Set<string>();
  nodeSel.classed("dim", (n: N) => n.id !== d.id && !neigh.has(n.id));
  linkSel.classed("dim", (l: L) => { const s = (l.source as any).id, t = (l.target as any).id; return s !== d.id && t !== d.id; });
  const neighNodes = [...neigh].map((id) => NODES.find((n) => n.id === id)).filter(Boolean) as N[];
  neighNodes.sort((a, b) => b.degree - a.degree);
  // Deep-link to the matching record's edit form in a new tab (CVE→VULNERABILITY, actor→THREATACTOR…).
  // Explorer editCol/editVal → getRowById → edit modal; the node label is the lookup value.
  const fl = FORM_LINK[d.type];
  const col = COLOR[d.type] || "#94a3b8";
  const formLink = fl
    ? `<div style="margin:8px 0"><a class="og-openform" target="_blank" rel="noopener" style="color:${col}"
         href="/?db=${fl.db}&table=${fl.table}&editCol=${fl.editCol}&editVal=${encodeURIComponent(d.label)}"
         >${esc(T(fl.key))} ↗</a></div>`
    : "";
  $("og-panel").innerHTML = `<h3><span style="color:${col}">●</span> ${esc(d.label)}</h3>
    <div class="muted" style="font-size:12px">${esc(typeLabel(d.type))}${d.type !== "intel" ? ` · ${fmt("og.seenIn", { n: d.degree })}` : ""}</div>
    ${formLink}
    ${d.source ? `<div class="k">${T("og.source")}</div>${esc(d.source)}` : ""}
    ${d.date ? `<div class="k">${T("og.date")}</div>${esc(d.date)}` : ""}
    ${d.ref ? `<div class="k">${T("og.reference")}</div><a href="${esc(d.ref)}" target="_blank" rel="noopener" style="word-break:break-all">${esc(d.ref).slice(0, 80)}↗</a>` : ""}
    <div class="k">${fmt("og.connections", { n: neighNodes.length })}</div>
    ${neighNodes.slice(0, 60).map((n) => `<div class="neigh" data-id="${esc(n.id)}"><span style="color:${COLOR[n.type] || "#94a3b8"}">●</span> ${esc(n.label)} <span class="muted" style="font-size:10px">${esc(typeLabel(n.type))}</span></div>`).join("") || `<span class='muted'>${T("og.none")}</span>`}`;
  $("og-panel").querySelectorAll<HTMLElement>(".neigh").forEach((el) => el.addEventListener("click", () => { const n = NODES.find((x) => x.id === el.dataset.id); if (n) focus(n); }));
}

function legend(byType: Record<string, number>): void {
  $("og-legend").innerHTML = Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([t, n]) =>
    `<span class="lg" data-t="${esc(t)}" style="border-color:${COLOR[t] || "#2d3250"}"><span class="dot" style="background:${COLOR[t] || "#64748b"}"></span>${esc(typeLabel(t))} ${n}</span>`).join("");
  $("og-legend").querySelectorAll<HTMLElement>(".lg").forEach((el) => el.addEventListener("click", () => {
    const t = el.dataset.t!; if (hidden.has(t)) hidden.delete(t); else hidden.add(t); el.classList.toggle("off"); render();
  }));
}

function load(): void {
  fetch("/api/osint-graph").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: any) => {
    NODES = d.nodes; LINKS = d.links; const s = d.summary;
    if (!NODES.length) { $("og-graph").innerHTML = `<div class="muted" style="padding:40px;text-align:center">${T("og.empty")}</div>`; return; }
    $("og-kpi").innerHTML = `<div class="k">${T("og.kReports")} <b>${s.items}</b></div><div class="k">${T("og.kEntities")} <b>${s.entities}</b></div><div class="k">${T("og.kLinks")} <b>${s.links}</b></div>` +
      (s.topEntities?.length ? `<div class="k">${T("og.kTop")} ${s.topEntities.slice(0, 3).map((e: any) => `${esc(e.label)} (${e.degree})`).join(", ")}</div>` : "");
    legend(s.byType || {});
    render();
  }).catch((e) => { $("og-graph").innerHTML = `<div class="muted" style="padding:40px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  ($("og-search") as HTMLInputElement).addEventListener("input", (e) => {
    const q = (e.target as HTMLInputElement).value.trim().toLowerCase();
    if (!nodeSel) return;
    if (!q) { nodeSel.classed("dim", false); linkSel.classed("dim", false); return; }
    const match = NODES.find((n) => n.label.toLowerCase().includes(q));
    nodeSel.classed("dim", (n: N) => !n.label.toLowerCase().includes(q));
    linkSel.classed("dim", true);
    if (match) focus(match);
  });
  load();
});
