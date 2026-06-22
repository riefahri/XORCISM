/** ctem.ts — CTEM exposure cockpit (/ctem). Reads /api/ctem; ctem.org standardized taxonomy. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(msg: string): void { const el = $("toast"); el.textContent = msg; el.className = "show"; setTimeout(() => { el.className = ""; }, 2200); }

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const STAGE_DESC: Record<string, string> = { Discover: "found, not yet triaged", Prioritize: "triaged — urgency & impact", Remediate: "in remediation / mobilized" };

function post(url: string): Promise<any> { return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).then((r) => r.json()); }

function load(): void {
  fetch("/api/ctem").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    const s = d.summary;
    const cards = [
      card("Tracked exposures", String(s.tracked), `${s.open} open · ${s.remediated} remediated`),
      card("Critical / High open", `${s.criticalOpen} / ${s.highOpen}`, "by severity", s.criticalOpen ? "#f87171" : "#fbbf24"),
      card("In Prioritize", String(s.inPrioritize), `${s.inDiscover} discover · ${s.inRemediate} remediate`, "#fbbf24"),
      card("Category coverage", `${s.categoriesCovered}/${s.categoriesTotal}`, "categories observed", "#60a5fa"),
      card("Unowned", String(s.unassigned), "open without an owner", s.unassigned ? "#fbbf24" : "#4ade80"),
      card("Catalogue", String(s.catalogueSize), "ctem.org identifiers", "#a78bfa"),
    ].join("");

    // 3-stage flow
    const flow = d.stages.map((st: any, i: number) =>
      `${i ? '<div class="arrow">&#10142;</div>' : ""}<div class="stage s-${esc(st.stage)}"><div class="n">${st.open}</div><div class="t">${esc(st.stage)}</div><div class="d">${esc(STAGE_DESC[st.stage] || "")}</div></div>`).join("");

    // category coverage
    const cats = d.categories.map((c: any) =>
      `<div class="catcard"><div class="cn">${esc(c.name)}</div><div class="cc"><span class="mono">${esc(c.code)}</span> · ${c.catalogue} identifier${c.catalogue > 1 ? "s" : ""}</div>
        <span class="badge ${c.open ? "b-open" : "b-clear"}">${c.open ? `${c.open} open` : (c.tracked ? `${c.tracked} tracked` : "none")}</span></div>`).join("");

    // worklist
    const wl = d.worklist.length
      ? `<table class="t"><thead><tr><th>Identifier</th><th>Exposure</th><th>Category</th><th>Asset / evidence</th><th>Severity</th><th>Stage</th><th>Owner</th><th></th></tr></thead><tbody>${d.worklist.map((e: any) => `<tr>
          <td><a class="mono" href="https://ctem.org/docs/${esc(String(e.ctemId).toLowerCase())}" target="_blank" rel="noopener">${esc(e.ctemId)}</a></td>
          <td class="nm">${esc(e.title)}</td><td>${esc(e.category)}</td>
          <td>${e.asset ? `<span>${esc(e.asset)}</span>` : ""}${e.evidence ? `<div class="muted" style="font-size:11px">${esc(e.evidence)}</div>` : (!e.asset ? '<span class="muted">—</span>' : "")}</td>
          <td><span class="sev sv-${esc(e.severity)}">${esc(e.severity)}</span></td>
          <td><span class="stg stg-${esc(e.stage)}">${esc(e.stage)}</span></td>
          <td>${e.owner ? esc(e.owner) : '<span class="muted">unassigned</span>'}</td>
          <td style="white-space:nowrap">${e.stage !== "Remediate" ? `<button class="btn-sm2" data-adv="${e.id}" title="Advance to the next CTEM stage">&#10142; stage</button> ` : ""}<button class="btn-sm2" data-rem="${e.id}" title="Mark remediated">&#10003;</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:10px 0">No exposures tracked yet. Use <b>Discover from assets</b> to classify internet-exposed assets, or add exposures from the catalogue below.</div>`;

    // catalogue browser
    const cat = d.catalogue;
    const browser = cat.groups.map((g: any) => `<details class="cat"><summary><span class="mono">${esc(g.code)}</span> ${esc(g.name)} <span class="muted" style="font-weight:400">· ${g.items.length}</span></summary>
      ${g.items.map((it: any) => `<div class="ident"><span class="iid">${esc(it.ctemId)}</span> &nbsp;<span class="it">${esc(it.title)}</span><div class="muted" style="margin-top:2px">${esc(it.description)} <a href="${esc(it.link)}" target="_blank" rel="noopener" style="color:#64748b">↗</a></div></div>`).join("")}</details>`).join("");

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">The CTEM program — open exposures by stage</div>
      <div class="flow">${flow}</div>
      <div class="sec">Category coverage <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">${cat.total} identifiers · 8 categories</span></div>
      <div class="catgrid">${cats}</div>
      <div class="sec">Exposure worklist (${d.worklist.length})</div>${wl}
      <div class="sec">ctem.org identifier catalogue</div>${browser}
      <div class="lic">Taxonomy: <a href="${esc(cat.source)}" target="_blank" rel="noopener" style="color:#94a3b8">ctem.org</a> (SecureCoders) · ${esc(cat.total)} identifiers v${esc(cat.version)} · licensed ${esc(cat.license)}. XORCISM tracks your exposures against this standard.</div>`;

    document.querySelectorAll<HTMLButtonElement>("[data-adv]").forEach((b) => b.addEventListener("click", () => {
      post(`/api/ctem/exposure/${b.dataset.adv}/stage`).then((r) => { toast(r.stage ? `Advanced to ${r.stage}` : "Advanced"); load(); }).catch(() => toast("Failed"));
    }));
    document.querySelectorAll<HTMLButtonElement>("[data-rem]").forEach((b) => b.addEventListener("click", () => {
      fetch(`/api/ctem/exposure/${b.dataset.rem}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: "Remediated" }) })
        .then((r) => r.json()).then(() => { toast("Marked remediated"); load(); }).catch(() => toast("Failed"));
    }));
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

document.addEventListener("DOMContentLoaded", () => {
  load();
  $("btn-discover").addEventListener("click", () => {
    const btn = $("btn-discover") as HTMLButtonElement; btn.disabled = true;
    post("/api/ctem/discover").then((r) => { toast(r.created != null ? `Discovered ${r.created} exposure(s) from ${r.scanned} assets` : "Done"); load(); })
      .catch(() => toast("Discovery failed")).finally(() => { btn.disabled = false; });
  });
});
