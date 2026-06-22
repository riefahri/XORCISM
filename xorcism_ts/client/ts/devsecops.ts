/** devsecops.ts — DevSecOps operations cockpit (/devsecops). Reads /api/devsecops. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 2400); }
const SEVS = ["None", "Low", "Medium", "High", "Critical"];
let DATA: any = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const cellSym: Record<string, string> = { pass: "✓", fail: "✗", ran: "•", none: "·" };

function load(): void {
  fetch("/api/devsecops").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d) => {
    DATA = d; const s = d.summary;
    if (!d.apps.length) {
      $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">No applications under DevSecOps yet.<br>Use <b>+ Application</b> to register a repo, then <b>Record scan</b> to log pipeline scan results.</div>`;
      wireActions(); return;
    }
    const cards = [
      card("Applications", String(s.apps), `${s.fullyCovered} fully covered`),
      card("Avg scan coverage", s.avgCoverage + "%", `of ${d.scanTypes.length} scan classes`, s.avgCoverage >= 70 ? "#4ade80" : "#fbbf24"),
      card("Gate-pass rate", s.gatePassRate != null ? s.gatePassRate + "%" : "—", `${s.blockedApps} pipeline-blocked`, s.blockedApps ? "#f87171" : "#4ade80"),
      card("Open critical / high", `${s.openCritical} / ${s.openHigh}`, "across latest scans", s.openCritical ? "#f87171" : "#fbbf24"),
      card("MTTR", s.mttrDays != null ? s.mttrDays + " d" : "—", `${s.remediated} remediated${s.openStreaks ? ` · ${s.openStreaks} open${s.oldestOpenDays != null ? `, oldest ${s.oldestOpenDays}d` : ""}` : ""}`, "#a78bfa"),
      card("Scans (30d)", String(s.scansLast30d), "pipeline runs"),
      card("ASVS verified", s.asvsAvgCoverage != null ? s.asvsAvgCoverage + "%" : "—", `${s.asvsApps} app(s)${s.asvsFailed ? ` · ${s.asvsFailed} failed` : ""}`, "#34d399"),
    ].join("");

    const head = `<th>Application</th><th>Lang</th><th>Crit.</th>` + d.scanTypes.map((t: string) => `<th class="c" title="${esc(t)}">${esc(t.slice(0, 4))}</th>`).join("") + `<th class="c">Crit/High</th><th class="c">Gate</th><th>Coverage</th><th class="c">ASVS</th>`;
    const rows = d.apps.map((a: any) => {
      const cells = a.matrix.map((m: any) => `<td class="c"><span class="cell c-${m.status}" title="${esc(m.type)} · ${esc(m.tool)}${m.status === "none" ? " · not run" : ` · C${m.critical}/H${m.high}${m.gate ? ` · gate ≤${m.gate}` : ""}`}">${cellSym[m.status]}</span></td>`).join("");
      return `<tr>
        <td><span class="nm">${esc(a.name)}</span>${a.repo ? `<div class="mono">${esc(a.repo)}</div>` : ""}</td>
        <td class="muted">${esc(a.language || "—")}</td>
        <td><span class="crat cr-${esc(a.criticality)}">${esc(a.criticality)}</span></td>
        ${cells}
        <td class="c">${a.openCritical ? `<span class="crit">${a.openCritical}</span>` : "0"}/${a.openHigh ? `<span class="high">${a.openHigh}</span>` : "0"}</td>
        <td class="c"><span class="gs gs-${a.gateStatus}">${a.gateStatus === "pass" ? "PASS" : a.gateStatus === "fail" ? "BLOCK" : "—"}</span></td>
        <td><span class="bar"><i style="width:${a.coveragePct}%"></i></span> <span class="muted" style="font-size:11px">${a.coverage}/${d.scanTypes.length}</span></td>
        <td class="c">${a.asvs ? `<button class="btn-sm2" data-asvs="${a.id}" title="ASVS L${a.asvs.level} · ${a.asvs.verified}/${a.asvs.applicable} verified${a.asvs.failed ? ` · ${a.asvs.failed} failed` : ""}"${a.asvs.failed ? ' style="border-color:#f87171"' : ""}>L${a.asvs.level} · ${a.asvs.pct}%</button>` : `<button class="btn-sm2" data-asvs="${a.id}" title="Set ASVS verification">+ ASVS</button>`}</td></tr>`;
    }).join("");

    const gates = d.gates.filter((g: any) => g.scope === "global").map((g: any) => `<div class="gaterow">
      <span class="gt">${esc(g.scanType)}</span><span class="muted">max severity allowed</span>
      <select class="dn" data-gate="${esc(g.scanType)}">${SEVS.map((s2) => `<option${s2 === g.maxSeverity ? " selected" : ""}>${s2}</option>`).join("")}</select>
      <span class="muted" style="font-size:11px">${g.blockOnFail ? "🚫 blocks" : "warns"}</span></div>`).join("");

    const wl = d.worklist.length
      ? `<table class="t"><thead><tr><th>Application</th><th>Scan</th><th>Tool</th><th class="c">Crit</th><th class="c">High</th><th>Gate</th></tr></thead><tbody>${d.worklist.slice(0, 30).map((w: any) => `<tr>
          <td><span class="nm">${esc(w.app)}</span> <span class="crat cr-${esc(w.criticality)}" style="font-size:9px">${esc(w.criticality)}</span></td>
          <td>${esc(w.scanType)}</td><td class="mono">${esc(w.tool)}</td>
          <td class="c">${w.critical ? `<span class="crit">${w.critical}</span>` : "0"}</td><td class="c">${w.high ? `<span class="high">${w.high}</span>` : "0"}</td>
          <td>${w.status === "fail" ? `<span class="gs gs-fail">BLOCKED ≤${esc(w.gate)}</span>` : `<span class="muted">open critical</span>`}</td></tr>`).join("")}</tbody></table>`
      : `<div class="muted" style="padding:8px 0">No gate failures or open criticals. 🎉</div>`;

    const scans = d.scans.slice(0, 20).map((sc: any) => `<tr><td>${esc(sc.app)}</td><td>${esc(sc.scanType)}</td><td class="mono">${esc(sc.tool)}</td>
      <td class="c">${sc.critical ? `<span class="crit">${sc.critical}</span>` : 0}/${sc.high ? `<span class="high">${sc.high}</span>` : 0}/${sc.medium}/${sc.low}</td>
      <td>${sc.gatePassed === false ? `<span class="gs gs-fail">fail</span>` : sc.gatePassed === true ? `<span class="gs gs-pass">pass</span>` : `<span class="muted">—</span>`}</td>
      <td class="muted" style="font-size:11px">${esc(String(sc.ranAt || "").slice(0, 10))}</td></tr>`).join("");

    $("body").innerHTML = `<div class="cards">${cards}</div>
      <div class="sec">Pipeline scan coverage <span class="spacer"></span><span class="muted" style="font-size:11px;text-transform:none;font-weight:400">✓ gate pass · ✗ blocked · • ran · · not run</span></div>
      <table class="t"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>
      <div class="grid2" style="margin-top:18px">
        <div class="panel"><div class="sec" style="margin-top:0">Security gates (global policy)</div>${gates || "<div class='muted'>—</div>"}</div>
        <div class="panel"><div class="sec" style="margin-top:0">By scan class</div>${d.byType.map((t: any) => `<div class="gaterow"><span class="gt">${esc(t.type)}</span><span class="bar"><i style="width:${Math.round((t.apps / d.apps.length) * 100)}%"></i></span><span class="muted" style="font-size:11px">${t.apps}/${d.apps.length} apps${t.fails ? ` · <span class="crit">${t.fails} failing</span>` : ""}</span></div>`).join("")}</div>
      </div>
      <div class="sec">Remediation worklist (${d.worklist.length})</div>${wl}
      <div class="sec">Recent scans</div><table class="t"><thead><tr><th>App</th><th>Scan</th><th>Tool</th><th class="c">C/H/M/L</th><th>Gate</th><th>Ran</th></tr></thead><tbody>${scans}</tbody></table>`;

    document.querySelectorAll<HTMLSelectElement>("[data-gate]").forEach((sel) => sel.addEventListener("change", () => {
      fetch("/api/devsecops/gate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanType: sel.dataset.gate, maxSeverity: sel.value }) })
        .then((r) => r.json()).then(() => { toast(`Gate ${sel.dataset.gate} → max ${sel.value}`); load(); }).catch(() => toast("Failed"));
    }));
    document.querySelectorAll<HTMLButtonElement>("[data-asvs]").forEach((b) => b.addEventListener("click", () => openAsvs(Number(b.dataset.asvs))));
    wireActions();
  }).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; });
}

function closeModal(): void { $("modal").classList.remove("show"); }

// ── OWASP ASVS verification modal (per app) ──────────────────────────────────────────
let asvsDirty = false;
function openAsvs(appId: number): void {
  fetch(`/api/devsecops/asvs/${appId}`).then((r) => r.json()).then((d) => { if (d.error) return void toast(d.error); renderAsvs(appId, d); }).catch(() => toast("Failed"));
}
function renderAsvs(appId: number, d: any): void {
  const c = d.coverage;
  const byCh: Record<string, any[]> = {};
  for (const r of d.requirements) (byCh[r.chapter || "—"] = byCh[r.chapter || "—"] || []).push(r);
  const chCov: Record<string, any> = {};
  for (const c of d.byChapter || []) chCov[c.chapter] = c;
  const levels = [0, 1, 2, 3].map((l) => `<option value="${l}"${l === d.targetLevel ? " selected" : ""}>${l === 0 ? "— none —" : "L" + l}</option>`).join("");
  const sCls = (s: string): string => s === "Verified" ? "color:#4ade80" : s === "Failed" ? "color:#f87171" : /n\/?a/i.test(s) ? "color:#64748b" : "color:#94a3b8";
  const chBadge = (ch: string): string => { const c = chCov[ch]; return c ? `<span style="font-weight:400;color:${c.failed ? "#f87171" : c.pct >= 80 ? "#34d399" : "#94a3b8"}">${c.verified}/${c.applicable} · ${c.pct}%${c.failed ? ` · ${c.failed}✗` : ""}</span>` : ""; };
  const groups = Object.keys(byCh).map((ch) => `<div style="margin-top:8px"><div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.4px;display:flex;justify-content:space-between;align-items:baseline">${esc(ch)}${chBadge(ch)}</div>${byCh[ch].map((r) => `<div style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:12px;border-bottom:1px solid #1e2133">
      <span class="mono" style="min-width:62px" title="${esc(r.statement)}">${esc(r.shortcode)}</span>
      <span style="flex:1;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.statement)}">${esc(r.statement)}</span>
      <select class="dn" data-req="${esc(r.shortcode)}" style="${sCls(r.status)}">${d.statuses.map((s: string) => `<option${s === r.status ? " selected" : ""}>${esc(s)}</option>`).join("")}</select></div>`).join("")}</div>`).join("");
  $("mbox").innerHTML = `<h3>OWASP ASVS — ${esc(d.app)}</h3>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><label style="margin:0;color:#94a3b8;font-size:12px">Target level</label><select id="asvs-level" class="dn">${levels}</select>
      <span class="muted" style="font-size:12px;flex:1">${d.targetLevel ? `${c.verified}/${c.inScope} verified · <b style="color:#34d399">${c.pct}%</b>${c.failed ? ` · <span style="color:#f87171">${c.failed} failed</span>` : ""}${c.na ? ` · ${c.na} N/A` : ""}` : "set a target level (L1 / L2 / L3) to verify against"}</span></div>
    <div style="max-height:52vh;overflow:auto">${groups || "<div class='muted' style='padding:10px 0'>Pick a target level to load the applicable requirements.</div>"}</div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px"><span class="muted" style="font-size:11px">ASVS 4.0.3 · ${d.catalogueSize} requirements in catalogue</span><button class="btn-sm2" id="asvs-close">Close</button></div>`;
  $("modal").classList.add("show");
  $("asvs-close").onclick = () => { closeModal(); if (asvsDirty) { asvsDirty = false; load(); } };
  $("asvs-level").addEventListener("change", (e) => {
    asvsDirty = true;
    fetch(`/api/devsecops/asvs/${appId}/level`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ level: Number((e.target as HTMLSelectElement).value) }) })
      .then((r) => r.json()).then(() => openAsvs(appId)).catch(() => toast("Failed"));
  });
  document.querySelectorAll<HTMLSelectElement>("[data-req]").forEach((sel) => sel.addEventListener("change", () => {
    asvsDirty = true; sel.style.cssText = sCls(sel.value);
    fetch(`/api/devsecops/asvs/${appId}/status`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ shortcode: sel.dataset.req, status: sel.value }) })
      .then((r) => r.json()).then(() => toast(`${sel.dataset.req} → ${sel.value}`)).catch(() => toast("Failed"));
  }));
}
function openApp(): void {
  $("mbox").innerHTML = `<h3>Register application</h3>
    <label>Name *</label><input id="a-name" placeholder="payments-api">
    <label>Repository</label><input id="a-repo" placeholder="github.com/acme/payments-api">
    <div class="row3"><div><label>Language</label><input id="a-lang" placeholder="Go"></div><div><label>Team</label><input id="a-team"></div><div style="grid-column:span 2"><label>Criticality</label><select id="a-crit"><option>Low</option><option>Medium</option><option selected>High</option><option>Critical</option></select></div></div>
    <label>Pipeline URL</label><input id="a-pipe" placeholder="https://ci.acme.dev/payments-api">
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="btn-sm2" id="a-cancel">Cancel</button><button class="btn" id="a-save">Register</button></div>`;
  $("modal").classList.add("show");
  $("a-cancel").onclick = closeModal;
  $("a-save").onclick = () => {
    const name = ($("a-name") as HTMLInputElement).value.trim(); if (!name) return void toast("Name required");
    fetch("/api/devsecops/app", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, repo: ($("a-repo") as HTMLInputElement).value.trim(), language: ($("a-lang") as HTMLInputElement).value.trim(), team: ($("a-team") as HTMLInputElement).value.trim(), criticality: ($("a-crit") as HTMLSelectElement).value, pipelineUrl: ($("a-pipe") as HTMLInputElement).value.trim() }) })
      .then((r) => r.json()).then((d) => { if (d.error) throw new Error(d.error); closeModal(); toast("Application registered"); load(); }).catch((e) => toast("Failed: " + e.message));
  };
}
function openScan(): void {
  const apps = (DATA?.apps || []) as any[];
  $("mbox").innerHTML = `<h3>Record pipeline scan</h3>
    <label>Application *</label><select id="s-app">${apps.map((a) => `<option value="${a.id}">${esc(a.name)}</option>`).join("")}</select>
    <div class="row3" style="grid-template-columns:1fr 1fr"><div><label>Scan class *</label><select id="s-type">${(DATA?.scanTypes || []).map((t: string) => `<option>${t}</option>`).join("")}</select></div><div><label>Tool</label><input id="s-tool" placeholder="semgrep"></div></div>
    <label>Findings by severity</label>
    <div class="row3"><div><label style="font-size:10px">Critical</label><input id="s-c" type="number" value="0"></div><div><label style="font-size:10px">High</label><input id="s-h" type="number" value="0"></div><div><label style="font-size:10px">Medium</label><input id="s-m" type="number" value="0"></div><div><label style="font-size:10px">Low</label><input id="s-l" type="number" value="0"></div></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px"><button class="btn-sm2" id="s-cancel">Cancel</button><button class="btn" id="s-save">Record</button></div>`;
  $("modal").classList.add("show");
  $("s-cancel").onclick = closeModal;
  $("s-save").onclick = () => {
    const body = { appId: Number(($("s-app") as HTMLSelectElement).value), scanType: ($("s-type") as HTMLSelectElement).value, tool: ($("s-tool") as HTMLInputElement).value.trim() || undefined, critical: +($("s-c") as HTMLInputElement).value, high: +($("s-h") as HTMLInputElement).value, medium: +($("s-m") as HTMLInputElement).value, low: +($("s-l") as HTMLInputElement).value };
    fetch("/api/devsecops/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then((r) => r.json()).then((d) => { if (d.error) throw new Error(d.error); closeModal(); toast(d.gatePassed === false ? "Scan recorded — gate BLOCKED" : "Scan recorded — gate passed"); load(); }).catch((e) => toast("Failed: " + e.message));
  };
}
function wireActions(): void { $("btn-newapp").onclick = openApp; $("btn-scan").onclick = openScan; $("modal").onclick = (e) => { if (e.target === $("modal")) closeModal(); }; }

document.addEventListener("DOMContentLoaded", load);
