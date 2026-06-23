/** privacy.ts — GDPR / DPO cockpit (/privacy). RoPA + DSAR + DPIA + breach register + worklist.
 *  Reads /api/privacy; create paths POST processing / dsar / breach. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Data {
  summary: { processing: number; processingNoBasis: number; dsarTotal: number; dsarOpen: number; dsarOverdue: number; dpiaTotal: number; dpiaApproved: number; dpiaGaps: number; breaches: number; breachesUnnotified: number; breach72: number; score: number; grade: string };
  processing: any[]; dsars: any[]; dpias: any[]; breaches: any[]; worklist: { kind: string; label: string; severity: string; ref: string }[];
  legalBases: string[]; dsarTypes: string[];
}
let DATA: Data | null = null;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;
const pill = (txt: string, cls: string): string => `<span class="pill ${cls}">${esc(txt)}</span>`;

function render(): void {
  const d = DATA!; const s = d.summary;
  const cards = [
    card("DPO posture", `<span class="grade g-${s.grade}">${s.score}</span><span style="font-size:13px;color:#64748b">/100</span>`, `grade ${s.grade}`),
    card("Processing (RoPA)", String(s.processing), `${s.processingNoBasis} without legal basis`, s.processingNoBasis ? "#fb923c" : "#34d399"),
    card("Data-subject requests", String(s.dsarOpen), `${s.dsarOverdue} overdue · ${s.dsarTotal} total`, s.dsarOverdue ? "#f87171" : "#34d399"),
    card("DPIAs", `${s.dpiaApproved}/${s.dpiaTotal}`, `${s.dpiaGaps} high-risk gap(s)`, s.dpiaGaps ? "#fb923c" : "#34d399"),
    card("Breaches", String(s.breaches), `${s.breach72} past 72h unnotified`, s.breach72 ? "#f87171" : s.breachesUnnotified ? "#fbbf24" : "#34d399"),
  ].join("");

  const work = d.worklist.length
    ? `<ul class="worklist">${d.worklist.map((w) => `<li><span class="sev sv-${["Critical", "High", "Medium", "Low"].includes(w.severity) ? w.severity : "Low"}">${esc(w.severity)}</span> <span>${esc(w.label)}</span><span class="muted" style="margin-left:auto;font-size:11px">${esc(w.ref)}</span></li>`).join("")}</ul>`
    : `<div class="muted" style="padding:8px 0">✓ No outstanding DPO actions.</div>`;

  const proc = d.processing.length
    ? `<table class="pt"><thead><tr><th>Processing activity</th><th>Purpose</th><th>Legal basis</th><th>Data</th><th>DPIA</th></tr></thead><tbody>${d.processing.map((p) => `<tr>
        <td><span class="nm">${esc(p.name)}</span>${p.crossBorder ? " " + pill("transfer", "p-info") : ""}</td>
        <td class="muted">${esc(p.purpose || "—")}</td>
        <td>${p.legalBasis ? esc(p.legalBasis) : pill("missing", "p-bad")}</td>
        <td>${p.special ? pill("special cat.", "p-warn") + " " : ""}<span class="pill ${/high/i.test(p.riskLevel) ? "p-bad" : "p-info"}">${esc(p.riskLevel || "—")}</span></td>
        <td>${p.dpiaApproved ? pill("approved", "p-ok") : p.hasDpia ? pill("draft", "p-warn") : (/high/i.test(p.riskLevel) || p.special ? pill("required", "p-bad") : "<span class='muted'>n/a</span>")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No processing activities recorded — add your first RoPA entry.</div>`;

  const dsarRows = d.dsars.length
    ? `<table class="pt"><thead><tr><th>Subject</th><th>Type</th><th>Received</th><th>Due</th><th>Status</th><th></th></tr></thead><tbody>${d.dsars.map((r) => `<tr>
        <td class="nm">${esc(r.subject)}</td><td>${esc(r.type)}</td><td class="muted">${esc(r.received)}</td>
        <td>${r.overdue ? pill("overdue " + esc(r.due), "p-bad") : esc(r.due) + (r.daysLeft != null && !r.closed ? ` <span class="muted">(${r.daysLeft}d)</span>` : "")}</td>
        <td>${r.closed ? pill(esc(r.status || "done"), "p-ok") : pill(esc(r.status || "new"), r.overdue ? "p-bad" : "p-warn")}</td>
        <td>${r.closed ? "" : `<button class="btn-sm2" data-dsar-done="${r.id}">Complete</button>`}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No data-subject requests logged.</div>`;

  const breachRows = d.breaches.length
    ? `<table class="pt"><thead><tr><th>Breach</th><th>Detected</th><th>Affected</th><th>Severity</th><th>72h / Art 33</th></tr></thead><tbody>${d.breaches.map((b) => `<tr>
        <td class="nm">${esc(b.title)}</td><td class="muted">${esc(String(b.detected))}</td><td>${b.affected || "—"}</td>
        <td><span class="pill ${/high|crit/i.test(b.severity) ? "p-bad" : "p-info"}">${esc(b.severity || "—")}</span></td>
        <td>${b.notifiedAuthority ? pill("notified", "p-ok") : b.breached72 ? pill("breached " + (b.hoursSinceDetected ?? "?") + "h", "p-bad") : pill((b.hoursSinceDetected ?? 0) + "h elapsed", "p-warn")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">No personal-data breaches recorded.</div>`;

  $("body").innerHTML = `<div class="cards">${cards}</div>
    <div class="sec">⚖️ DPO worklist (${d.worklist.length})</div><div class="panel">${work}</div>
    <div class="sec">📒 Records of Processing Activities — RoPA (${d.processing.length})</div><div class="panel">${proc}</div>
    <div class="sec">📨 Data-subject requests — DSAR (${d.dsars.length})</div><div class="panel">${dsarRows}</div>
    <div class="sec">🚨 Personal-data breach register (${d.breaches.length})</div><div class="panel">${breachRows}</div>`;

  Array.prototype.forEach.call(document.querySelectorAll("[data-dsar-done]"), (b: HTMLElement) => {
    b.onclick = () => act(`/api/privacy/dsar/${b.getAttribute("data-dsar-done")}/status`, { status: "Completed" }, "Request completed");
  });
}

function act(url: string, body: unknown, okMsg: string): void {
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then(() => { toast(okMsg); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
}
function closeModal(): void { $("modal").classList.remove("show"); }
function openModal(html: string): void { $("dlg").innerHTML = html; $("modal").classList.add("show"); const c = document.getElementById("dlg-close"); if (c) c.onclick = closeModal; }

function procDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">New processing activity (RoPA)</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">Close</button></div>
    <label>Name<input id="f-name" placeholder="e.g. Customer CRM"></label>
    <label>Purpose<input id="f-purpose" placeholder="why the data is processed"></label>
    <div class="row"><label>Legal basis (Art 6)<select id="f-basis"><option value="">— select —</option>${d.legalBases.map((b) => `<option>${esc(b)}</option>`).join("")}</select></label>
      <label>Risk level<select id="f-risk"><option>Low</option><option selected>Medium</option><option>High</option></select></label></div>
    <label>Data categories<input id="f-cats" placeholder="e.g. name, email, payment data"></label>
    <label>Data subjects<input id="f-subj" placeholder="e.g. customers, employees"></label>
    <label>Retention period<input id="f-ret" placeholder="e.g. account life + 3 years"></label>
    <div class="chk"><input type="checkbox" id="f-special"> Special-category data (Art 9)</div>
    <div class="chk"><input type="checkbox" id="f-cross"> Cross-border transfer (outside EEA)</div>
    <label>Transfer safeguard (if any)<input id="f-safeguard" placeholder="e.g. SCCs, adequacy decision"></label>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#fb923c;color:#fdba74">Add to RoPA</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const name = ($("f-name") as HTMLInputElement).value.trim();
    if (!name) { toast("Name required"); return; }
    fetch("/api/privacy/processing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      name, purpose: ($("f-purpose") as HTMLInputElement).value, legalBasis: ($("f-basis") as HTMLSelectElement).value, riskLevel: ($("f-risk") as HTMLSelectElement).value,
      dataCategories: ($("f-cats") as HTMLInputElement).value, dataSubjects: ($("f-subj") as HTMLInputElement).value, retention: ($("f-ret") as HTMLInputElement).value,
      specialCategories: ($("f-special") as HTMLInputElement).checked, crossBorder: ($("f-cross") as HTMLInputElement).checked, transferSafeguard: ($("f-safeguard") as HTMLInputElement).value }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Added to RoPA"); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function dsarDialog(): void {
  const d = DATA!;
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">New data-subject request</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">Close</button></div>
    <label>Data subject<input id="f-subject" placeholder="name"></label>
    <label>Email<input id="f-email" placeholder="optional"></label>
    <div class="row"><label>Type<select id="f-type">${d.dsarTypes.map((tt) => `<option>${esc(tt)}</option>`).join("")}</select></label>
      <label>Received date<input id="f-recv" type="date"></label></div>
    <div class="muted" style="font-size:11px;margin-top:6px">The 1-month statutory due date (GDPR Art 12) is set automatically.</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#fb923c;color:#fdba74">Log request</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const subjectName = ($("f-subject") as HTMLInputElement).value.trim();
    if (!subjectName) { toast("Subject required"); return; }
    fetch("/api/privacy/dsar", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      subjectName, subjectEmail: ($("f-email") as HTMLInputElement).value, requestType: ($("f-type") as HTMLSelectElement).value, receivedDate: ($("f-recv") as HTMLInputElement).value || undefined }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then((j) => { toast("Logged · due " + (j.dueDate || "")); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function breachDialog(): void {
  openModal(`<div style="display:flex;align-items:center;margin-bottom:6px"><b style="font-size:15px;color:#e7ebf3">Record personal-data breach</b><span style="flex:1"></span><button class="btn-sm2" id="dlg-close">Close</button></div>
    <label>Title<input id="f-title" placeholder="short description"></label>
    <label>Description<textarea id="f-desc" rows="3"></textarea></label>
    <div class="row"><label>Affected subjects<input id="f-aff" type="number" placeholder="count"></label>
      <label>Severity<select id="f-sev"><option>Low</option><option selected>Medium</option><option>High</option><option>Critical</option></select></label>
      <label>Risk to subjects<select id="f-risk"><option>Low</option><option selected>Medium</option><option>High</option></select></label></div>
    <label>Data categories<input id="f-cats" placeholder="e.g. name, email"></label>
    <div class="muted" style="font-size:11px;margin-top:6px">The 72-hour authority-notification clock (Art 33) starts at detection (now).</div>
    <div style="display:flex;justify-content:flex-end;margin-top:12px"><button class="btn-sm2" id="f-save" style="border-color:#f87171;color:#fca5a5">Record breach</button></div>`);
  ($("f-save") as HTMLButtonElement).onclick = () => {
    const title = ($("f-title") as HTMLInputElement).value.trim();
    if (!title) { toast("Title required"); return; }
    fetch("/api/privacy/breach", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      title, description: ($("f-desc") as HTMLTextAreaElement).value, affectedSubjects: Number(($("f-aff") as HTMLInputElement).value) || 0,
      severity: ($("f-sev") as HTMLSelectElement).value, riskToSubjects: ($("f-risk") as HTMLSelectElement).value, dataCategories: ($("f-cats") as HTMLInputElement).value }) })
      .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
      .then(() => { toast("Breach recorded"); closeModal(); reload().then(render); }).catch((e) => toast("⚠️ " + (e.message || e)));
  };
}

function reload(): Promise<void> {
  return fetch("/api/privacy").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) closeModal(); });
  ($("btn-proc") as HTMLButtonElement).onclick = procDialog;
  ($("btn-dsar") as HTMLButtonElement).onclick = dsarDialog;
  ($("btn-breach") as HTMLButtonElement).onclick = breachDialog;
  reload().then(render).catch((e) => { $("body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
