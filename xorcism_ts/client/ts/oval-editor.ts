/**
 * oval-editor.ts — advanced OVAL Definition editor (/oval-editor).
 *
 * Metadata form (class/family comboboxes, title, description, references) + a recursive criteria-tree
 * builder whose leaves reuse the OVAL tests and definitions already imported in XOVAL (autocomplete
 * comboboxes over /api/oval/test-search and /api/oval/def-search). Generates OVAL 5.11 XML (preview)
 * and saves relationally + as a generated document via /api/oval/definition.
 */
export {}; // module scope (keeps $/esc/toast local, not global) — esbuild bundles this entry standalone
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface CriteriaNode { kind: "criteria"; operator: string; negate: boolean; applicabilityCheck: boolean; comment: string; children: TreeNode[]; }
interface CriterionLeaf { kind: "criterion"; testId: number; testIdPattern?: string; testComment?: string; hasContent?: boolean; negate: boolean; comment: string; }
interface ExtendLeaf { kind: "extend"; defId: number; defIdPattern?: string; defTitle?: string; negate: boolean; comment: string; }
type TreeNode = CriteriaNode | CriterionLeaf | ExtendLeaf;

interface Enums { classes: { id: number; value: string }[]; operators: string[]; families: string[]; namespace: string; schemaVersion: string; schemaVersions: string[]; }

let enums: Enums = { classes: [], operators: ["AND", "OR", "ONE", "XOR"], families: [], namespace: "ai.xorcism", schemaVersion: "5.12.3", schemaVersions: ["5.12.3", "5.12.1", "5.11.2"] };
let root: CriteriaNode = newCriteria();
let refs: { source: string; refId: string; refUrl: string }[] = [];
let loadedIdPattern = "";   // set when editing an authored def (drives update vs create)

function newCriteria(): CriteriaNode { return { kind: "criteria", operator: "AND", negate: false, applicabilityCheck: false, comment: "", children: [] }; }

function toast(msg: string, kind: "ok" | "err" = "ok"): void {
  const el = $("toast");
  el.textContent = msg;
  el.style.cssText = `position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#13162a;border:1px solid ${kind === "err" ? "#f87171" : "#34d399"};color:#e2e8f0;border-radius:10px;padding:11px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,.5);z-index:1100`;
  window.setTimeout(() => { el.textContent = ""; el.style.cssText = ""; }, 6000);
}

// ── autocomplete combobox over a search endpoint ───────────────────────────────
function attachAutocomplete(
  input: HTMLInputElement, holder: HTMLElement, endpoint: string,
  fmt: (item: Record<string, unknown>) => string, onPick: (item: Record<string, unknown>) => void,
): void {
  let timer = 0; let box: HTMLDivElement | null = null;
  const close = (): void => { if (box) { box.remove(); box = null; } };
  input.addEventListener("input", () => {
    const q = input.value.trim();
    window.clearTimeout(timer);
    if (q.length < 2) { close(); return; }
    timer = window.setTimeout(async () => {
      try {
        const r = await fetch(`${endpoint}?q=${encodeURIComponent(q)}`);
        if (!r.ok) return;
        const items = (await r.json()) as Record<string, unknown>[];
        close();
        if (!items.length) return;
        box = document.createElement("div"); box.className = "ac";
        for (const it of items.slice(0, 50)) {
          const d = document.createElement("div"); d.innerHTML = fmt(it);
          d.onmousedown = (e) => { e.preventDefault(); onPick(it); close(); };
          box.appendChild(d);
        }
        holder.appendChild(box);
      } catch { /* search unavailable */ }
    }, 220);
  });
  input.addEventListener("blur", () => window.setTimeout(close, 180));
}

// ── tree rendering ─────────────────────────────────────────────────────────────
function renderTree(): void {
  const host = $("ox-tree"); host.innerHTML = "";
  host.appendChild(renderCriteria(root, null));
}

function opSelect(node: CriteriaNode): HTMLSelectElement {
  const sel = document.createElement("select");
  for (const o of enums.operators) { const opt = document.createElement("option"); opt.value = o; opt.textContent = o; if (o === node.operator) opt.selected = true; sel.appendChild(opt); }
  sel.onchange = () => { node.operator = sel.value; };
  sel.className = "op";
  return sel;
}
function ck(labelTxt: string, checked: boolean, on: (v: boolean) => void): HTMLLabelElement {
  const l = document.createElement("label"); l.className = "ox-ck"; l.style.fontSize = "11.5px";
  const i = document.createElement("input"); i.type = "checkbox"; i.checked = checked; i.onchange = () => on(i.checked);
  l.appendChild(i); l.appendChild(document.createTextNode(" " + labelTxt));
  return l;
}
function commentInput(val: string, on: (v: string) => void, ph = "comment"): HTMLInputElement {
  const i = document.createElement("input"); i.type = "text"; i.className = "cmt"; i.placeholder = ph; i.value = val || ""; i.oninput = () => on(i.value);
  return i;
}
function rmBtn(on: () => void): HTMLButtonElement {
  const b = document.createElement("button"); b.type = "button"; b.className = "btn-rm"; b.textContent = "✕"; b.title = "Remove"; b.onclick = on; return b;
}
function miniBtn(txt: string, on: () => void): HTMLButtonElement {
  const b = document.createElement("button"); b.type = "button"; b.className = "btn-mini"; b.textContent = txt; b.onclick = on; return b;
}

function renderCriteria(node: CriteriaNode, removeSelf: (() => void) | null): HTMLElement {
  const box = document.createElement("div"); box.className = "node-criteria";
  const head = document.createElement("div"); head.className = "node-head";
  const lbl = document.createElement("span"); lbl.textContent = removeSelf ? "Group" : "Criteria (root)"; lbl.style.cssText = "font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.4px";
  head.appendChild(lbl);
  head.appendChild(opSelect(node));
  head.appendChild(ck("negate", node.negate, (v) => { node.negate = v; }));
  head.appendChild(ck("applicability", node.applicabilityCheck, (v) => { node.applicabilityCheck = v; }));
  head.appendChild(commentInput(node.comment, (v) => { node.comment = v; }));
  head.appendChild(miniBtn("＋ Test", () => { node.children.push({ kind: "criterion", testId: 0, negate: false, comment: "" }); renderTree(); }));
  head.appendChild(miniBtn("＋ Extend", () => { node.children.push({ kind: "extend", defId: 0, negate: false, comment: "" }); renderTree(); }));
  head.appendChild(miniBtn("＋ Group", () => { node.children.push(newCriteria()); renderTree(); }));
  if (removeSelf) head.appendChild(rmBtn(removeSelf));
  box.appendChild(head);

  const kids = document.createElement("div"); kids.className = "node-children";
  if (!node.children.length) { const e = document.createElement("div"); e.className = "muted"; e.style.cssText = "font-size:11.5px;padding:4px 0"; e.textContent = "Empty — add a test, an extend_definition, or a nested group."; kids.appendChild(e); }
  node.children.forEach((child, i) => {
    const remove = (): void => { node.children.splice(i, 1); renderTree(); };
    if (child.kind === "criteria") kids.appendChild(renderCriteria(child, remove));
    else if (child.kind === "criterion") kids.appendChild(renderCriterion(child, remove));
    else kids.appendChild(renderExtend(child, remove));
  });
  box.appendChild(kids);
  return box;
}

function renderCriterion(leaf: CriterionLeaf, remove: () => void): HTMLElement {
  const wrap = document.createElement("div");
  const row = document.createElement("div"); row.className = "leaf criterion";
  const tag = document.createElement("span"); tag.textContent = "criterion → test"; tag.style.cssText = "font-size:10.5px;color:#34d399;align-self:center"; row.appendChild(tag);
  const pick = document.createElement("div"); pick.className = "pick";
  const input = document.createElement("input"); input.type = "text"; input.placeholder = "search OVAL test (id or comment)…"; input.value = leaf.testIdPattern || "";
  const sel = document.createElement("div"); sel.className = "sel";
  const refresh = (): void => {
    sel.textContent = leaf.testId
      ? `✓ ${leaf.testIdPattern || "#" + leaf.testId}${leaf.hasContent ? " ●" : ""}${leaf.testComment ? " — " + leaf.testComment : ""}`
      : "no test selected";
  };
  refresh();
  attachAutocomplete(input, pick, "/api/oval/test-search",
    (it) => `<span class="id">${esc(it.idPattern)}</span>${it.hasContent ? ' <span title="content available" style="color:#34d399">●</span>' : ""} — ${esc(String(it.comment || "").slice(0, 88))}`,
    (it) => { leaf.testId = Number(it.id); leaf.testIdPattern = String(it.idPattern); leaf.testComment = String(it.comment || ""); leaf.hasContent = !!it.hasContent; input.value = String(it.idPattern); refresh(); });
  pick.appendChild(input); pick.appendChild(sel);
  row.appendChild(pick);
  // 👁 view test content (criterion/tst)
  const detail = document.createElement("div");
  const eye = miniBtn("👁", () => { void toggleTestView(leaf, detail, eye); });
  eye.title = "View test content (object / states)";
  row.appendChild(eye);
  row.appendChild(ck("negate", leaf.negate, (v) => { leaf.negate = v; }));
  row.appendChild(commentInput(leaf.comment, (v) => { leaf.comment = v; }));
  row.appendChild(rmBtn(remove));
  wrap.appendChild(row); wrap.appendChild(detail);
  return wrap;
}

// ── test-content inspector (fetches /api/oval/test) ─────────────────────────────
interface TestEntity { name: string; operation?: string; datatype?: string; varRef?: string; value?: string; }
interface TestView {
  idPattern: string; comment?: string; hasContent: boolean; type?: string; family?: string; check?: string; checkExistence?: string;
  object?: { id: string; comment?: string; entities: TestEntity[]; xml: string };
  states?: { id: string; comment?: string; entities: TestEntity[]; xml: string }[];
  variables?: { id: string; type: string; xml: string }[]; xml?: string;
}
function entTable(entities: TestEntity[]): string {
  if (!entities.length) return "";
  return `<table><tr><th>entity</th><th>op</th><th>datatype</th><th>value</th></tr>` +
    entities.map((e) => `<tr><td class="ent-name">${esc(e.name)}</td><td>${esc(e.operation || "equals")}</td><td>${esc(e.datatype || "string")}</td><td>${e.varRef ? `<i>var: ${esc(e.varRef)}</i>` : esc(e.value || "")}</td></tr>`).join("") +
    `</table>`;
}
async function toggleTestView(leaf: CriterionLeaf, host: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (host.innerHTML) { host.innerHTML = ""; btn.classList.remove("active"); return; }
  if (!leaf.testIdPattern) { host.innerHTML = `<div class="tst-view none">Select a test first.</div>`; return; }
  host.innerHTML = `<div class="tst-view">Loading…</div>`; btn.classList.add("active");
  try {
    const r = await fetch(`/api/oval/test?id=${encodeURIComponent(leaf.testIdPattern)}`);
    const d = (await r.json()) as TestView;
    if (!r.ok) throw new Error((d as unknown as { error?: string }).error || `HTTP ${r.status}`);
    if (!d.hasContent) {
      host.innerHTML = `<div class="tst-view"><div class="meta"><span><b>${esc(d.idPattern)}</b></span></div>` +
        `<div>${esc(d.comment || "(no comment)")}</div>` +
        `<div class="none" style="margin-top:6px">No test content imported yet. Use <b>⬆ Import test content</b> to upload the OVAL document that defines this test.</div></div>`;
      return;
    }
    const obj = d.object
      ? `<div class="sec">object — ${esc(d.object.id)}</div>${entTable(d.object.entities)}`
      : `<div class="sec none">no object</div>`;
    const states = (d.states && d.states.length)
      ? d.states.map((s) => `<div class="sec">state — ${esc(s.id)}</div>${entTable(s.entities)}`).join("")
      : `<div class="sec">no state (existence check only)</div>`;
    host.innerHTML =
      `<div class="tst-view">
        <div class="meta">
          <span><b>${esc(d.idPattern)}</b></span>
          ${d.type ? `<span>type: <b>${esc(d.family ? d.family + ":" : "")}${esc(d.type)}</b></span>` : ""}
          ${d.check ? `<span>check: <b>${esc(d.check)}</b></span>` : ""}
          ${d.checkExistence ? `<span>existence: <b>${esc(d.checkExistence)}</b></span>` : ""}
        </div>
        ${d.comment ? `<div>${esc(d.comment)}</div>` : ""}
        ${obj}${states}
        <details style="margin-top:6px"><summary class="sec" style="cursor:pointer">raw bundle XML</summary><pre>${esc(d.xml || "")}</pre></details>
      </div>`;
  } catch (e) { host.innerHTML = `<div class="tst-view none">⚠️ ${esc(String(e))}</div>`; }
}

function renderExtend(leaf: ExtendLeaf, remove: () => void): HTMLElement {
  const row = document.createElement("div"); row.className = "leaf extend";
  const tag = document.createElement("span"); tag.textContent = "extend_definition"; tag.style.cssText = "font-size:10.5px;color:#fbbf24;align-self:center"; row.appendChild(tag);
  const pick = document.createElement("div"); pick.className = "pick";
  const input = document.createElement("input"); input.type = "text"; input.placeholder = "search OVAL definition (id or title)…"; input.value = leaf.defIdPattern || "";
  const sel = document.createElement("div"); sel.className = "sel"; sel.style.color = "#fbbf24";
  const refresh = (): void => { sel.textContent = leaf.defId ? `✓ ${leaf.defIdPattern || "#" + leaf.defId}${leaf.defTitle ? " — " + leaf.defTitle : ""}` : "no definition selected"; };
  refresh();
  attachAutocomplete(input, pick, "/api/oval/def-search",
    (it) => `<span class="id">${esc(it.idPattern)}</span> — ${esc(String(it.title || "").slice(0, 90))}`,
    (it) => { leaf.defId = Number(it.id); leaf.defIdPattern = String(it.idPattern); leaf.defTitle = String(it.title || ""); input.value = String(it.idPattern); refresh(); });
  pick.appendChild(input); pick.appendChild(sel);
  row.appendChild(pick);
  row.appendChild(ck("negate", leaf.negate, (v) => { leaf.negate = v; }));
  row.appendChild(commentInput(leaf.comment, (v) => { leaf.comment = v; }));
  row.appendChild(rmBtn(remove));
  return row;
}

// ── references rows ────────────────────────────────────────────────────────────
function renderRefs(): void {
  const host = $("ox-refs"); host.innerHTML = "";
  refs.forEach((r, i) => {
    const row = document.createElement("div"); row.className = "ref-row";
    const mk = (ph: string, key: "source" | "refId" | "refUrl", w?: string): HTMLInputElement => {
      const inp = document.createElement("input"); inp.type = "text"; inp.placeholder = ph; inp.value = r[key]; if (w) inp.style.flex = w;
      inp.oninput = () => { r[key] = inp.value; }; return inp;
    };
    row.appendChild(mk("source (CVE/CCE)", "source", "0 0 130px"));
    row.appendChild(mk("ref_id (CVE-2024-…)", "refId"));
    row.appendChild(mk("ref_url (optional)", "refUrl"));
    row.appendChild(rmBtn(() => { refs.splice(i, 1); renderRefs(); }));
    host.appendChild(row);
  });
}

// ── metadata <-> form ──────────────────────────────────────────────────────────
function collectMeta(): Record<string, unknown> {
  const v = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement).value;
  const classSel = $("ox-class") as HTMLSelectElement;
  return {
    idPattern: loadedIdPattern || undefined,
    version: Number(v("ox-version")) || 1,
    classId: v("ox-class") ? Number(v("ox-class")) : null,
    className: classSel.options[classSel.selectedIndex]?.textContent || "",
    title: v("ox-title").trim(), description: v("ox-desc").trim(),
    deprecated: ($("ox-deprecated") as HTMLInputElement).checked,
    family: v("ox-family"), platform: v("ox-platform").trim(),
    schemaVersion: v("ox-schema") || enums.schemaVersion,
    selfContained: ($("ox-selfcontained") as HTMLInputElement).checked,
    references: refs.filter((r) => r.source || r.refId),
  };
}

function applyMeta(m: Record<string, unknown>): void {
  ($("ox-idPattern") as HTMLInputElement).value = String(m.idPattern || "");
  ($("ox-version") as HTMLInputElement).value = String(m.version || 1);
  ($("ox-class") as HTMLSelectElement).value = m.classId != null ? String(m.classId) : "";
  ($("ox-family") as HTMLSelectElement).value = String(m.family || "");
  ($("ox-title") as HTMLInputElement).value = String(m.title || "");
  ($("ox-desc") as HTMLTextAreaElement).value = String(m.description || "");
  ($("ox-platform") as HTMLInputElement).value = String(m.platform || "");
  ($("ox-deprecated") as HTMLInputElement).checked = !!m.deprecated;
}

// ── actions ──────────────────────────────────────────────────────────────────
function showXml(xml: string): void { $("ox-xmlwrap").style.display = "block"; $("ox-xml").textContent = xml; }

async function preview(): Promise<void> {
  $("ox-status").textContent = "Generating…";
  try {
    const r = await fetch("/api/oval/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ meta: collectMeta(), tree: root }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    showXml(d.xml); $("ox-status").textContent = "Preview generated (not saved).";
  } catch (e) { $("ox-status").textContent = `⚠️ ${e}`; }
}

async function save(): Promise<void> {
  const meta = collectMeta();
  if (!String(meta.title || "").trim()) { $("ox-status").textContent = "⚠️ A title is required."; return; }
  const btn = $("ox-save") as HTMLButtonElement; btn.disabled = true; $("ox-status").textContent = "Saving…";
  try {
    const r = await fetch("/api/oval/definition", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ meta, tree: root }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    loadedIdPattern = d.idPattern;
    ($("ox-idPattern") as HTMLInputElement).value = d.idPattern;
    showXml(d.xml);
    $("ox-status").textContent = `${d.created ? "Created" : "Updated"} ${d.idPattern} · ${d.nodes} node(s) persisted.`;
    toast(`✅ ${d.created ? "Created" : "Updated"} ${d.idPattern}`);
  } catch (e) { $("ox-status").textContent = `⚠️ ${e}`; toast(`⚠️ ${e}`, "err"); }
  finally { btn.disabled = false; }
}

async function loadExisting(idPattern: string): Promise<void> {
  $("ox-status").textContent = "Loading…";
  try {
    const r = await fetch(`/api/oval/definition?id=${encodeURIComponent(idPattern)}`);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    const m = d.meta as Record<string, unknown>;
    root = (d.tree && d.tree.kind === "criteria") ? d.tree : newCriteria();
    refs = Array.isArray(m.references) ? (m.references as typeof refs) : [];
    // An imported (non-authored) definition is loaded as a CLONE: clear the id so save mints a new one.
    loadedIdPattern = m.authored ? String(m.idPattern || "") : "";
    applyMeta({ ...m, idPattern: loadedIdPattern });
    renderRefs(); renderTree();
    $("ox-status").textContent = m.authored
      ? `Loaded authored definition ${m.idPattern} for editing.`
      : `Loaded ${m.idPattern} as a clone — saving will create a new oval:${enums.namespace}:def:N.`;
  } catch (e) { $("ox-status").textContent = `⚠️ ${e}`; }
}

function resetNew(): void {
  root = newCriteria(); refs = []; loadedIdPattern = "";
  applyMeta({ version: 1, classId: enums.classes[0]?.id ?? null, family: "windows", title: "", description: "", platform: "", deprecated: false, idPattern: "" });
  renderRefs(); renderTree(); showXmlReset();
  $("ox-status").textContent = "New definition.";
}
function showXmlReset(): void { $("ox-xmlwrap").style.display = "none"; $("ox-xml").textContent = ""; }

// ── import OVAL test content (objects/states) modal ─────────────────────────────
let impXml = "";
function openImportTests(): void {
  impXml = "";
  ($("ox-imp-file") as HTMLInputElement).value = "";
  $("ox-imp-status").textContent = ""; $("ox-imp-result").innerHTML = ""; $("ox-imp-err").textContent = "";
  ($("ox-imp-run") as HTMLButtonElement).disabled = true;
  $("ox-imp-modal").classList.add("open");
}
function closeImportTests(): void { $("ox-imp-modal").classList.remove("open"); }
async function onImportTestsFile(): Promise<void> {
  const f = ($("ox-imp-file") as HTMLInputElement).files?.[0]; if (!f) return;
  $("ox-imp-err").textContent = ""; $("ox-imp-result").innerHTML = "";
  ($("ox-imp-run") as HTMLButtonElement).disabled = true;
  try {
    impXml = await f.text();
    if (!/oval_definitions|_test/i.test(impXml)) { $("ox-imp-status").textContent = "⚠️ This file does not look like an OVAL document."; return; }
    $("ox-imp-status").textContent = `Loaded ${Math.max(1, Math.round(impXml.length / 1024))} KB. Click Import content.`;
    ($("ox-imp-run") as HTMLButtonElement).disabled = false;
  } catch (e) { $("ox-imp-status").textContent = `⚠️ ${e}`; }
}
async function runImportTests(): Promise<void> {
  if (!impXml.trim()) { $("ox-imp-err").textContent = "⚠️ Choose an OVAL file first."; return; }
  const btn = $("ox-imp-run") as HTMLButtonElement; btn.disabled = true; $("ox-imp-status").textContent = "Importing…";
  try {
    const r = await fetch("/api/oval/import-tests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ xml: impXml }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    $("ox-imp-status").textContent = "";
    $("ox-imp-result").innerHTML = `<div class="tst-view"><div class="ok" style="color:#34d399">${d.parsed} test(s) parsed · ${d.created} created · ${d.updated} updated · ${d.skipped} skipped.</div></div>`;
    toast(`✅ Imported test content: ${d.created} new, ${d.updated} updated`);
  } catch (e) { $("ox-imp-err").textContent = `⚠️ ${e}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  void (async () => {
    try {
      const r = await fetch("/api/oval/meta");
      if (r.ok) enums = await r.json();
    } catch { /* keep defaults */ }
    const classSel = $("ox-class") as HTMLSelectElement;
    classSel.innerHTML = `<option value="">—</option>` + enums.classes.map((c) => `<option value="${c.id}">${esc(c.value)}</option>`).join("");
    const famSel = $("ox-family") as HTMLSelectElement;
    famSel.innerHTML = `<option value="">—</option>` + enums.families.map((f) => `<option value="${esc(f)}">${esc(f)}</option>`).join("");
    const schemaSel = $("ox-schema") as HTMLSelectElement;
    const svs = enums.schemaVersions && enums.schemaVersions.length ? enums.schemaVersions : [enums.schemaVersion];
    schemaSel.innerHTML = svs.map((s, i) => `<option value="${esc(s)}">${esc(s)}${i === 0 ? " (latest)" : s === "5.11.2" ? " (OpenSCAP)" : ""}</option>`).join("");
    schemaSel.value = enums.schemaVersion;

    // default class = compliance if present
    const comp = enums.classes.find((c) => /compliance/i.test(c.value));
    if (comp) classSel.value = String(comp.id);
    famSel.value = "windows";

    renderRefs(); renderTree();

    $("ox-addref").addEventListener("click", () => { refs.push({ source: "", refId: "", refUrl: "" }); renderRefs(); });
    $("ox-preview").addEventListener("click", () => void preview());
    $("ox-save").addEventListener("click", () => void save());
    $("ox-new").addEventListener("click", resetNew);
    $("ox-import-tests").addEventListener("click", openImportTests);
    $("ox-imp-cancel").addEventListener("click", closeImportTests);
    $("ox-imp-modal").addEventListener("click", (e) => { if (e.target === $("ox-imp-modal")) closeImportTests(); });
    ($("ox-imp-file") as HTMLInputElement).addEventListener("change", () => void onImportTestsFile());
    $("ox-imp-run").addEventListener("click", () => void runImportTests());
    $("ox-copy").addEventListener("click", () => { void navigator.clipboard?.writeText($("ox-xml").textContent || ""); toast("Copied"); });
    $("ox-download").addEventListener("click", () => {
      const blob = new Blob([$("ox-xml").textContent || ""], { type: "application/xml" });
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
      a.download = (loadedIdPattern || "oval-definition").replace(/[:]/g, "_") + ".xml"; a.click();
      window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    });

    // load/clone search box
    const lq = $("ox-loadq") as HTMLInputElement;
    attachAutocomplete(lq, $("ox-loadac"), "/api/oval/def-search",
      (it) => `<span class="id">${esc(it.idPattern)}</span> — ${esc(String(it.title || "").slice(0, 90))}`,
      (it) => { lq.value = String(it.idPattern); void loadExisting(String(it.idPattern)); });

    // deep-link: ?id=oval:...:def:N
    const qid = new URLSearchParams(location.search).get("id");
    if (qid) { lq.value = qid; void loadExisting(qid); }
  })();
});
