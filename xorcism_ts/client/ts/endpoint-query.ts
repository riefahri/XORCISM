/** endpoint-query.ts — Tanium-style "Ask the Fleet" (/endpoint-query): pick a sensor, ask the online
 *  XOR agent fleet, and watch answers aggregate into the answer grid. Reads /api/endpoint-query. */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2800); }

interface Sensor { id: string; name: string; category: string; description: string; list: boolean; unit?: string }
interface Q { id: number; sensor: string; text: string; filter: string | null; target: number; answered: number; status: string; askedBy: string | null; askedAt: string }
interface Data { fleet: { total: number; online: number; offline: number }; sensors: Sensor[]; categories: string[]; questions: Q[] }
interface Result { id: number; text: string; sensor: string; filter: string | null; status: string; askedBy: string | null; askedAt: string; target: number; answered: number; pct: number; grid: { value: string; endpoints: number; bar: number }[] }

let DATA: Data | null = null;
let pollTimer: number | undefined;

const card = (lbl: string, val: string, foot: string, color?: string): string =>
  `<div class="card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div><div class="foot">${esc(foot)}</div></div>`;

function render(): void {
  const d = DATA!;
  $("cards").innerHTML = [
    card("Endpoints online", String(d.fleet.online), `${d.fleet.total} enrolled · ${d.fleet.offline} offline`, d.fleet.online ? "#34d399" : "#fbbf24"),
    card("Sensors", String(d.sensors.length), `${d.categories.length} categories`),
    card("Questions asked", String(d.questions.length), "recent", "#60a5fa"),
  ].join("");

  const sel = $("q-sensor") as HTMLSelectElement;
  if (!sel.options.length) {
    const byCat: Record<string, Sensor[]> = {};
    for (const s of d.sensors) (byCat[s.category] ||= []).push(s);
    sel.innerHTML = Object.entries(byCat).map(([cat, list]) => `<optgroup label="${esc(cat)}">${list.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("")}</optgroup>`).join("");
    hint();
    sel.onchange = hint;
  }
  renderRecent();
}

function hint(): void {
  const sel = $("q-sensor") as HTMLSelectElement;
  const s = DATA!.sensors.find((x) => x.id === sel.value);
  $("q-hint").textContent = s ? `${s.description}${s.list ? " (multi-value sensor — filter narrows the matches)" : ""}` : "";
  ($("q-filter") as HTMLInputElement).style.display = s && s.list ? "" : "none";
}

function renderRecent(): void {
  const d = DATA!;
  $("recent").innerHTML = d.questions.length
    ? d.questions.map((q) => `<div class="qrow" data-q="${q.id}">
        <span class="cat">${esc((d.sensors.find((s) => s.name === q.sensor)?.category) || "Sensor")}</span>
        <span class="nm">${esc(q.text)}</span>
        <span style="flex:1"></span>
        <span class="muted" style="font-size:11px">${esc(q.answered)}/${esc(q.target)} answered</span>
        <span class="pill ${q.status === "complete" ? "p-ok" : q.status === "asking" ? "p-asking" : "p-none"}">${esc(q.status)}</span></div>`).join("")
    : `<div class="muted" style="padding:8px 0">No questions yet — ask one above.</div>`;
  Array.prototype.forEach.call(document.querySelectorAll("[data-q]"), (el: HTMLElement) => { el.onclick = () => showResult(Number(el.getAttribute("data-q"))); });
}

function renderResult(r: Result): void {
  const pctColor = r.pct >= 100 ? "#34d399" : "#fbbf24";
  const grid = r.grid.length
    ? `<table class="gr"><tbody>${r.grid.map((g) => `<tr>
        <td class="nm" style="max-width:420px;word-break:break-word">${esc(g.value)}</td>
        <td style="width:55%"><div class="barwrap"><i style="width:${g.bar}%"></i><span>${g.endpoints} endpoint${g.endpoints > 1 ? "s" : ""}</span></div></td></tr>`).join("")}</tbody></table>`
    : `<div class="muted" style="padding:8px 0">Waiting for answers from the fleet…</div>`;
  $("result").innerHTML = `<div class="sec">Answer grid <span class="muted" style="font-weight:400;text-transform:none">— ${esc(r.text)}</span></div>
    <div class="panel">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px">
        <span class="pill ${r.status === "complete" ? "p-ok" : "p-asking"}">${esc(r.status)}</span>
        <span class="muted">${r.answered}/${r.target} endpoints answered (<b style="color:${pctColor}">${r.pct}%</b>)</span>
        <span style="flex:1"></span>
        <span class="muted" style="font-size:11px">${r.grid.length} distinct value(s)</span>
      </div>
      ${grid}
    </div>`;
}

function showResult(id: number, poll = true): void {
  window.clearTimeout(pollTimer);
  fetch(`/api/endpoint-query/question/${id}`).then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((r: Result) => {
      renderResult(r);
      // live: keep polling while still asking (answers stream in at agent check-ins)
      if (poll && r.status === "asking") pollTimer = window.setTimeout(() => showResult(id, true), 3000) as unknown as number;
      if (r.status === "complete") void reload().then(render);
    }).catch((e) => toast("⚠️ " + (e.message || e)));
}

function ask(): void {
  const sensorId = ($("q-sensor") as HTMLSelectElement).value;
  const filter = ($("q-filter") as HTMLInputElement).value.trim();
  const btn = $("q-ask") as HTMLButtonElement;
  btn.disabled = true; const old = btn.innerHTML; btn.innerHTML = "Asking…";
  fetch("/api/endpoint-query/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sensorId, filter: filter || undefined }) })
    .then((r) => r.json().then((j) => { if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }))
    .then((j: { questionId: number; targeted: number; sensor: string }) => {
      toast(j.targeted ? `Asked ${j.targeted} online endpoint(s)` : "No online endpoints — question saved");
      showResult(j.questionId);
      void reload().then(render);
    })
    .catch((e) => toast("⚠️ " + (e.message || e)))
    .finally(() => { btn.disabled = false; btn.innerHTML = old; });
}

function reload(): Promise<void> {
  return fetch("/api/endpoint-query").then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then((d: Data) => { DATA = d; });
}

document.addEventListener("DOMContentLoaded", () => {
  ($("q-ask") as HTMLButtonElement).onclick = ask;
  reload().then(() => { render(); if (DATA!.questions.length) showResult(DATA!.questions[0].id, false); })
    .catch((e) => { $("cards").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e.message || e)}</div>`; });
});
