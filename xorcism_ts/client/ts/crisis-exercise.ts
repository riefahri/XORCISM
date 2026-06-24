/**
 * crisis-exercise.ts — Tabletop-exercise RUNNER (/crisis-exercise?audit=<id>), OpenAEV-style.
 * Play a crisis scenario as a timeline of multi-channel injects (email/SMS/WhatsApp/phone/media…),
 * deliver them, and record timestamped participant reactions/decisions. Data: /api/crisis-management/exercise/:id.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 3000); }

const AUDIT_ID = Number(new URLSearchParams(location.search).get("audit") || 0);
const CH_ICON: Record<string, string> = { email: "📧", sms: "💬", whatsapp: "🟢", phone: "📞", media: "📣", technical: "🖥️", decision: "🎯", manual: "📝" };
const CH_LABEL: Record<string, string> = { email: "Email", sms: "SMS", whatsapp: "WhatsApp", phone: "Phone call", media: "Media", technical: "Technical", decision: "Decision", manual: "Manual" };
const EV_ICON: Record<string, string> = { start: "▶️", end: "⏹️", deliver: "📤", response: "💬", decision: "✅", escalation: "🚨", acknowledge: "👍", note: "📝", media: "📣" };
const CHANNELS = ["email", "sms", "whatsapp", "phone", "media", "technical", "decision", "manual"];

interface Inject { id: number; title: string; description: string; channel: string; injectType: string; offsetMinutes: number | null; sender: string; recipients: string; subject: string; expectedAction: string; actualResponse: string; status: string; delivered: boolean; deliveredDate: string | null; scheduledAt: string | null; }
interface Participant { id: number; name: string; role: string; team: string; email: string; phone: string; attended: boolean; }
interface LogE { id: number; injectId: number | null; participantId: number | null; eventType: string; channel: string; message: string; loggedAt: string; byUser: string; }
interface Detail { exercise: { auditId: number; name: string; scenario: string; status: string; date: string | null; startedAt: string | null; endedAt: string | null; durationMin: number | null; running: boolean }; injects: Inject[]; participants: Participant[]; log: LogE[]; summary: { injects: number; delivered: number; pending: number; participants: number; reactions: number; events: number; durationMin: number | null }; }

let DATA: Detail | null = null;
let clockTimer: number | null = null;

const tOff = (m: number | null): string => (m == null ? "T?" : m === 0 ? "T+0" : `T+${m}m`);
const stCls = (s: string): string => (/complet|done/i.test(s) ? "st-completed" : /progress|cours/i.test(s) ? "st-progress" : "st-planned");
const hhmm = (iso: string): string => { try { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); } catch { return iso; } };

async function api(method: string, url: string, body?: unknown): Promise<any> {
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body != null ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

function injectCard(i: Inject): string {
  const ic = CH_ICON[i.channel] || "📝";
  return `<div class="inj ${i.delivered ? "delivered" : ""}" data-inj="${i.id}">
    <div class="top">
      <span class="toff">${tOff(i.offsetMinutes)}</span>
      <span class="chan">${ic} ${esc(CH_LABEL[i.channel] || i.channel)}</span>
      <span class="ttl">${esc(i.subject || i.title)}</span>
      ${i.delivered ? `<span class="dlv">✓ delivered${i.deliveredDate ? " " + hhmm(i.deliveredDate) : ""}</span>` : ""}
    </div>
    ${(i.sender || i.recipients) ? `<div class="meta">${i.sender ? `from <b>${esc(i.sender)}</b>` : ""}${i.recipients ? ` → ${esc(i.recipients)}` : ""}${i.scheduledAt ? ` · scheduled ${hhmm(i.scheduledAt)}` : ""}</div>` : ""}
    ${i.description ? `<div class="body">${esc(i.description)}</div>` : ""}
    ${i.expectedAction ? `<div class="exp">🎯 Expected: ${esc(i.expectedAction)}</div>` : ""}
    ${i.actualResponse ? `<div class="resp">➟ ${esc(i.actualResponse)}</div>` : ""}
    <div class="acts">
      ${i.delivered ? "" : `<button class="btn-sm dlv-btn" data-inj="${i.id}">📤 Deliver</button>`}
      <button class="btn-sm react-btn" data-inj="${i.id}">＋ Reaction</button>
    </div>
    <div class="react" id="react-${i.id}">
      <select class="r-type"><option value="response">Response</option><option value="decision">Decision</option><option value="escalation">Escalation</option><option value="acknowledge">Acknowledge</option><option value="note">Note</option></select>
      <input class="r-msg" placeholder="What did the team do / decide? (timestamped)">
      <button class="btn-sm r-save" data-inj="${i.id}">Log</button>
    </div>
  </div>`;
}

function participantRow(p: Participant): string {
  const ct = [p.email, p.phone].filter(Boolean).join(" · ");
  return `<div class="pp"><span>👤 <b>${esc(p.name)}</b>${p.team ? ` <span class="role">(${esc(p.team)})</span>` : ""}<div class="role">${esc(p.role || "—")}</div></span><span class="ct">${esc(ct)}</span></div>`;
}

function feedRow(l: LogE): string {
  return `<div class="fe ${esc(l.eventType)}"><span class="ts">${hhmm(l.loggedAt)}</span><span class="ic">${EV_ICON[l.eventType] || "•"}</span><span>${esc(l.message)}</span></div>`;
}

function render(): void {
  const d = DATA!; const e = d.exercise; const s = d.summary;
  const running = e.running;
  $("ex-body").innerHTML = `
    <div class="ex-head">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <h1>${esc(e.name)}</h1><span class="st-pill ${stCls(e.status)}">${esc(e.status || "Planned")}</span>
        <span class="spacer" style="flex:1"></span><a class="btn-sm" href="/crisis-management">← Crisis Management</a>
      </div>
      <div class="scn">Scenario: <b>${esc(e.scenario || "—")}</b>${e.date ? ` · planned ${esc(e.date)}` : ""}</div>
      <div class="ex-bar">
        <span class="ex-clock" id="ex-clock">${running ? "T+…" : "T+0"}</span>
        ${e.startedAt ? (running ? `<button class="btn-stop" id="ex-end">⏹ End exercise</button>` : `<span class="ex-chip">Ended · duration <b>${e.durationMin ?? 0}m</b></span>`)
                      : `<button class="btn-go" id="ex-start">▶ Start exercise</button>`}
        <span class="ex-chip">Injects <b>${s.delivered}/${s.injects}</b> delivered</span>
        <span class="ex-chip">Participants <b>${s.participants}</b></span>
        <span class="ex-chip">Reactions <b>${s.reactions}</b></span>
      </div>
    </div>
    <div class="ex-grid">
      <div>
        <div class="sec">📡 Inject timeline <span class="spacer"></span><button class="btn-sm" id="add-inj-toggle">＋ Add inject</button></div>
        <div id="add-inj" class="panel" style="display:none">
          <div class="frm">
            <input id="ai-title" class="full" placeholder="Inject title / subject *">
            <select id="ai-chan">${CHANNELS.map((c) => `<option value="${c}">${CH_ICON[c]} ${CH_LABEL[c]}</option>`).join("")}</select>
            <input id="ai-offset" type="number" placeholder="T+ minutes (e.g. 15)">
            <input id="ai-sender" placeholder="Sender (e.g. CSIRT)">
            <input id="ai-recipients" placeholder="Recipients (team / role)">
            <textarea id="ai-desc" class="full" placeholder="Message body…"></textarea>
            <input id="ai-exp" class="full" placeholder="Expected action / decision">
          </div>
          <div style="margin-top:7px;display:flex;gap:7px;justify-content:flex-end"><button class="btn-sm" id="ai-cancel">Cancel</button><button class="btn-go" id="ai-save" style="padding:6px 13px">Add inject</button></div>
        </div>
        ${d.injects.length ? d.injects.map(injectCard).join("") : `<div class="muted" style="padding:10px 0">No injects. Add one above, or launch from a scenario.</div>`}
      </div>
      <div>
        <div class="sec">🧑‍🤝‍🧑 Participants (${d.participants.length})</div>
        <div class="panel">
          ${d.participants.length ? d.participants.map(participantRow).join("") : `<div class="muted">No participants yet.</div>`}
          <div class="frm" style="margin-top:8px">
            <input id="pp-name" class="full" placeholder="Name *">
            <input id="pp-role" placeholder="Role (e.g. Incident Commander)">
            <input id="pp-team" placeholder="Team / cell">
            <input id="pp-email" placeholder="Email">
            <input id="pp-phone" placeholder="Phone">
            <button class="btn-go full" id="pp-add" style="padding:6px">＋ Add participant</button>
          </div>
        </div>
        <div class="sec">🕒 Live timeline log</div>
        <div class="panel feed" id="ex-feed">
          ${d.log.length ? d.log.slice().reverse().map(feedRow).join("") : `<div class="muted">No events yet — start the exercise and deliver injects.</div>`}
        </div>
      </div>
    </div>`;
  wire();
  startClock();
}

function startClock(): void {
  if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
  const e = DATA!.exercise;
  const el = document.getElementById("ex-clock"); if (!el) return;
  if (!e.startedAt) { el.textContent = "T+0"; return; }
  const start = Date.parse(e.startedAt);
  const tick = (): void => {
    const end = e.endedAt ? Date.parse(e.endedAt) : Date.now();
    const sec = Math.max(0, Math.floor((end - start) / 1000));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), ss = sec % 60;
    el.textContent = `T+${h ? h + ":" : ""}${String(m).padStart(h ? 2 : 1, "0")}:${String(ss).padStart(2, "0")}`;
  };
  tick();
  if (e.running) clockTimer = window.setInterval(tick, 1000);
}

function wire(): void {
  document.getElementById("ex-start")?.addEventListener("click", () => act(`/api/crisis-management/exercise/${AUDIT_ID}/start`, {}, "Exercise started — clock running"));
  document.getElementById("ex-end")?.addEventListener("click", () => { if (confirm("End the exercise? The clock stops.")) act(`/api/crisis-management/exercise/${AUDIT_ID}/end`, {}, "Exercise ended"); });

  document.querySelectorAll<HTMLButtonElement>(".dlv-btn").forEach((b) => b.addEventListener("click", () => act(`/api/crisis-management/inject/${b.dataset.inj}/deliver`, {}, "Inject delivered")));
  document.querySelectorAll<HTMLButtonElement>(".react-btn").forEach((b) => b.addEventListener("click", () => { const r = document.getElementById(`react-${b.dataset.inj}`); r?.classList.toggle("open"); (r?.querySelector(".r-msg") as HTMLInputElement)?.focus(); }));
  document.querySelectorAll<HTMLButtonElement>(".r-save").forEach((b) => b.addEventListener("click", () => {
    const box = document.getElementById(`react-${b.dataset.inj}`)!;
    const msg = (box.querySelector(".r-msg") as HTMLInputElement).value.trim();
    if (!msg) { toast("Enter what happened"); return; }
    const eventType = (box.querySelector(".r-type") as HTMLSelectElement).value;
    act(`/api/crisis-management/exercise/${AUDIT_ID}/log`, { injectId: Number(b.dataset.inj), eventType, message: msg }, "Reaction logged");
  }));

  document.getElementById("add-inj-toggle")?.addEventListener("click", () => { const a = $("add-inj"); a.style.display = a.style.display === "none" ? "block" : "none"; });
  document.getElementById("ai-cancel")?.addEventListener("click", () => { $("add-inj").style.display = "none"; });
  document.getElementById("ai-save")?.addEventListener("click", () => {
    const v = (id: string): string => ($(id) as HTMLInputElement).value.trim();
    if (!v("ai-title")) { toast("Title required"); return; }
    act(`/api/crisis-management/exercise/${AUDIT_ID}/inject`, {
      title: v("ai-title"), channel: ($("ai-chan") as HTMLSelectElement).value, offsetMinutes: v("ai-offset") || null,
      sender: v("ai-sender"), recipients: v("ai-recipients"), description: v("ai-desc"), expectedAction: v("ai-exp"),
    }, "Inject added");
  });

  document.getElementById("pp-add")?.addEventListener("click", () => {
    const v = (id: string): string => ($(id) as HTMLInputElement).value.trim();
    if (!v("pp-name")) { toast("Name required"); return; }
    act(`/api/crisis-management/exercise/${AUDIT_ID}/participant`, { name: v("pp-name"), role: v("pp-role"), team: v("pp-team"), email: v("pp-email"), phone: v("pp-phone"), attended: true }, "Participant added");
  });
}

async function act(url: string, body: unknown, okMsg: string): Promise<void> {
  try { await api("POST", url, body); toast(okMsg); await load(); }
  catch (e) { toast("⚠️ " + (e as Error).message); }
}

async function load(): Promise<void> {
  if (!AUDIT_ID) { $("ex-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ No exercise id. Open this from <a href="/crisis-management" style="color:#fb7185">Crisis Management</a>.</div>`; return; }
  try { DATA = await api("GET", `/api/crisis-management/exercise/${AUDIT_ID}`); }
  catch (e) { $("ex-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc((e as Error).message)}</div>`; return; }
  render();
}

document.addEventListener("DOMContentLoaded", load);
