/**
 * webhooks.ts — manage outbound webhooks (/webhooks).
 * Register URL + events, list with last-delivery status, send a test, delete.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface Hook { WebhookID: number; Url: string; Events: string; Active: number; CreatedDate: string; LastStatus: number | null; LastDeliveryDate: string | null; FailureCount: number; }
const fmt = (d: string | null): string => (d ? esc(String(d).replace("T", " ").slice(0, 16)) : "—");
let EVENTS: string[] = [];

function statusCell(h: Hook): string {
  if (h.LastStatus == null) return `<span class="muted">never sent</span>`;
  const ok = h.LastStatus >= 200 && h.LastStatus < 300;
  const code = h.LastStatus === 0 ? "blocked/err" : String(h.LastStatus);
  return `<span class="${ok ? "ok" : "bad"}">${esc(code)}</span> <span class="muted">${fmt(h.LastDeliveryDate)}</span>`;
}

async function loadList(): Promise<void> {
  let d: { webhooks: Hook[]; events: string[] } = { webhooks: [], events: [] };
  try { const r = await fetch("/api/webhooks"); if (r.ok) d = await r.json(); } catch { /* */ }
  EVENTS = d.events || [];
  if (!$("wh-eventpick").innerHTML) {
    $("wh-eventpick").innerHTML = `<span style="margin-right:8px">Events:</span>` +
      `<label style="margin-right:12px"><input type="checkbox" id="ev_all" checked> <code>* (all)</code></label>` +
      EVENTS.map((e) => `<label style="margin-right:12px"><input type="checkbox" class="ev-cb" value="${esc(e)}"> <code>${esc(e)}</code></label>`).join("");
    $("wh-eventpick").querySelectorAll<HTMLInputElement>(".ev-cb").forEach((cb) =>
      cb.addEventListener("change", () => { if (cb.checked) (document.getElementById("ev_all") as HTMLInputElement).checked = false; }));
    (document.getElementById("ev_all") as HTMLInputElement).addEventListener("change", (e) => {
      if ((e.target as HTMLInputElement).checked) $("wh-eventpick").querySelectorAll<HTMLInputElement>(".ev-cb").forEach((c) => (c.checked = false));
    });
  }
  if (!d.webhooks.length) { $("wh-list").innerHTML = `<div class="muted" style="padding:16px">No webhooks yet.</div>`; return; }
  $("wh-list").innerHTML = `<table class="wh"><thead><tr>
      <th>Endpoint</th><th>Events</th><th>Last delivery</th><th></th></tr></thead><tbody>${
    d.webhooks.map((h) => `<tr>
      <td class="mono">${esc(h.Url)}</td>
      <td>${(h.Events || "").split(",").map((e) => `<span class="ev">${esc(e.trim())}</span>`).join("")}</td>
      <td>${statusCell(h)}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-ghost btn-sm" data-test="${h.WebhookID}">Test</button>
        <button class="btn btn-ghost btn-sm" data-del="${h.WebhookID}">Delete</button></td>
    </tr>`).join("")}</tbody></table>`;
  $("wh-list").querySelectorAll<HTMLButtonElement>("[data-test]").forEach((b) => {
    b.onclick = async () => {
      b.disabled = true; b.textContent = "…";
      try { const r = await fetch(`/api/webhooks/${b.dataset.test}/test`, { method: "POST" }); const d2 = await r.json();
        alert(d2.ok ? `Test delivered (HTTP ${d2.status})` : `Test failed (status ${d2.status} — blocked or unreachable)`); }
      catch (e) { alert("Test error: " + e); }
      finally { void loadList(); }
    };
  });
  $("wh-list").querySelectorAll<HTMLButtonElement>("[data-del]").forEach((b) => {
    b.onclick = async () => { if (!confirm("Delete this webhook?")) return; await fetch(`/api/webhooks/${b.dataset.del}`, { method: "DELETE" }); void loadList(); };
  });
}

async function create(): Promise<void> {
  const url = ($("wh-url") as HTMLInputElement).value.trim();
  if (!url) { alert("Enter an endpoint URL."); return; }
  const all = (document.getElementById("ev_all") as HTMLInputElement).checked;
  const events = all ? ["*"] : [...$("wh-eventpick").querySelectorAll<HTMLInputElement>(".ev-cb")].filter((c) => c.checked).map((c) => c.value);
  const btn = $("wh-create") as HTMLButtonElement; btn.disabled = true;
  try {
    const r = await fetch("/api/webhooks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, events }) });
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || `HTTP ${r.status}`); }
    const d = await r.json();
    ($("wh-url") as HTMLInputElement).value = "";
    $("wh-reveal").innerHTML = `<div class="reveal">
      <div style="font-size:12px;color:#6ee7b7;margin-bottom:6px">Signing secret — copy it now, it won't be shown again:</div>
      <div class="k" id="wh-secret">${esc(d.secret)}</div>
      <div class="warn"><button class="btn btn-ghost btn-sm" id="wh-copy">Copy</button> &nbsp; verify deliveries with <code>HMAC-SHA256(secret, body)</code>.</div>
    </div>`;
    $("wh-copy").onclick = () => { void navigator.clipboard?.writeText(d.secret); ($("wh-copy") as HTMLButtonElement).textContent = "Copied"; };
    void loadList();
  } catch (e) { alert("Could not add webhook: " + e); }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  $("wh-create").onclick = () => void create();
  void loadList();
});
