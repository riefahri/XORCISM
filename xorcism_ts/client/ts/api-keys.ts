/**
 * api-keys.ts — manage your XORCISM API keys (/api-keys).
 * List / create (raw shown once; presets or custom scopes; optional expiry) / revoke.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface KeyRow { KeyID: number; Name: string; Prefix: string; Scopes: string | null; CreatedDate: string; ExpiresDate: string | null; LastUsedDate: string | null; Revoked: number; }

const GRANULAR = ["assets:read", "assets:write", "incidents:read", "incidents:write", "exposure:read", "risk:read"];
const fmt = (d: string | null): string => (d ? esc(String(d).replace("T", " ").slice(0, 16)) : "—");

function scopeBadge(s: string | null): string {
  const v = s || "read";
  const label = v === "write" ? "read+write" : v;
  const css = v === "read" ? "background:#1e2133;color:#94a3b8" : "background:#78350f;color:#fcd34d";
  return `<span style="font-size:11px;${css};border-radius:5px;padding:2px 7px">${esc(label)}</span>`;
}
function expiresCell(d: string | null): string {
  if (!d) return `<span class="muted">never</span>`;
  if (Date.parse(d) <= Date.now()) return `<span style="color:#f87171">expired</span>`;
  return fmt(d);
}

async function loadList(): Promise<void> {
  let keys: KeyRow[] = [];
  try { const r = await fetch("/api/apikeys"); if (r.ok) keys = (await r.json()).keys || []; } catch { /* */ }
  if (!keys.length) { $("ak-list").innerHTML = `<div class="muted" style="padding:16px">No keys yet. Create one above.</div>`; return; }
  $("ak-list").innerHTML = `<table class="ak"><thead><tr>
      <th>Name</th><th>Key</th><th>Scope</th><th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead><tbody>${
    keys.map((k) => `<tr class="${k.Revoked ? "revoked" : ""}">
      <td>${esc(k.Name)}</td>
      <td class="mono">${esc(k.Prefix)}</td>
      <td>${scopeBadge(k.Scopes)}</td>
      <td>${fmt(k.CreatedDate)}</td>
      <td>${expiresCell(k.ExpiresDate)}</td>
      <td>${fmt(k.LastUsedDate)}</td>
      <td>${k.Revoked ? `<span class="pill-rev">revoked</span>`
        : `<button class="btn btn-ghost btn-sm" data-revoke="${k.KeyID}">Revoke</button>`}</td>
    </tr>`).join("")}</tbody></table>`;
  $("ak-list").querySelectorAll<HTMLButtonElement>("[data-revoke]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm("Revoke this key? Clients using it will stop working.")) return;
      await fetch(`/api/apikeys/${b.dataset.revoke}`, { method: "DELETE" });
      void loadList();
    };
  });
}

function chosenScopes(): string {
  const preset = ($("ak-scope") as HTMLSelectElement).value;
  if (preset !== "custom") return preset;
  const checked = GRANULAR.filter((s) => (document.getElementById(`sc_${s}`) as HTMLInputElement)?.checked);
  return checked.length ? checked.join(",") : "read";
}

async function create(): Promise<void> {
  const name = ($("ak-name") as HTMLInputElement).value.trim();
  const scopes = chosenScopes();
  const expiresInDays = Number(($("ak-expiry") as HTMLSelectElement).value) || 0;
  const btn = $("ak-create") as HTMLButtonElement;
  btn.disabled = true;
  try {
    const r = await fetch("/api/apikeys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, scopes, expiresInDays }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    ($("ak-name") as HTMLInputElement).value = "";
    $("ak-reveal").innerHTML = `<div class="reveal">
      <div style="font-size:12px;color:#6ee7b7;margin-bottom:6px">New key (scope: ${esc(d.record.Scopes)}) — copy it now, it won't be shown again:</div>
      <div class="k" id="ak-raw">${esc(d.key)}</div>
      <div class="warn"><button class="btn btn-ghost btn-sm" id="ak-copy">Copy</button> &nbsp; store it in your client's secret store.</div>
    </div>`;
    $("ak-copy").onclick = () => { void navigator.clipboard?.writeText(d.key); ($("ak-copy") as HTMLButtonElement).textContent = "Copied"; };
    void loadList();
  } catch (e) { alert("Could not create key: " + e); }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  // custom-scope checkboxes
  $("ak-custom").innerHTML = `<span style="margin-right:8px">Scopes:</span>` + GRANULAR.map((s) =>
    `<label style="margin-right:12px;cursor:pointer"><input type="checkbox" id="sc_${s}" style="vertical-align:-1px"> <code>${esc(s)}</code></label>`).join("");
  const scopeSel = $("ak-scope") as HTMLSelectElement;
  scopeSel.addEventListener("change", () => { $("ak-custom").style.display = scopeSel.value === "custom" ? "" : "none"; });
  $("ak-create").onclick = () => void create();
  ($("ak-name") as HTMLInputElement).addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") void create(); });
  void loadList();
});
