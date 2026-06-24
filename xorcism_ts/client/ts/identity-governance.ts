/**
 * identity-governance.ts — Identity Governance (IGA / IDMS) cockpit. Access-certification campaigns
 * over the IDENTITY inventory, lifecycle (JML) posture, certification coverage and a revocation queue.
 * Reads /api/identity-governance; reviews via /api/identity-governance/item/:id.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const e = $("toast"); e.textContent = m; e.className = "show"; setTimeout(() => { e.className = ""; }, 3000); }

interface Progress { total: number; certified: number; revoked: number; delegated: number; pending: number; pct: number }
interface Campaign { CampaignID: number; Name: string; Scope: string; Status: string; DueDate: string | null; ItemCount: number; CreatedBy: string; CreatedDate: string; progress: Progress; overdue: boolean }
interface Scope { key: string; label: string; desc: string }
interface Revocation { ItemID: number; IdentityName: string; Comment: string | null; Reviewer: string | null; DecidedDate: string | null; campaign: string; CampaignID: number }
interface Dash {
  summary: { campaigns: number; activeCampaigns: number; overdueCampaigns: number; pendingReviews: number; openRevocations: number; coveragePct: number | null; privilegedTotal: number; privilegedReviewed: number };
  lifecycle: { total: number; human: number; nonHuman: number; privileged: number; orphaned: number; stale: number; mfaGaps: number };
  scopes: Scope[]; campaigns: Campaign[]; revocations: Revocation[];
}
let DATA: Dash | null = null;
let openCampaign: number | null = null;

const pctColor = (n: number | null): string => (n == null ? "#94a3b8" : n >= 80 ? "#34d399" : n >= 50 ? "#fbbf24" : "#f87171");
const card = (lbl: string, val: string | number, foot: string, color?: string): string =>
  `<div class="ig-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(String(val))}</div><div class="foot">${esc(foot)}</div></div>`;

function lifecycle(l: Dash["lifecycle"]): string {
  const cell = (n: number, k: string, color?: string) => `<div class="lifecell"><div class="n"${color ? ` style="color:${color}"` : ""}>${n}</div><div class="k">${esc(k)}</div></div>`;
  return `<div class="life">
    ${cell(l.total, "Identities")}${cell(l.human, "Human")}${cell(l.nonHuman, "Non-human")}
    ${cell(l.privileged, "Privileged", "#c084fc")}${cell(l.mfaGaps, "MFA gaps", l.mfaGaps ? "#f87171" : "#34d399")}
    ${cell(l.orphaned, "Orphaned", l.orphaned ? "#fbbf24" : "#34d399")}${cell(l.stale, "Stale", l.stale ? "#fbbf24" : "#34d399")}
  </div>`;
}

function campaignRow(c: Campaign): string {
  const p = c.progress;
  return `<div class="camp" data-camp="${c.CampaignID}">
    <div class="cn">${esc(c.Name)}<span class="cscope">${esc(c.Scope)}</span></div>
    <div class="track">
      <div class="pbar"><i style="width:${Math.max(2, p.pct)}%"></i></div>
      <div class="pmeta">${p.total - p.pending}/${p.total} reviewed · ${p.certified} certified · ${p.revoked} revoked${p.delegated ? ` · ${p.delegated} delegated` : ""}</div>
    </div>
    <div style="text-align:right">
      <span class="cstat cstat-${c.Status === "completed" ? "completed" : "active"}">${esc(c.Status)}</span>
      ${c.overdue ? ' <span class="ovd">overdue</span>' : ""}
      <div class="pmeta">${c.DueDate ? "due " + esc(c.DueDate) : ""}</div>
    </div>
  </div>`;
}

function itemRow(it: any): string {
  const s = it.snapshot || {};
  const tags: string[] = [];
  if (/admin|root|owner|privileg|super/i.test(String(s.privilege || ""))) tags.push(`<span class="tag tag-priv">${esc(s.privilege)}</span>`);
  if (s.mfa && !/^(y|yes|true|enabled|on|1)$/i.test(String(s.mfa))) tags.push('<span class="tag tag-nomfa">no MFA</span>');
  if (!s.owner) tags.push('<span class="tag tag-orph">no owner</span>');
  if ((s.staleDays ?? 0) > 90) tags.push(`<span class="tag tag-stale">stale ${s.staleDays}d</span>`);
  const decided = it.Decision && it.Decision !== "pending";
  const ctrl = decided
    ? `<span class="dec dec-${esc(it.Decision)}">${esc(it.Decision)}</span>${it.Reviewer ? `<span class="pmeta" style="margin-left:8px;color:#64748b">${esc(it.Reviewer)}</span>` : ""} <button class="rbtn" data-reset="${it.ItemID}">undo</button>`
    : `<button class="rbtn cert" data-dec="certify" data-item="${it.ItemID}">&#10003; Certify</button>
       <button class="rbtn rev" data-dec="revoke" data-item="${it.ItemID}">&#10005; Revoke</button>
       <button class="rbtn del" data-dec="delegate" data-item="${it.ItemID}">Delegate</button>`;
  return `<div class="ri">
    <div class="who">${esc(it.IdentityName)}</div>
    <div class="attr">${tags.join("")}${s.owner ? `owner: ${esc(s.owner)} · ` : ""}${s.class || s.type ? esc(s.class || s.type) + " · " : ""}${s.status || ""}</div>
    <div style="text-align:right;min-width:200px">${ctrl}</div>
  </div>`;
}

async function loadCampaign(id: number): Promise<void> {
  const host = document.getElementById(`camp-detail-${id}`);
  if (!host) return;
  host.innerHTML = `<div class="muted" style="padding:10px">Loading review items…</div>`;
  const r = await fetch(`/api/identity-governance/campaign/${id}`);
  if (!r.ok) { host.innerHTML = `<div class="muted" style="padding:10px">Failed to load.</div>`; return; }
  const c = await r.json();
  host.innerHTML = `<div class="panel"><div class="ph">&#128221; ${esc(c.Name)} — ${c.items.length} identities · ${c.progress.pct}% reviewed</div>
    ${c.items.map(itemRow).join("")}</div>`;
  wireItems();
}

function render(d: Dash): void {
  DATA = d;
  const s = d.summary;
  const html = `
    <div class="ig-cards">
      ${card("Active campaigns", s.activeCampaigns, `${s.campaigns} all-time`, s.activeCampaigns ? "#a78bfa" : "#4ade80")}
      ${card("Pending reviews", s.pendingReviews, "awaiting a decision", s.pendingReviews ? "#fbbf24" : "#4ade80")}
      ${card("Cert. coverage", s.coveragePct != null ? `${s.coveragePct}%` : "—", `${s.privilegedReviewed}/${s.privilegedTotal} privileged · 90d`, pctColor(s.coveragePct))}
      ${card("Open revocations", s.openRevocations, "to de-provision", s.openRevocations ? "#f87171" : "#4ade80")}
      ${card("Overdue campaigns", s.overdueCampaigns, "past due date", s.overdueCampaigns ? "#f87171" : "#4ade80")}
    </div>
    <div class="ig-section">Identity lifecycle posture (JML)</div>
    ${lifecycle(d.lifecycle)}
    <div class="ig-section">Access-certification campaigns<span class="spacer"></span>
      <button class="barbtn go" id="new-camp">+ New campaign</button></div>
    ${d.campaigns.length ? d.campaigns.map((c) => `${campaignRow(c)}<div id="camp-detail-${c.CampaignID}"></div>`).join("")
      : `<div class="muted" style="padding:10px">No campaigns yet. Launch a recertification campaign to attest who still needs privileged access.</div>`}
    <div class="ig-section">Revocation queue (${d.revocations.length})</div>
    ${d.revocations.length ? `<div class="panel">${d.revocations.map((rv) => `<div class="ri">
        <div class="who">${esc(rv.IdentityName)}</div>
        <div class="attr">revoked in <b>${esc(rv.campaign)}</b>${rv.Comment ? " · " + esc(rv.Comment) : ""}${rv.Reviewer ? " · " + esc(rv.Reviewer) : ""}</div>
        <div style="text-align:right"><button class="rbtn" data-actioned="${rv.ItemID}">&#10003; Mark de-provisioned</button></div>
      </div>`).join("")}</div>`
      : `<div class="muted" style="padding:10px">No open revocations — the de-provisioning queue is clear.</div>`}`;
  $("ig-body").innerHTML = html;
  wire();
  if (openCampaign != null && document.getElementById(`camp-detail-${openCampaign}`)) void loadCampaign(openCampaign);
}

function wire(): void {
  $("new-camp").onclick = () => openModal();
  document.querySelectorAll<HTMLElement>(".camp[data-camp]").forEach((el) => {
    el.onclick = () => {
      const id = Number(el.getAttribute("data-camp"));
      if (openCampaign === id) { openCampaign = null; const h = document.getElementById(`camp-detail-${id}`); if (h) h.innerHTML = ""; return; }
      openCampaign = id; void loadCampaign(id);
    };
  });
  document.querySelectorAll<HTMLButtonElement>("button[data-actioned]").forEach((b) => {
    b.onclick = async () => {
      const id = b.getAttribute("data-actioned");
      const r = await fetch(`/api/identity-governance/item/${id}/actioned`, { method: "POST" });
      if (!r.ok) { toast("Failed"); return; }
      toast("Marked de-provisioned"); void load();
    };
  });
}

function wireItems(): void {
  const review = async (id: string, decision: string) => {
    let comment: string | undefined;
    if (decision === "revoke") { const c = prompt("Reason for revoking access (optional):"); comment = c ?? undefined; }
    const r = await fetch(`/api/identity-governance/item/${id}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision, comment }),
    });
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast(j.error || "Failed"); return; }
    toast(`Decision: ${decision}`); void load();
  };
  document.querySelectorAll<HTMLButtonElement>("button[data-item]").forEach((b) => {
    b.onclick = () => review(b.getAttribute("data-item")!, b.getAttribute("data-dec")!);
  });
  document.querySelectorAll<HTMLButtonElement>("button[data-reset]").forEach((b) => {
    b.onclick = () => review(b.getAttribute("data-reset")!, "pending");
  });
}

function openModal(): void {
  const sel = $("f-scope") as HTMLSelectElement;
  sel.innerHTML = (DATA?.scopes || []).map((s) => `<option value="${s.key}">${esc(s.label)}</option>`).join("");
  const hint = $("f-scope-hint");
  const setHint = () => { hint.textContent = DATA?.scopes.find((s) => s.key === sel.value)?.desc || ""; };
  sel.onchange = setHint; setHint();
  ($("f-name") as HTMLInputElement).value = "";
  $("ig-modal").classList.add("show");
}

document.addEventListener("DOMContentLoaded", () => {
  $("ig-cancel").onclick = () => $("ig-modal").classList.remove("show");
  $("ig-modal").onclick = (e) => { if (e.target === $("ig-modal")) $("ig-modal").classList.remove("show"); };
  $("ig-create").onclick = async () => {
    const body = {
      name: ($("f-name") as HTMLInputElement).value.trim() || undefined,
      scope: ($("f-scope") as HTMLSelectElement).value,
      dueDate: ($("f-due") as HTMLInputElement).value || undefined,
    };
    const btn = $("ig-create") as HTMLButtonElement; btn.disabled = true;
    try {
      const r = await fetch("/api/identity-governance/campaign", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { toast(j.error || "Failed to create"); return; }
      $("ig-modal").classList.remove("show");
      toast(`Campaign launched · ${j.items} identities to review`);
      openCampaign = j.id; void load();
    } finally { btn.disabled = false; }
  };
  void load();
});

async function load(): Promise<void> {
  try {
    const r = await fetch("/api/identity-governance");
    if (r.status === 403) { $("ig-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">You don't have access to identity data.</div>`; return; }
    if (!r.ok) throw new Error(String(r.status));
    render(await r.json() as Dash);
  } catch (e) {
    $("ig-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">Failed to load (${esc((e as Error).message)}).</div>`;
  }
}
