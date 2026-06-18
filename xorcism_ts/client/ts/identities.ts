/**
 * identities.ts — Identity & Access Management inventory (/identities).
 * Renders the human + non-human identity inventory with governance findings, from /api/identities.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }

interface IdentityRow {
  id: number; name: string; type: string; klass: "Human" | "Non-Human"; status: string;
  owner: string | null; asset: string | null; provider: string; privilege: string;
  environment: string; credentialType: string; mfa: string; risk: string;
  expiry: string | null; lastUsed: string | null; lastRotated: string | null;
  persons: number; flags: string[]; score: number;
}
interface IdentityFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; identityId: number; identity: string; }
interface Inventory {
  rows: IdentityRow[]; findings: IdentityFinding[];
  summary: {
    total: number; human: number; nonHuman: number; privileged: number; orphaned: number; stale: number;
    expiring: number; hardcoded: number; compromised: number; mfaGaps: number;
    byType: Record<string, number>; byClass: Record<string, number>;
  };
}

const TYPE_ICON: Record<string, string> = {
  human: "👤", "ai agent": "🤖", api: "🔌", container: "📦", "service account": "⚙️",
  "hardcoded credential": "🔑", certificate: "📜", device: "💻", workload: "🧩", bot: "🤖",
  token: "🎫", "service principal": "🛂",
};
const icon = (t: string): string => TYPE_ICON[t.toLowerCase()] || "🪪";
const scoreClass = (n: number): string => (n >= 40 ? "s-hi" : n >= 15 ? "s-md" : "s-lo");

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="iam-card"><div class="lbl">${esc(lbl)}</div>
    <div class="val"${color ? ` style="color:${color}"` : ""}>${val}</div>
    <div class="foot">${esc(foot)}</div></div>`;
}

function rowHtml(r: IdentityRow): string {
  const cls = r.klass === "Human" ? "cl-human" : "cl-nonhuman";
  const stCls = /compromis|breach/i.test(r.status) ? "st-compromised" : /disabled|inactive|retired/i.test(r.status) ? "st-disabled" : "";
  const flags = r.flags.length ? r.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join("") : `<span class="muted">—</span>`;
  const priv = r.privilege ? `<span class="priv">${esc(r.privilege)}</span>` : `<span class="muted">—</span>`;
  return `<tr>
    <td><div class="idname"><span class="type-icon">${icon(r.type)}</span>${esc(r.name)}</div>
      <div class="muted" style="font-size:11px">${esc(r.type)}${r.provider ? ` · ${esc(r.provider)}` : ""}${r.environment ? ` · ${esc(r.environment)}` : ""}</div></td>
    <td><span class="badge ${cls}">${esc(r.klass)}</span></td>
    <td>${esc(r.owner || "—")}${r.persons ? ` <span class="muted">(${r.persons}👤)</span>` : ""}</td>
    <td>${esc(r.asset || "—")}</td>
    <td>${priv}</td>
    <td><span class="st ${stCls}">${esc(r.status)}</span></td>
    <td>${flags}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: IdentityFinding): string {
  return `<li><span class="sev-dot dot-${f.severity}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> —
    <a href="/?db=XORCISM&table=IDENTITY">${esc(f.label)}</a></li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/identities"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("iam-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("iam-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      No identities registered yet.
      <a href="/?db=XORCISM&table=IDENTITY">Add your first identity</a> — a person's account, a service account,
      an API key, a container workload, a certificate, an AI agent… then come back to see the governance worklist.</div>`;
    return;
  }

  const cards = [
    card("Identities", String(s.total), `${s.human} human · ${s.nonHuman} non-human`),
    card("Privileged", String(s.privileged), "admin / root / owner", s.privileged ? "#c084fc" : undefined),
    card("Orphaned NHI", String(s.orphaned), "non-human · no owner", s.orphaned ? "#fb923c" : "#34d399"),
    card("Expiring", String(s.expiring), "credential expired / soon", s.expiring ? "#fbbf24" : "#34d399"),
    card("Stale", String(s.stale), `unused > 90 days`, s.stale ? "#fbbf24" : undefined),
    card("Hardcoded", String(s.hardcoded), "embedded secrets", s.hardcoded ? "#f87171" : "#34d399"),
    card("MFA gaps", String(s.mfaGaps), "privileged human, no MFA", s.mfaGaps ? "#f87171" : "#34d399"),
    card("Compromised", String(s.compromised), "flagged status", s.compromised ? "#f87171" : "#34d399"),
  ].join("");

  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1])
    .map(([t, n]) => `<span class="bd">${icon(t)} ${esc(t)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">+${d.findings.length - 60} more…</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">✓ No governance findings — every identity has an owner, sane privilege, fresh credentials and recent use.</div>`;

  const table = `<table class="iam"><thead><tr>
      <th>Identity</th><th>Class</th><th>Owner</th><th>Bound asset</th><th>Privilege</th><th>Status</th><th>Findings</th><th title="Derived risk priority">Risk</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("iam-body").innerHTML = `<div class="iam-cards">${cards}</div>
    <div class="iam-section">Risk worklist (${d.findings.length})</div>${findings}
    <div class="iam-section">Breakdown by type</div><div class="breakdown">${byType}</div>
    <div class="iam-section">Inventory (${d.rows.length})</div>${table}
    <div class="legend">↳ <b>Risk</b> is a derived priority (0–100): compromised +50, hardcoded +30, expired/orphaned +25,
      privileged +20, missing MFA +20, never-rotated +15, stale +10. Edit identities under
      <a href="/?db=XORCISM&table=IDENTITY">Manage identities</a>; map humans via
      <a href="/?db=XORCISM&table=IDENTITYPERSON">Identity↔Person</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => void load());
