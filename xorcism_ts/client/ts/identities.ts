/**
 * identities.ts — Identity & Access Management inventory (/identities).
 * Renders the human + non-human identity inventory with governance findings, from /api/identities.
 */
import { initI18n, t } from "./i18n";

function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
const fmt = (key: string, vars: Record<string, string | number>): string =>
  Object.entries(vars).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), t(key));

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
    mfaEnabled: number; mfaUnknown: number; mfaCoveragePct: number;
    secretsTotal: number; rotationOverdue: number; neverRotated: number; avgRotationDays: number | null;
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
    <td><span class="badge ${cls}">${r.klass === "Human" ? t("idn.human") : t("idn.nonHuman")}</span></td>
    <td>${esc(r.owner || "—")}${r.persons ? ` <span class="muted">(${r.persons}👤)</span>` : ""}</td>
    <td>${esc(r.asset || "—")}</td>
    <td>${priv}</td>
    <td><span class="st ${stCls}">${esc(r.status)}</span></td>
    <td>${flags}</td>
    <td class="score ${scoreClass(r.score)}">${r.score || ""}</td>
  </tr>`;
}

function findingHtml(f: IdentityFinding): string {
  // Click-through opens the IDENTITY explorer view filtered to the finding's identity.
  const href = f.identity
    ? `/?db=XORCISM&table=IDENTITY&filterCol=IdentityName&filterVal=${encodeURIComponent(f.identity)}`
    : "/?db=XORCISM&table=IDENTITY";
  return `<li><span class="sev-dot dot-${f.severity}"></span>
    <span class="sev-${f.severity}">${esc(f.severity)}</span> —
    <a href="${esc(href)}">${esc(f.label)}</a></li>`;
}

async function load(): Promise<void> {
  let d: Inventory;
  try { const r = await fetch("/api/identities"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("iam-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }
  const s = d.summary;

  if (!d.rows.length) {
    $("iam-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">
      ${t("idn.emptyA")}
      <a href="/?db=XORCISM&table=IDENTITY">${t("idn.emptyLink")}</a> ${t("idn.emptyB")}</div>`;
    return;
  }

  const cards = [
    card(t("idn.cIdentities"), String(s.total), fmt("idn.cIdentitiesFoot", { h: s.human, nh: s.nonHuman })),
    card(t("idn.cPriv"), String(s.privileged), t("idn.cPrivFoot"), s.privileged ? "#c084fc" : undefined),
    card(t("idn.cOrphan"), String(s.orphaned), t("idn.cOrphanFoot"), s.orphaned ? "#fb923c" : "#34d399"),
    card(t("idn.cExpiring"), String(s.expiring), t("idn.cExpiringFoot"), s.expiring ? "#fbbf24" : "#34d399"),
    card(t("idn.cStale"), String(s.stale), t("idn.cStaleFoot"), s.stale ? "#fbbf24" : undefined),
    card(t("idn.cHardcoded"), String(s.hardcoded), t("idn.cHardcodedFoot"), s.hardcoded ? "#f87171" : "#34d399"),
    card(t("idn.cMfaGaps"), String(s.mfaGaps), t("idn.cMfaGapsFoot"), s.mfaGaps ? "#f87171" : "#34d399"),
    card(t("idn.cMfaCov"), `${s.mfaCoveragePct}%`, fmt("idn.cMfaCovFoot", { e: s.mfaEnabled, h: s.human }) + (s.mfaUnknown ? fmt("idn.cMfaCovUnknown", { u: s.mfaUnknown }) : ""), s.mfaCoveragePct >= 90 ? "#34d399" : s.mfaCoveragePct >= 60 ? "#fbbf24" : "#f87171"),
    card(t("idn.cRotation"), String(s.rotationOverdue), fmt("idn.cRotationFoot", { n: s.secretsTotal }) + (s.neverRotated ? fmt("idn.cRotationNever", { nr: s.neverRotated }) : ""), s.rotationOverdue ? "#fbbf24" : "#34d399"),
    card(t("idn.cAvgAge"), s.avgRotationDays != null ? `${s.avgRotationDays}d` : "—", t("idn.cAvgAgeFoot"), s.avgRotationDays != null && s.avgRotationDays > 90 ? "#fb923c" : undefined),
    card(t("idn.cCompromised"), String(s.compromised), t("idn.cCompromisedFoot"), s.compromised ? "#f87171" : "#34d399"),
  ].join("");

  const byType = Object.entries(s.byType).sort((a, b) => b[1] - a[1])
    .map(([ty, n]) => `<span class="bd">${icon(ty)} ${esc(ty)} <b>${n}</b></span>`).join("");

  const findings = d.findings.length
    ? `<ul class="findings">${d.findings.slice(0, 60).map(findingHtml).join("")}</ul>${d.findings.length > 60 ? `<div class="muted" style="font-size:11px;margin-top:6px">${fmt("idn.more", { n: d.findings.length - 60 })}</div>` : ""}`
    : `<div class="muted" style="padding:12px 0">${t("idn.workNone")}</div>`;

  const table = `<table class="iam"><thead><tr>
      <th>${t("idn.thIdentity")}</th><th>${t("idn.thClass")}</th><th>${t("idn.thOwner")}</th><th>${t("idn.thAsset")}</th><th>${t("idn.thPrivilege")}</th><th>${t("idn.thStatus")}</th><th>${t("idn.thFindings")}</th><th title="${t("idn.thRiskTitle")}">${t("idn.thRisk")}</th>
    </tr></thead><tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  $("iam-body").innerHTML = `<div class="iam-cards">${cards}</div>
    <div class="iam-section">${t("idn.secWorklist")} (${d.findings.length})</div>${findings}
    <div class="iam-section">${t("idn.secByType")}</div><div class="breakdown">${byType}</div>
    <div class="iam-section">${t("idn.secInventory")} (${d.rows.length})</div>${table}
    <div class="legend">${t("idn.legend")}
      <a href="/?db=XORCISM&table=IDENTITY">${t("idn.linkManage")}</a>${t("idn.legendMid")}
      <a href="/?db=XORCISM&table=IDENTITYPERSON">${t("idn.linkMap")}</a>.</div>`;
}

document.addEventListener("DOMContentLoaded", () => { initI18n(); void load(); });
