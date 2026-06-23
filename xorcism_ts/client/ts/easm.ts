/**
 * easm.ts — External Attack Surface Management cockpit (/easm).
 * Renders the internet-facing subset of the estate (exposure reasons, services/ports, TLS
 * posture, external KEV/critical vulns), the exposures worklist and surface drift, from
 * /api/easm. A "Snapshot surface" button records a baseline so drift can be measured.
 */
function $(id: string): HTMLElement { return document.getElementById(id)!; }
function esc(s: unknown): string { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!)); }
function toast(m: string): void { const t = $("toast"); if (!t) return; t.textContent = m; t.className = "show"; setTimeout(() => { t.className = ""; }, 2600); }

interface Service { proto: string; port: number; service: string; source: string }
interface Row {
  id: number; name: string; address: string; reasons: string[]; criticality: string;
  owner: string | null; services: Service[]; openPorts: number;
  ssl: { days: number | null; expiry: string | null; status: string } | null;
  vulns: { open: number; kev: number; critical: number }; shadow: boolean; flags: string[]; score: number;
}
interface Finding { kind: string; label: string; severity: string; assetId: number; asset: string }
interface Data {
  rows: Row[]; worklist: Finding[];
  drift: { added: string[]; removed: string[]; snapshots: number } | null;
  summary: { internetFacing: number; exposedServices: number; openPorts: number; expiringCerts: number; expiredCerts: number; externalKev: number; shadow: number; noOwner: number; byReason: Record<string, number> };
}

function card(lbl: string, val: string, foot: string, color?: string): string {
  return `<div class="em-card"><div class="lbl">${esc(lbl)}</div><div class="val"${color ? ` style="color:${color}"` : ""}>${esc(val)}</div><div class="foot">${esc(foot)}</div></div>`;
}
function sevClass(s: string): string { return `s-${(s || "low").toLowerCase()}`; }

function certHtml(ssl: Row["ssl"]): string {
  if (!ssl || ssl.days == null) return `<span class="muted">—</span>`;
  if (ssl.days < 0) return `<span class="cert-expired">EXPIRED</span> <span class="muted">${esc(ssl.expiry)}</span>`;
  if (ssl.days <= 30) return `<span class="cert-expiring">${ssl.days}d</span> <span class="muted">${esc(ssl.expiry)}</span>`;
  return `<span class="cert-valid">${ssl.days}d</span> <span class="muted">${esc(ssl.expiry)}</span>`;
}

function rowHtml(r: Row): string {
  const ports = r.services.length
    ? r.services.slice(0, 10).map((s) => `<span class="port" title="${esc(s.service || s.source)}">${esc(s.proto)}/${esc(String(s.port))}</span>`).join("") + (r.services.length > 10 ? ` <span class="muted">+${r.services.length - 10}</span>` : "")
    : `<span class="muted">—</span>`;
  const reasons = r.reasons.map((x) => `<span class="reason">${esc(x)}</span>`).join("");
  const vulns = r.vulns.open
    ? `${r.vulns.kev ? `<span class="kev" title="actively exploited">KEV ${r.vulns.kev}</span> ` : ""}${r.vulns.critical ? `<span class="sev s-high">${r.vulns.critical} crit</span> ` : ""}<span class="muted">${r.vulns.open} open</span>`
    : `<span class="muted">0</span>`;
  return `<tr>
    <td><span class="scorebar"><span style="width:${Math.max(4, r.score)}%"></span></span><b>${r.score}</b></td>
    <td><span class="aname">${esc(r.name)}</span>${r.shadow ? ` <span class="shadow" title="internet-reachable but not declared public-facing">SHADOW</span>` : ""}<br><span class="muted mono">${esc(r.address)}</span><div style="margin-top:3px">${reasons}</div></td>
    <td>${esc(r.criticality)}${r.owner ? `<br><span class="muted">${esc(r.owner)}</span>` : `<br><span class="muted">no owner</span>`}</td>
    <td>${ports}</td>
    <td>${certHtml(r.ssl)}</td>
    <td>${vulns}</td>
  </tr>`;
}

function findingHtml(f: Finding): string {
  return `<tr><td><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span></td><td><a href="/?db=XORCISM&table=ASSET&filterCol=AssetID&filterVal=${esc(f.assetId)}" class="aname">${esc(f.asset)}</a></td><td>${esc(f.label.replace(`${f.asset}: `, ""))}</td></tr>`;
}

async function load(): Promise<void> {
  let d: Data;
  try { const r = await fetch("/api/easm"); if (!r.ok) throw new Error(`HTTP ${r.status}`); d = await r.json(); }
  catch (e) { $("em-body").innerHTML = `<div class="muted" style="padding:24px;text-align:center">⚠️ ${esc(e)}</div>`; return; }

  if (!d.rows.length) {
    $("em-body").innerHTML = `<div class="muted" style="padding:32px;text-align:center;line-height:1.7">
      No internet-facing assets resolved yet.<br>
      An asset joins the external surface when it has a <b>public IP</b>, a <b>website URL</b>, <b>inbound traffic</b>
      (NETWORKSESSION direction=inbound), an <b>externally-monitored endpoint</b>, or its <b>Public-facing</b> flag is set.<br>
      Mark assets public-facing in <a href="/asset-management">Asset Management</a>, import flows via the
      <a href="/network-sessions">network</a> cartography, or add HTTP/SSL monitors in <a href="/asset-monitoring">monitoring</a>.</div>`;
    return;
  }

  const s = d.summary;
  const cards = [
    card("Internet-facing", String(s.internetFacing), "exposed assets", s.internetFacing ? "#22d3ee" : undefined),
    card("Exposed services", String(s.exposedServices), `${s.openPorts} open ports`, s.exposedServices ? "#60a5fa" : undefined),
    card("External KEV", String(s.externalKev), "exploited & reachable", s.externalKev ? "#f87171" : "#34d399"),
    card("Certificates", String(s.expiredCerts + s.expiringCerts), `${s.expiredCerts} expired · ${s.expiringCerts} expiring`, (s.expiredCerts + s.expiringCerts) ? "#fbbf24" : "#34d399"),
    card("Shadow exposure", String(s.shadow), "undeclared public", s.shadow ? "#fbbf24" : "#34d399"),
    card("No owner", String(s.noOwner), "unaccountable", s.noOwner ? "#fbbf24" : undefined),
  ].join("");

  const reasonChips = Object.entries(s.byReason).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<span class="bd"><b>${esc(String(v))}</b> ${esc(k)}</span>`).join("");

  const driftHtml = d.drift && (d.drift.added.length || d.drift.removed.length)
    ? `<div class="em-section">Surface drift (vs previous snapshot · ${d.drift.snapshots} snapshot${d.drift.snapshots === 1 ? "" : "s"})</div>
       <div class="breakdown">
         ${d.drift.added.length ? `<span class="bd drift-add">▲ ${d.drift.added.length} newly exposed: ${d.drift.added.slice(0, 8).map(esc).join(", ")}${d.drift.added.length > 8 ? "…" : ""}</span>` : ""}
         ${d.drift.removed.length ? `<span class="bd drift-rem">▼ ${d.drift.removed.length} no longer exposed: ${d.drift.removed.slice(0, 8).map(esc).join(", ")}${d.drift.removed.length > 8 ? "…" : ""}</span>` : ""}
       </div>`
    : d.drift && d.drift.snapshots
      ? `<div class="em-section">Surface drift</div><div class="breakdown"><span class="bd">No change since the previous of ${d.drift.snapshots} snapshot${d.drift.snapshots === 1 ? "" : "s"}.</span></div>`
      : "";

  const surfaceTable = `<div class="em-section">Internet-facing assets (${d.rows.length})</div>
    <table class="em"><thead><tr><th>Score</th><th>Asset / address</th><th>Criticality / owner</th><th>Exposed ports</th><th>TLS cert</th><th>External vulns</th></tr></thead>
    <tbody>${d.rows.map(rowHtml).join("")}</tbody></table>`;

  const worklist = d.worklist.length
    ? `<div class="em-section">Exposures worklist (${d.worklist.length})</div>
       <table class="em"><thead><tr><th>Severity</th><th>Asset</th><th>Exposure</th></tr></thead>
       <tbody>${d.worklist.map(findingHtml).join("")}</tbody></table>`
    : `<div class="em-section">Exposures worklist</div><div class="breakdown"><span class="bd">✅ No open exposures — the external surface is clean.</span></div>`;

  $("em-body").innerHTML = `<div class="em-cards">${cards}</div>
    <div class="em-section">Why exposed</div><div class="breakdown">${reasonChips || `<span class="bd">—</span>`}</div>
    ${driftHtml}
    ${worklist}
    ${surfaceTable}
    <div class="legend">Outside-in view derived from ASSET (public IP / website / public-facing), ASSETSERVICE &amp; inbound NETWORKSESSION (ports), MONITORINGCHECK (TLS), and ASSETVULNERABILITY ⋈ XVULNERABILITY (KEV/critical). Snapshot the surface to track drift.</div>`;
}

async function snapshot(): Promise<void> {
  const btn = $("em-snap") as HTMLButtonElement; const stat = $("em-snap-stat");
  btn.disabled = true; stat.textContent = "Capturing…";
  try {
    const r = await fetch("/api/easm/snapshot", { method: "POST" });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
    stat.innerHTML = `✅ Snapshot #${esc(j.snapshotId)} — ${esc(j.assets)} assets, ${esc(j.exposed)} exposed. Drift will compare against this next time.`;
    toast("Surface snapshot captured");
    void load();
  } catch (e) { stat.innerHTML = `⚠️ ${esc(e)}`; }
  finally { btn.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  void load();
  const btn = document.getElementById("em-snap");
  if (btn) btn.addEventListener("click", () => void snapshot());
});
