/**
 * easm.ts — External Attack Surface Management (outside-in view of the estate).
 *
 * Where asset-management is the inside-out governance pane, EASM is the attacker's
 * outside-in pane: it isolates the *internet-facing* subset of ASSET and resolves, per
 * exposed asset, WHY it is on the surface (public IP / website / inbound traffic / a
 * monitored endpoint / a "public-facing" flag), the SERVICES & PORTS it exposes
 * (ASSETSERVICE + external-inbound NETWORKSESSION + monitors), its TLS/cert posture
 * (MONITORINGCHECK SSL expiry), and the externally-reachable VULNERABILITIES it carries
 * (cross-DB to XVULNERABILITY for KEV / critical). It then derives the exposures a team
 * acts on — KEV on an internet-facing host, expired/expiring certificates, excessive open
 * ports, unmanaged ("shadow") exposure, owner-less public assets — each with a 0-100 score,
 * plus a surface-drift delta (new/removed exposed assets) from XSURFACESNAPSHOT.
 *
 * Read-only. Reuses the same building blocks as assets.ts / monitoring.ts / netflow.ts /
 * drift.ts rather than introducing new tables.
 */
import { getDb } from "./db";
import { surfaceDrift } from "./drift";

export interface EasmService { proto: string; port: number; service: string; source: string }
export interface EasmRow {
  id: number;
  name: string;
  address: string;                 // best public address (url / ip / fqdn)
  reasons: string[];               // why it is on the external surface
  criticality: string;
  owner: string | null;
  services: EasmService[];
  openPorts: number;
  ssl: { days: number | null; expiry: string | null; status: string } | null;
  vulns: { open: number; kev: number; critical: number };
  shadow: boolean;                 // exposed (inbound/public IP) but not marked public-facing
  flags: string[];
  score: number;                   // 0-100 derived exposure priority
}
export interface EasmFinding { kind: string; label: string; severity: "Critical" | "High" | "Medium" | "Low"; assetId: number; asset: string }
export interface EasmInventory {
  rows: EasmRow[];
  worklist: EasmFinding[];
  drift: { added: string[]; removed: string[]; snapshots: number } | null;
  summary: {
    internetFacing: number; exposedServices: number; openPorts: number;
    expiringCerts: number; expiredCerts: number; externalKev: number; shadow: number;
    noOwner: number; byReason: Record<string, number>;
  };
}

const EMPTY: EasmInventory = {
  rows: [], worklist: [], drift: null,
  summary: { internetFacing: 0, exposedServices: 0, openPorts: 0, expiringCerts: 0, expiredCerts: 0, externalKev: 0, shadow: 0, noOwner: 0, byReason: {} },
};

const SSL_SOON_DAYS = 30;
const CRITICAL = /^(high|critical)$/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function has(dbName: string, table: string): boolean {
  try { return !!getDb(dbName).prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table); }
  catch { return false; }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || String(v ?? "").toLowerCase() === "true"; }
function num(v: unknown): number | null { const n = Number(v); return Number.isFinite(n) && v !== null && v !== "" ? n : null; }
function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date).replace(" ", "T"));
  return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000);
}
/** RFC1918 / loopback / link-local / unspecified → not internet-reachable. */
function isPrivateIp(ip: string): boolean {
  const s = (ip || "").trim();
  if (!s) return true;
  if (/^(10\.|127\.|169\.254\.|0\.0\.0\.0|::1$|fe80:|fc|fd)/i.test(s)) return true;
  if (/^192\.168\./.test(s)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s)) return true;
  return false;
}

/** Outside-in external attack surface inventory + exposures worklist. */
export function easmInventory(tenant: number | null): EasmInventory {
  if (!has("XORCISM", "ASSET")) return { ...EMPTY };
  const db = getDb("XORCISM");
  const ac = cols("XORCISM", "ASSET");
  const col = (c: string): boolean => ac.has(c);
  const tw = tenant != null && col("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const assets = db.prepare(`SELECT * FROM ASSET ${tw}`).all() as Record<string, unknown>[];
  if (!assets.length) return { ...EMPTY };

  // Owner names (PERSON).
  const persons = new Map<number, string>();
  if (cols("XORCISM", "PERSON").has("FullName"))
    for (const p of db.prepare(`SELECT PersonID, FullName FROM PERSON`).all() as { PersonID: number; FullName: string }[]) persons.set(Number(p.PersonID), p.FullName);

  // Exposed services per asset (ASSETSERVICE: protocol/port the host serves).
  const svcByAsset = new Map<number, EasmService[]>();
  if (has("XORCISM", "ASSETSERVICE")) {
    const sc = cols("XORCISM", "ASSETSERVICE");
    const stw = tenant != null && sc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const s of db.prepare(`SELECT AssetID, Protocol, Port, ServiceName FROM ASSETSERVICE ${stw}`).all() as Record<string, unknown>[]) {
      const aid = Number(s.AssetID); if (!aid) continue;
      const list = svcByAsset.get(aid) ?? []; list.push({ proto: String(s.Protocol ?? "tcp"), port: Number(s.Port ?? 0), service: String(s.ServiceName ?? "").trim(), source: "service" }); svcByAsset.set(aid, list);
    }
  }
  // External-inbound flows (NETWORKSESSION direction=inbound) → reachable dst ports + a "reason".
  const inboundAssets = new Set<number>();
  if (has("XORCISM", "NETWORKSESSION")) {
    const nc = cols("XORCISM", "NETWORKSESSION");
    if (nc.has("DstAssetID") && nc.has("Direction")) {
      const ntw = tenant != null && nc.has("TenantID") ? `AND TenantID = ${tenant}` : "";
      for (const s of db.prepare(`SELECT DstAssetID, Protocol, DstPort, ServiceName FROM NETWORKSESSION WHERE LOWER(Direction)='inbound' AND DstAssetID IS NOT NULL ${ntw}`).all() as Record<string, unknown>[]) {
        const aid = Number(s.DstAssetID); if (!aid) continue;
        inboundAssets.add(aid);
        const list = svcByAsset.get(aid) ?? [];
        const port = Number(s.DstPort ?? 0);
        if (port && !list.some((x) => x.port === port && x.proto === String(s.Protocol ?? "tcp"))) { list.push({ proto: String(s.Protocol ?? "tcp"), port, service: String(s.ServiceName ?? "").trim(), source: "inbound" }); svcByAsset.set(aid, list); }
      }
    }
  }
  // SSL / monitored endpoints (MONITORINGCHECK): cert expiry + "monitored" reason.
  const sslByAsset = new Map<number, { days: number | null; expiry: string | null; status: string }>();
  const monitoredAssets = new Set<number>();
  if (has("XORCISM", "MONITORINGCHECK")) {
    const mc = cols("XORCISM", "MONITORINGCHECK");
    if (mc.has("AssetID")) {
      const mtw = tenant != null && mc.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
      for (const c of db.prepare(`SELECT AssetID, CheckType, Target, SSLExpiryDate FROM MONITORINGCHECK ${mtw}`).all() as Record<string, unknown>[]) {
        const aid = Number(c.AssetID); if (!aid) continue;
        const type = String(c.CheckType ?? "").toLowerCase();
        if (type === "http" || type === "ssl" || type === "tcp") monitoredAssets.add(aid);
        const days = daysUntil(c.SSLExpiryDate ? String(c.SSLExpiryDate) : null);
        if (days != null) {
          const prev = sslByAsset.get(aid);
          if (!prev || prev.days == null || days < prev.days)
            sslByAsset.set(aid, { days, expiry: String(c.SSLExpiryDate).slice(0, 10), status: days < 0 ? "expired" : days <= SSL_SOON_DAYS ? "expiring" : "valid" });
        }
      }
    }
  }
  // Open vulnerabilities per asset, enriched cross-DB (KEV / critical).
  const vulnByAsset = new Map<number, { open: number; kev: number; critical: number }>();
  if (has("XORCISM", "ASSETVULNERABILITY")) {
    const avc = cols("XORCISM", "ASSETVULNERABILITY");
    const fp = avc.has("FalsePositive") ? "AND (FalsePositive IS NULL OR FalsePositive = 0)" : "";
    const avtw = tenant != null && avc.has("TenantID") ? `AND TenantID = ${tenant}` : "";
    const links = db.prepare(`SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${fp} ${avtw}`).all() as { AssetID: number; VulnerabilityID: number }[];
    const meta = new Map<number, { kev: boolean; crit: boolean }>();
    const vids = [...new Set(links.map((l) => Number(l.VulnerabilityID)))];
    if (vids.length && cols("XVULNERABILITY", "VULNERABILITY").size) {
      const xv = getDb("XVULNERABILITY");
      const vc = cols("XVULNERABILITY", "VULNERABILITY");
      const sevCol = vc.has("SsvcDecision") ? "SsvcDecision" : "''";
      for (let i = 0; i < vids.length; i += 400) {
        const chunk = vids.slice(i, i + 400);
        const ph = chunk.map(() => "?").join(",");
        const rows = xv.prepare(`SELECT VulnerabilityID, ${vc.has("KEV") ? "KEV" : "0 AS KEV"}, ${vc.has("CVSSBaseScore") ? "CVSSBaseScore" : "NULL AS CVSSBaseScore"}, ${sevCol} AS Ssvc FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { VulnerabilityID: number; KEV: unknown; CVSSBaseScore: unknown; Ssvc: string }[];
        for (const r of rows) {
          const kev = truthy(r.KEV);
          const crit = kev || (num(r.CVSSBaseScore) ?? 0) >= 9 || /act|attend/i.test(String(r.Ssvc ?? ""));
          meta.set(Number(r.VulnerabilityID), { kev, crit });
        }
      }
    }
    for (const l of links) {
      const a = vulnByAsset.get(Number(l.AssetID)) ?? { open: 0, kev: 0, critical: 0 };
      a.open++;
      const m = meta.get(Number(l.VulnerabilityID));
      if (m?.kev) a.kev++;
      if (m?.crit) a.critical++;
      vulnByAsset.set(Number(l.AssetID), a);
    }
  }

  const worklist: EasmFinding[] = [];
  const byReason: Record<string, number> = {};
  const rows: EasmRow[] = [];
  for (const a of assets) {
    const id = Number(a.AssetID);
    const name = String(a.AssetName ?? "").trim() || `Asset #${id}`;
    const ip = String(a.ipaddressIPv4 ?? "").trim();
    const url = String(a.websiteurl ?? "").trim();
    const fqdn = String(a.fqdn || a.hostname || "").trim();
    const publicFlag = truthy(a.PublicFacing);
    const publicIp = !!ip && !isPrivateIp(ip);
    const inbound = inboundAssets.has(id);
    const monitored = monitoredAssets.has(id);

    // Reasons this asset is on the external attack surface.
    const reasons: string[] = [];
    if (publicFlag) reasons.push("Marked internet-facing");
    if (url) reasons.push(`Public website (${url.replace(/^https?:\/\//, "").slice(0, 40)})`);
    if (publicIp) reasons.push(`Public IP (${ip})`);
    if (inbound) reasons.push("Inbound traffic from the Internet");
    if (monitored && !publicFlag && !url && !publicIp) reasons.push("Externally-monitored endpoint");
    if (!reasons.length) continue;   // internal asset — not part of the external surface
    for (const r of reasons) { const key = r.replace(/\s*\(.*/, ""); byReason[key] = (byReason[key] || 0) + 1; }

    const criticality = String(a.AssetCriticalityLevel ?? "").trim() || "Unrated";
    const isCrit = CRITICAL.test(criticality);
    const ownerId = a.PersonID != null ? Number(a.PersonID) : null;
    const owner = ownerId != null ? (persons.get(ownerId) ?? `#${ownerId}`) : null;
    const address = url || (publicIp ? ip : "") || fqdn || ip || "—";
    const services = (svcByAsset.get(id) ?? []).sort((x, y) => x.port - y.port);
    const openPorts = new Set(services.map((s) => `${s.proto}/${s.port}`)).size;
    const ssl = sslByAsset.get(id) ?? null;
    const v = vulnByAsset.get(id) ?? { open: 0, kev: 0, critical: 0 };
    // "Shadow": reachable from the Internet (inbound/public IP) yet not formally marked public-facing.
    const shadow = (inbound || publicIp) && !publicFlag;

    const flags: string[] = [];
    let score = 0;
    const add = (kind: string, label: string, severity: EasmFinding["severity"], pts: number): void => {
      flags.push(label); score += pts;
      worklist.push({ kind, label: `${name}: ${label}`, severity, assetId: id, asset: name });
    };

    if (v.kev) add("kev", `${v.kev} actively-exploited (KEV) vuln${v.kev > 1 ? "s" : ""} on an internet-facing host`, "Critical", 40);
    else if (v.critical) add("critvuln", `${v.critical} critical vuln${v.critical > 1 ? "s" : ""} externally reachable`, "High", 22);
    if (ssl && ssl.days != null && ssl.days < 0) add("certexpired", `TLS certificate EXPIRED (${ssl.expiry})`, "Critical", 30);
    else if (ssl && ssl.days != null && ssl.days <= SSL_SOON_DAYS) add("certexpiring", `TLS certificate expires in ${ssl.days}d (${ssl.expiry})`, ssl.days <= 7 ? "High" : "Medium", 12);
    if (openPorts > 5) add("ports", `${openPorts} open service ports exposed`, "Medium", 10);
    if (shadow) add("shadow", "Internet-reachable but not declared public-facing (shadow exposure)", "High", 14);
    if (ownerId == null) add("orphan", "Internet-facing asset has no owner", "Medium", 10);
    if (isCrit && (publicFlag || publicIp)) add("crown", "Internet-facing crown-jewel asset", "High", 12);

    rows.push({ id, name, address, reasons, criticality, owner, services, openPorts, ssl, vulns: v, shadow, flags, score: Math.min(100, score) });
  }

  rows.sort((x, y) => y.score - x.score || y.vulns.kev - x.vulns.kev || y.openPorts - x.openPorts);
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  worklist.sort((x, y) => sevRank[x.severity] - sevRank[y.severity]);

  // Surface drift (new / removed exposed assets) from the latest two snapshots, best-effort.
  let drift: EasmInventory["drift"] = null;
  try {
    const d = surfaceDrift(tenant);
    if (d.snapshots) drift = { added: (d.added || []).slice(0, 50), removed: (d.removed || []).slice(0, 50), snapshots: d.snapshots };
  } catch { /* drift unavailable */ }

  const summary = {
    internetFacing: rows.length,
    exposedServices: rows.reduce((s, r) => s + r.services.length, 0),
    openPorts: rows.reduce((s, r) => s + r.openPorts, 0),
    expiringCerts: rows.filter((r) => r.ssl && r.ssl.days != null && r.ssl.days >= 0 && r.ssl.days <= SSL_SOON_DAYS).length,
    expiredCerts: rows.filter((r) => r.ssl && r.ssl.days != null && r.ssl.days < 0).length,
    externalKev: rows.reduce((s, r) => s + r.vulns.kev, 0),
    shadow: rows.filter((r) => r.shadow).length,
    noOwner: rows.filter((r) => r.owner == null).length,
    byReason,
  };
  return { rows, worklist: worklist.slice(0, 200), drift, summary };
}
