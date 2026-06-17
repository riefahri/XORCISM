/**
 * attackpath.ts — Attack-path & choke-point analysis (the XM Cyber / BloodHound move).
 *
 * Builds a reachability graph over ASSETs:
 *   - edges  : same-/24 network adjacency (from ASSET IPs) + BIA dependencies (BIADEPENDENCY)
 *   - entries: internet-exposed assets (websiteurl or a public IPv4) = attacker footholds
 *   - jewels : high-value assets (BusinessValue / RiskScore) = crown jewels
 *   - cost   : traversing INTO a node = 100 − its exploitability (fusion score); easier-to-own
 *              nodes are cheaper, so the shortest path is the easiest real attack route.
 *
 * Then: fusion-weighted multi-source Dijkstra (all entries → each jewel) yields the easiest
 * attack path to every crown jewel, and a choke-point ranking — the single node on the most
 * paths, i.e. the one fix/segmentation that severs the most attack routes.
 */
import { getDb } from "./db";
import { vulnExploitability } from "./fusion";

export interface ApNode {
  id: number; label: string; ip: string | null; role: "entry" | "jewel" | "node";
  exposure: number; value: number; onPath: boolean; choke: number;
}
export interface ApLink { source: number; target: number; kind: "subnet" | "bia"; onPath: boolean; }
export interface ApPath { jewel: number; jewelLabel: string; entry: number; entryLabel: string; cost: number; nodes: number[]; steps: string[]; }
export interface AttackPathGraph {
  nodes: ApNode[]; links: ApLink[]; paths: ApPath[];
  chokepoints: { id: number; label: string; paths: number }[];
  stats: { assets: number; entries: number; jewels: number; edges: number; pathsFound: number };
}

function cols(db: ReturnType<typeof getDb>, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
}
function isPublicV4(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  return a > 0 && a < 224;
}
function slash24(ip: string | null): string | null {
  const m = (ip || "").match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
  return m ? m[1] : null;
}

export function attackPathGraph(tenant: number | null): AttackPathGraph {
  const xo = getDb("XORCISM");
  const aCols = cols(xo, "ASSET");
  const where: string[] = []; const args: unknown[] = [];
  if (tenant != null && aCols.has("TenantID")) { where.push('("TenantID" = ? OR "TenantID" IS NULL)'); args.push(tenant); }
  const sel = ["AssetID", "AssetName", "ipaddressIPv4", "websiteurl", "BusinessValue", "RiskScore", "fqdn", "hostname"].filter((c) => aCols.has(c) || c === "AssetID");
  const rows = xo.prepare(
    `SELECT ${sel.map((c) => `"${c}"`).join(",")} FROM ASSET ${where.length ? "WHERE " + where.join(" AND ") : ""} LIMIT 2000`
  ).all(...args) as Record<string, any>[];

  interface A { id: number; name: string; ip: string | null; web: string | null; value: number; exposure: number; }
  const assets: A[] = rows.map((r) => ({
    id: r.AssetID, name: String(r.AssetName ?? `#${r.AssetID}`), ip: r.ipaddressIPv4 ? String(r.ipaddressIPv4).trim() : null,
    web: r.websiteurl ? String(r.websiteurl).trim() : null, value: Number(r.BusinessValue) || Number(r.RiskScore) || 0, exposure: 0,
  }));
  const byId = new Map(assets.map((a) => [a.id, a]));
  const empty: AttackPathGraph = { nodes: [], links: [], paths: [], chokepoints: [], stats: { assets: assets.length, entries: 0, jewels: 0, edges: 0, pathsFound: 0 } };
  if (assets.length < 2) return empty;

  // per-asset exposure = max exploitability over its vulnerabilities
  try {
    const ids = assets.map((a) => a.id);
    const av = new Map<number, number[]>();
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const r of xo.prepare(
        `SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE AssetID IN (${ph}) AND COALESCE(FalsePositive,0)=0`
      ).all(...chunk) as { AssetID: number; VulnerabilityID: number }[]) {
        (av.get(r.AssetID) ?? av.set(r.AssetID, []).get(r.AssetID)!).push(r.VulnerabilityID);
      }
    }
    const allVids = [...new Set([...av.values()].flat())];
    const score = vulnExploitability(allVids);
    for (const a of assets) { const vs = av.get(a.id) || []; a.exposure = vs.reduce((mx, v) => Math.max(mx, score.get(v) || 0), 0); }
  } catch { /* vuln data unavailable → exposure 0 */ }

  // edges: same-/24 adjacency
  const links: ApLink[] = [];
  const adj = new Map<number, Set<number>>();
  const link = (s: number, t: number, kind: "subnet" | "bia") => {
    if (s === t) return;
    (adj.get(s) ?? adj.set(s, new Set()).get(s)!).add(t);
    (adj.get(t) ?? adj.set(t, new Set()).get(t)!).add(s);
    links.push({ source: s, target: t, kind, onPath: false });
  };
  const subnets = new Map<string, number[]>();
  for (const a of assets) { const s = slash24(a.ip); if (s) (subnets.get(s) ?? subnets.set(s, []).get(s)!).push(a.id); }
  const seenEdge = new Set<string>();
  for (const grp of subnets.values()) {
    if (grp.length < 2 || grp.length > 60) continue; // skip singletons & implausibly huge "subnets"
    for (let i = 0; i < grp.length; i++) for (let j = i + 1; j < grp.length; j++) {
      const k = `${grp[i]}|${grp[j]}`; if (seenEdge.has(k)) continue; seenEdge.add(k); link(grp[i], grp[j], "subnet");
    }
  }
  // edges: BIA dependencies (BIAENTRY.AssetName → ASSET.AssetName)
  try {
    const byName = new Map(assets.map((a) => [a.name.toLowerCase(), a.id]));
    const deps = xo.prepare(
      `SELECT e1.AssetName a, e2.AssetName b FROM BIADEPENDENCY d
       JOIN BIAENTRY e1 ON e1.BIAEntryID=d.FromEntryID JOIN BIAENTRY e2 ON e2.BIAEntryID=d.ToEntryID`
    ).all() as { a: string; b: string }[];
    for (const d of deps) {
      const s = byName.get(String(d.a || "").toLowerCase()), t = byName.get(String(d.b || "").toLowerCase());
      const k = s != null && t != null ? `${Math.min(s, t)}|${Math.max(s, t)}` : null;
      if (s != null && t != null && k && !seenEdge.has(k)) { seenEdge.add(k); link(s, t, "bia"); }
    }
  } catch { /* no BIA data */ }

  // entries (internet-exposed) + crown jewels (top value)
  const entries = assets.filter((a) => a.web || (a.ip && isPublicV4(a.ip))).map((a) => a.id);
  const valued = assets.filter((a) => a.value > 0).sort((x, y) => y.value - x.value);
  const jewelCount = valued.length ? Math.max(3, Math.ceil(valued.length * 0.2)) : 0;
  const jewels = valued.slice(0, jewelCount).map((a) => a.id);
  const jewelSet = new Set(jewels), entrySet = new Set(entries);

  // fusion-weighted multi-source Dijkstra: easiest path from any entry to each jewel
  const costOf = (id: number) => Math.max(1, 100 - (byId.get(id)?.exposure || 0));
  const paths: ApPath[] = [];
  const chokeCount = new Map<number, number>();
  const onPathNodes = new Set<number>(); const onPathEdges = new Set<string>();
  if (entries.length && jewels.length) {
    // single Dijkstra from all entries; then read off each jewel's path
    const dist = new Map<number, number>(); const prev = new Map<number, number>();
    const pq: { id: number; d: number }[] = [];
    for (const e of entries) { dist.set(e, costOf(e)); pq.push({ id: e, d: costOf(e) }); }
    const done = new Set<number>();
    while (pq.length) {
      pq.sort((a, b) => a.d - b.d); const { id } = pq.shift()!;
      if (done.has(id)) continue; done.add(id);
      for (const nb of adj.get(id) || []) {
        const nd = (dist.get(id) ?? Infinity) + costOf(nb);
        if (nd < (dist.get(nb) ?? Infinity)) { dist.set(nb, nd); prev.set(nb, id); pq.push({ id: nb, d: nd }); }
      }
    }
    for (const j of jewels) {
      if (!dist.has(j)) continue; // unreachable
      const chain: number[] = []; let cur: number | undefined = j;
      while (cur != null) { chain.unshift(cur); cur = prev.get(cur); }
      const entry = chain[0];
      if (!entrySet.has(entry)) continue;
      paths.push({ jewel: j, jewelLabel: byId.get(j)!.name, entry, entryLabel: byId.get(entry)!.name, cost: Math.round(dist.get(j)!), nodes: chain, steps: chain.map((c) => byId.get(c)!.name) });
      for (let i = 0; i < chain.length; i++) {
        onPathNodes.add(chain[i]);
        if (i > 0) onPathEdges.add(`${Math.min(chain[i - 1], chain[i])}|${Math.max(chain[i - 1], chain[i])}`);
        if (i > 0 && i < chain.length - 1) chokeCount.set(chain[i], (chokeCount.get(chain[i]) || 0) + 1); // intermediate hops
      }
    }
  }
  paths.sort((a, b) => a.cost - b.cost);
  for (const l of links) if (onPathEdges.has(`${Math.min(l.source, l.target)}|${Math.max(l.source, l.target)}`)) l.onPath = true;

  const nodes: ApNode[] = assets.map((a) => ({
    id: a.id, label: a.name, ip: a.ip,
    role: jewelSet.has(a.id) ? "jewel" : entrySet.has(a.id) ? "entry" : "node",
    exposure: a.exposure, value: a.value, onPath: onPathNodes.has(a.id), choke: chokeCount.get(a.id) || 0,
  }));
  const chokepoints = [...chokeCount.entries()].map(([id, n]) => ({ id, label: byId.get(id)!.name, paths: n })).sort((a, b) => b.paths - a.paths).slice(0, 10);

  return { nodes, links, paths, chokepoints, stats: { assets: assets.length, entries: entries.length, jewels: jewels.length, edges: links.length, pathsFound: paths.length } };
}
