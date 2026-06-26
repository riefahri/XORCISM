/**
 * threatdebt.ts — Adversary Opportunity Index (AOI).
 *
 * XORCISM's rename of the "threat debt" idea: a single, derived top-line that measures the *true
 * adversary opportunity* in the environment — path-organized, adversary-weighted, business-weighted,
 * and net of the controls you can prove. It is the attacker's-eye sibling to the (defender's)
 * EnterpriseRiskScore.
 *
 * It does NOT re-instrument anything — it COMPOSES engines that already exist:
 *   - attackpath.ts  attackPathGraph()  → the "Attack Path Test" Q1 (a viable entry→crown-jewel path
 *                     exists) + per-node exploitability (fusion: EPSS/KEV/exploit) + crown-jewel value.
 *   - tid.ts         tidInventory()     → Q2∩Q3: the threat-weighted defence-coverage score
 *                     (do adversaries use techniques we can't detect/mitigate/test?).
 *   - assurance.ts   controlAssurance() → credits the controls you can PROVE from telemetry.
 *   - fusion.ts      topExposures()     → graceful fallback when an estate has no attack-path data.
 *
 * Model (Phase 1):
 *   rawDebt        = Σ_paths [ (Σ on-path node exposure / 100) × jewelWeight(path) × 100 ]
 *   defenceResidual= clamp( (100 − tidScore)/100 − 0.3·assuranceCredit , 0.05 , 1 )   // Q2∩Q3, credited
 *   AOI (STOCK)    = round( 1000 × (1 − e^(−rawDebt/SCALE)) × defenceResidual )        // bounded, monotonic
 *   FLOW           = AOI(today) − AOI(previous snapshot)   (item-level paid/accrued split = Phase 2 ledger)
 *
 * Snapshots accrue in THREATDEBTSNAPSHOT (upsert per tenant per day), mirroring ORGANISATIONRISKSCORE.
 */
import { getDb } from "./db";
import { attackPathGraph, AttackPathGraph } from "./attackpath";
import { topExposures, vulnExploitability } from "./fusion";
import { tidInventory } from "./tid";
import { controlAssurance } from "./assurance";
import { emitLoopEvent } from "./croc";
import { createExposure } from "./ctem";

const SCALE = Number(process.env.XOR_AOI_SCALE) || 2000; // dampening of the saturating rawDebt→AOI curve (tunable)

export interface AoiSource { key: string; label: string; items: number; status: "live" | "tracked"; note: string }
export interface AoiPath { entry: string; jewel: string; hops: number; debt: number; cost: number }
export interface AoiFix { label: string; paths: number; deltaEst: number; rationale: string }
/** Phase-2 ledger item: a concrete qualifying finding tracked open→closed for exact FLOW accounting. */
export interface DebtItem { key: string; source: string; label: string; debt: number }
export interface LedgerFlow { accrued: number; paidDown: number; openItems: number; openDebt: number }
export interface Aoi {
  index: number;                 // STOCK, 0..1000
  rawDebt: number;
  pathData: boolean;
  paths: { found: number; jewels: number; entries: number };
  factors: { tidScore: number; defenceResidual: number; assuranceCredit: number };
  bySource: AoiSource[];
  worklist: AoiFix[];            // choke-point "price the fix" — biggest AOI index paydown per fix
  sourceFixes: { source: string; label: string; items: number; debt: number }[]; // ledger debt retired per source
  topItems: { source: string; label: string; debt: number }[];                    // per-item price the fix (open ledger, by debt)
  topPaths: AoiPath[];
  flow: { previous: number | null; net: number | null; since: string | null; accrued: number; paidDown: number; openItems: number };
  evaluatedAt: string;
}

const clamp = (x: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, x));
const today = (): string => new Date().toISOString().slice(0, 10);
const aoiOf = (rawDebt: number, residual: number): number =>
  Math.round(1000 * (1 - Math.exp(-Math.max(0, rawDebt) / SCALE)) * residual);

function count(db: ReturnType<typeof getDb>, sql: string, ...args: unknown[]): number {
  try { return (db.prepare(sql).get(...args) as { n: number }).n || 0; } catch { return 0; }
}

/** Compute the Adversary Opportunity Index for a tenant. Pass an already-built attack-path graph to
 *  avoid recomputing it (e.g. from boardReport, which already holds one). */
export function adversaryOpportunityIndex(tenant: number | null, graph?: AttackPathGraph): Aoi {
  const g = graph ?? attackPathGraph(tenant);
  const byId = new Map(g.nodes.map((n) => [n.id, n]));

  // crown-jewel value normalization → business-impact weight in [0.2 .. 1]
  const maxVal = Math.max(1, ...g.nodes.filter((n) => n.role === "jewel").map((n) => n.value));
  const jewelWeight = (jewelId: number): number => 0.2 + 0.8 * ((byId.get(jewelId)?.value || 0) / maxVal);

  // rawDebt = Σ over reachable paths of (on-path exploitability) × (business impact of the jewel)
  let rawDebt = 0;
  const topPaths: AoiPath[] = [];
  for (const p of g.paths) {
    const expSum = p.nodes.reduce((s, id) => s + (byId.get(id)?.exposure || 0), 0) / 100; // ~0..#hops
    const debt = expSum * jewelWeight(p.jewel) * 100;
    rawDebt += debt;
    topPaths.push({ entry: p.entryLabel, jewel: p.jewelLabel, hops: p.nodes.length, debt: Math.round(debt), cost: p.cost });
  }
  topPaths.sort((a, b) => b.debt - a.debt);

  // adversary-weighted defence residual (Q2 ∩ Q3), credited by controls we can prove
  let tidScore = 0, assuranceCredit = 0;
  try { tidScore = tidInventory(tenant).summary.tidScore || 0; } catch { /* */ }
  try { assuranceCredit = (controlAssurance(tenant).stats.provenPct || 0) / 100; } catch { /* */ }
  // tidScore already credits detection/mitigation; assurance adds a SMALL extra credit (capped weight)
  // for telemetry-proven controls without double-discounting a well-defended estate to the floor.
  const defenceResidual = clamp((100 - tidScore) / 100 - 0.15 * assuranceCredit, 0.05, 1);

  // fallback: estate has no attack-path data → fusion-weighted finding sum (same units as path debt)
  const pathData = g.paths.length > 0;
  if (!pathData) {
    try { rawDebt = topExposures(tenant, 50).results.reduce((s, r) => s + (r.priority || 0), 0); } catch { /* */ }
  }

  const index = aoiOf(rawDebt, defenceResidual);

  // "price the fix" — hardening a choke point retires every path through it (highest ROI first)
  const totalPaths = g.paths.length || 1;
  const worklist: AoiFix[] = g.chokepoints.slice(0, 6).map((c) => {
    const after = aoiOf(rawDebt * (1 - c.paths / totalPaths), defenceResidual);
    return {
      label: c.label, paths: c.paths, deltaEst: Math.max(0, index - after),
      rationale: `Sits on ${c.paths} attack path(s) to crown jewels — hardening/segmenting it severs the most routes for the least cost.`,
    };
  }).sort((a, b) => b.deltaEst - a.deltaEst);

  // the seven sources of threat debt (cheap inventory counts; live = scored into AOI today)
  const xo = getDb("XORCISM");
  const subnetOnPath = g.links.filter((l) => l.onPath && l.kind === "subnet").length;
  const ctlGap = (() => { try { const s = controlAssurance(tenant).stats; return s.partial + s.gap; } catch { return 0; } })();
  const tidExposed = (() => { try { return tidInventory(tenant).summary.exposed; } catch { return 0; } })();
  const bySource: AoiSource[] = [
    { key: "vuln", label: "Vulnerabilities", status: "live", note: "Exploitable CVEs on reachable assets (EPSS/KEV-weighted).", items: count(xo, "SELECT COUNT(*) n FROM ASSETVULNERABILITY WHERE COALESCE(FalsePositive,0)=0") },
    { key: "misconfig", label: "Misconfigurations", status: "tracked", note: "Failed hardening checks (OVAL/CIS).", items: count(getDbSafe("XOVAL"), "SELECT COUNT(*) n FROM OVALRESULTS WHERE UPPER(COALESCE(Result,''))='FAIL'") },
    { key: "control", label: "Control weaknesses", status: "live", note: "Controls failing validation (proven-vs-compliant).", items: ctlGap },
    { key: "identity", label: "Identity & access debt", status: "tracked", note: "Over-privileged / stale / high-risk identities.", items: count(xo, "SELECT COUNT(*) n FROM IDENTITY WHERE CAST(COALESCE(RiskScore,0) AS REAL) >= 60") },
    { key: "detection", label: "Detection & response debt", status: "live", note: "Adversary techniques with no detection/mitigation.", items: tidExposed },
    { key: "network", label: "Network & segmentation debt", status: "live", note: "East-west adjacencies on attack paths.", items: subnetOnPath },
    { key: "ai", label: "AI & automation debt", status: "tracked", note: "Ungoverned AI systems / agents / MCP servers.", items: count(xo, "SELECT COUNT(*) n FROM AISYSTEM WHERE COALESCE(Frameworks,'')=''") },
  ];

  // FLOW: index movement vs the prior snapshot + item-level paid/accrued (Phase-2 ledger, read-only)
  const prev = readPreviousSnapshot(tenant);
  const since = prev?.date ?? new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  const led = ledgerFlow(tenant, since);

  return {
    index, rawDebt: Math.round(rawDebt), pathData,
    paths: { found: g.stats.pathsFound, jewels: g.stats.jewels, entries: g.stats.entries },
    factors: { tidScore, defenceResidual: Math.round(defenceResidual * 100) / 100, assuranceCredit: Math.round(assuranceCredit * 100) / 100 },
    bySource, worklist, sourceFixes: ledgerBySource(tenant), topItems: topLedgerItems(tenant), topPaths: topPaths.slice(0, 12),
    flow: {
      previous: prev?.aoi ?? null, net: prev ? index - prev.aoi : null, since: prev?.date ?? null,
      accrued: led.accrued, paidDown: led.paidDown, openItems: led.openItems,
    },
    evaluatedAt: new Date().toISOString(),
  };
}

function getDbSafe(name: string): ReturnType<typeof getDb> {
  try { return getDb(name); } catch { return getDb("XORCISM"); }
}

// ─── Snapshot history (STOCK over time; mirrors ORGANISATIONRISKSCORE) ──────────────────────────
export function ensureThreatDebtTables(): void {
  const xo = getDb("XORCISM");
  xo.prepare(
    `CREATE TABLE IF NOT EXISTS THREATDEBTSNAPSHOT (
       SnapshotID INTEGER PRIMARY KEY,
       TenantID   INTEGER,
       CreatedDate TEXT,
       AOI        INTEGER,
       RawDebt    REAL,
       Paths      INTEGER
     )`
  ).run();
  // Phase-2 item-level ledger: each qualifying debt item tracked open→closed so paid-down/accrued is
  // an exact set-diff between reconciliations (not a scalar guess). ItemKey is stable per finding.
  xo.prepare(
    `CREATE TABLE IF NOT EXISTS THREATDEBTLEDGER (
       LedgerID    INTEGER PRIMARY KEY,
       TenantID    INTEGER,
       ItemKey     TEXT,
       Source      TEXT,
       Label       TEXT,
       Debt        REAL,
       OpenedDate  TEXT,
       LastSeenDate TEXT,
       ClosedDate  TEXT,
       CtemExposureID INTEGER
     )`
  ).run();
  try { xo.prepare("CREATE INDEX IF NOT EXISTS IX_TDLEDGER_OPEN ON THREATDEBTLEDGER (TenantID, ClosedDate)").run(); } catch { /* */ }
  // CtemExposureID added after the initial Phase-2 release — backfill on existing installs.
  try {
    const lc = new Set((xo.prepare("PRAGMA table_info(THREATDEBTLEDGER)").all() as { name: string }[]).map((c) => c.name));
    if (!lc.has("CtemExposureID")) xo.exec("ALTER TABLE THREATDEBTLEDGER ADD COLUMN CtemExposureID INTEGER");
  } catch { /* */ }
}

function readPreviousSnapshot(tenant: number | null): { aoi: number; date: string } | null {
  try {
    const xo = getDb("XORCISM");
    const d = today();
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const args = tenant != null ? [tenant, d] : [d];
    const row = xo.prepare(
      `SELECT AOI AS aoi, substr(CreatedDate,1,10) AS date FROM THREATDEBTSNAPSHOT
       WHERE ${w} AND substr(CreatedDate,1,10) < ? ORDER BY CreatedDate DESC LIMIT 1`
    ).get(...args) as { aoi: number; date: string } | undefined;
    return row ?? null;
  } catch { return null; }
}

/** Compute + upsert today's AOI snapshot for a tenant (history accrues on every read). Also commits
 *  the item-level ledger reconcile so paid-down/accrued is an exact set-diff. Returns the AOI. */
export function recordThreatDebtSnapshot(tenant: number | null): Aoi {
  const g = attackPathGraph(tenant);
  let churn: LedgerChurn = { opened: 0, closed: 0, openedItems: 0, closedItems: 0 };
  try { churn = reconcileLedger(tenant, collectDebtItems(tenant, g)); } catch (e) { console.warn(`[threatdebt] ledger: ${(e as Error).message}`); }
  const aoi = adversaryOpportunityIndex(tenant, g);
  // Phase 3 — feed the CROC loop on REAL churn only (idempotent: a no-change re-run emits nothing).
  // Accrual at high/critical severity is picked up by the orchestrator, which proposes a paydown for
  // human approval; paid-down is informational (the measurable "loop closed" signal).
  try {
    if (churn.opened > 0) {
      const sev = churn.opened >= 150 ? "critical" : churn.opened >= 60 ? "high" : "medium";
      emitLoopEvent({ type: "threatdebt.accrued", source: "threatdebt", severity: sev, tenant,
        summary: `Adversary opportunity accrued +${churn.opened} (${churn.openedItems} item[s]); AOI ${aoi.index}. ${paydownReco(aoi)}` });
    }
    if (churn.closed > 0) {
      emitLoopEvent({ type: "threatdebt.paid_down", source: "threatdebt", severity: "info", tenant,
        summary: `Adversary opportunity paid down -${churn.closed} (${churn.closedItems} item[s]); AOI ${aoi.index}.` });
    }
  } catch { /* the loop must never break the caller */ }
  try {
    const xo = getDb("XORCISM");
    const d = today();
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const args = tenant != null ? [tenant, d] : [d];
    const existing = xo.prepare(`SELECT SnapshotID FROM THREATDEBTSNAPSHOT WHERE ${w} AND substr(CreatedDate,1,10) = ?`).get(...args) as { SnapshotID: number } | undefined;
    if (existing) {
      xo.prepare("UPDATE THREATDEBTSNAPSHOT SET AOI=?, RawDebt=?, Paths=? WHERE SnapshotID=?").run(aoi.index, aoi.rawDebt, aoi.paths.found, existing.SnapshotID);
    } else {
      const id = (xo.prepare("SELECT COALESCE(MAX(SnapshotID),0)+1 AS n FROM THREATDEBTSNAPSHOT").get() as { n: number }).n;
      xo.prepare("INSERT INTO THREATDEBTSNAPSHOT (SnapshotID, TenantID, CreatedDate, AOI, RawDebt, Paths) VALUES (?,?,?,?,?,?)").run(id, tenant, d, aoi.index, aoi.rawDebt, aoi.paths.found);
    }
  } catch (e) { console.warn(`[threatdebt] snapshot: ${(e as Error).message}`); }
  return aoi;
}

/** Light read of the latest AOI snapshot (+ net vs the prior one) for the dashboard KPI strip —
 *  no heavy recompute on dashboard load. Null if no snapshot has been taken yet. */
export function threatDebtLatest(tenant: number | null): { index: number; date: string; net: number | null } | null {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    const rows = xo.prepare(`SELECT AOI AS aoi, substr(CreatedDate,1,10) AS date FROM THREATDEBTSNAPSHOT WHERE ${w} ORDER BY CreatedDate DESC LIMIT 2`).all(...a) as { aoi: number; date: string }[];
    if (!rows.length) return null;
    return { index: rows[0].aoi, date: rows[0].date, net: rows.length > 1 ? rows[0].aoi - rows[1].aoi : null };
  } catch { return null; }
}

export function threatDebtHistory(tenant: number | null, sinceDate: string | null): { date: string; aoi: number }[] {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const args: unknown[] = tenant != null ? [tenant] : [];
    let extra = "";
    if (sinceDate) { extra = "AND substr(CreatedDate,1,10) >= ?"; args.push(sinceDate); }
    return xo.prepare(`SELECT substr(CreatedDate,1,10) AS date, AOI AS aoi FROM THREATDEBTSNAPSHOT WHERE ${w} ${extra} ORDER BY CreatedDate`).all(...args) as { date: string; aoi: number }[];
  } catch { return []; }
}

// ─── Phase-2: item-level ledger (exact paid-down / accrued) ─────────────────────────────────────

/** Collect the canonical set of qualifying debt items across the seven sources. Asset-resident
 *  sources (vuln, network) are gated by the Attack Path Test (must lie on a reachable path); posture
 *  sources (control, identity, AI, misconfig) are environment-wide. Each item carries a debt weight. */
function collectDebtItems(tenant: number | null, g: AttackPathGraph): DebtItem[] {
  const items: DebtItem[] = [];
  const xo = getDb("XORCISM");
  const onPath = new Set(g.nodes.filter((n) => n.onPath).map((n) => n.id));
  const valOf = new Map(g.nodes.map((n) => [n.id, n.value]));
  const maxVal = Math.max(1, ...g.nodes.filter((n) => n.role === "jewel").map((n) => n.value));
  const wt = (id: number): number => 0.4 + 0.6 * Math.min(1, (valOf.get(id) || 0) / maxVal);

  // 1. vulnerabilities — open ASSETVULNERABILITY on on-path assets (Q1: viable path)
  if (onPath.size) {
    try {
      const ids = [...onPath]; const av: { AssetID: number; VulnerabilityID: number }[] = [];
      for (let i = 0; i < ids.length; i += 800) {
        const chunk = ids.slice(i, i + 800), ph = chunk.map(() => "?").join(",");
        av.push(...(xo.prepare(`SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE AssetID IN (${ph}) AND COALESCE(FalsePositive,0)=0`).all(...chunk) as { AssetID: number; VulnerabilityID: number }[]));
      }
      const expl = vulnExploitability([...new Set(av.map((r) => r.VulnerabilityID))]);
      for (const r of av) {
        const e = expl.get(r.VulnerabilityID) || 0;
        if (e <= 0) continue;
        items.push({ key: `vuln:${r.AssetID}:${r.VulnerabilityID}`, source: "vuln", label: `Exploitable CVE on asset #${r.AssetID}`, debt: Math.max(1, Math.round((e / 100) * wt(r.AssetID) * 100)) });
      }
    } catch { /* */ }
  }
  // 2. network & segmentation — on-path east-west adjacencies
  for (const l of g.links) if (l.onPath && l.kind === "subnet") {
    const a = Math.min(l.source, l.target), b = Math.max(l.source, l.target);
    items.push({ key: `net:${a}-${b}`, source: "network", label: "East-west adjacency on attack path", debt: 25 });
  }
  // 3. control weaknesses — controls failing validation (proven-vs-compliant)
  try {
    for (const c of controlAssurance(tenant).controls) {
      if (c.status === "gap") items.push({ key: `control:${c.id}`, source: "control", label: c.name, debt: 35 });
      else if (c.status === "partial") items.push({ key: `control:${c.id}`, source: "control", label: c.name, debt: 18 });
    }
  } catch { /* */ }
  // 4. identity & access debt — high-risk identities
  try {
    for (const r of xo.prepare("SELECT rowid AS rid FROM IDENTITY WHERE CAST(COALESCE(RiskScore,0) AS REAL) >= 60 LIMIT 300").all() as { rid: number }[])
      items.push({ key: `id:${r.rid}`, source: "identity", label: "High-risk identity", debt: 30 });
  } catch { /* */ }
  // 5. AI & automation debt — ungoverned AI systems / agents / MCP servers
  try {
    for (const r of xo.prepare("SELECT rowid AS rid FROM AISYSTEM WHERE COALESCE(Frameworks,'')='' LIMIT 200").all() as { rid: number }[])
      items.push({ key: `ai:${r.rid}`, source: "ai", label: "Ungoverned AI system", debt: 45 });
  } catch { /* */ }
  // 6. misconfigurations — failed hardening checks (OVAL/CIS)
  try {
    for (const r of getDbSafe("XOVAL").prepare("SELECT rowid AS rid FROM OVALRESULTS WHERE UPPER(COALESCE(Result,''))='FAIL' LIMIT 300").all() as { rid: number }[])
      items.push({ key: `oval:${r.rid}`, source: "misconfig", label: "Failed hardening check", debt: 8 });
  } catch { /* */ }
  return items;
}

export interface LedgerChurn { opened: number; closed: number; openedItems: number; closedItems: number }

/** Commit a ledger reconcile: open newly-seen items, touch still-present ones, close vanished ones.
 *  Returns THIS reconcile's churn (debt + item counts opened/closed) so callers can fire loop events
 *  only when the ledger actually changed (idempotent: a same-day re-run with no change returns zeros). */
function reconcileLedger(tenant: number | null, items: DebtItem[]): LedgerChurn {
  const xo = getDb("XORCISM");
  const d = today();
  const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
  const base: unknown[] = tenant != null ? [tenant] : [];
  const open = xo.prepare(`SELECT LedgerID, ItemKey, Debt FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NULL`).all(...base) as { LedgerID: number; ItemKey: string; Debt: number }[];
  const openByKey = new Map(open.map((r) => [r.ItemKey, r]));
  // CTEM-validated remediations are credited: drop them from the live set so they close (paid down)
  // and are not re-opened, even if a stale scan still reports the finding.
  const credited = ctemCreditedKeys(tenant);
  const effItems = credited.size ? items.filter((i) => !credited.has(i.key)) : items;
  const curKeys = new Set(effItems.map((i) => i.key));
  let nextId = (xo.prepare("SELECT COALESCE(MAX(LedgerID),0)+1 AS n FROM THREATDEBTLEDGER").get() as { n: number }).n;
  const ins = xo.prepare("INSERT INTO THREATDEBTLEDGER (LedgerID,TenantID,ItemKey,Source,Label,Debt,OpenedDate,LastSeenDate,ClosedDate) VALUES (?,?,?,?,?,?,?,?,NULL)");
  const touch = xo.prepare("UPDATE THREATDEBTLEDGER SET LastSeenDate=?, Debt=?, Label=? WHERE LedgerID=?");
  const close = xo.prepare("UPDATE THREATDEBTLEDGER SET ClosedDate=? WHERE LedgerID=?");
  let opened = 0, closed = 0, openedItems = 0, closedItems = 0;
  xo.transaction(() => {
    for (const it of effItems) {
      const r = openByKey.get(it.key);
      if (r) touch.run(d, it.debt, it.label, r.LedgerID);
      else { ins.run(nextId++, tenant, it.key, it.source, it.label, it.debt, d, d); opened += it.debt; openedItems++; }
    }
    for (const r of open) if (!curKeys.has(r.ItemKey)) { close.run(d, r.LedgerID); closed += r.Debt || 0; closedItems++; }
  })();
  return { opened: Math.round(opened), closed: Math.round(closed), openedItems, closedItems };
}

const SRC_LABEL: Record<string, string> = {
  vuln: "Vulnerabilities", network: "Network & segmentation", control: "Control weaknesses",
  identity: "Identity & access", ai: "AI & automation", misconfig: "Misconfigurations",
};

/** Pre-remediation modeling at SOURCE grain: open ledger debt retirable per source (price the fix
 *  beyond choke points). Sorted by debt retired desc. */
export function ledgerBySource(tenant: number | null): { source: string; label: string; items: number; debt: number }[] {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    const rows = xo.prepare(`SELECT Source AS source, COUNT(*) AS items, ROUND(COALESCE(SUM(Debt),0)) AS debt FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NULL GROUP BY Source ORDER BY debt DESC`).all(...a) as { source: string; items: number; debt: number }[];
    return rows.map((r) => ({ source: r.source, label: SRC_LABEL[r.source] || r.source, items: r.items, debt: r.debt }));
  } catch { return []; }
}

/** Pre-remediation modeling at ITEM grain: the highest-debt open ledger items (price the fix per
 *  individual finding). */
export function topLedgerItems(tenant: number | null): { source: string; label: string; debt: number }[] {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    return (xo.prepare(`SELECT Source AS source, Label AS label, ROUND(Debt) AS debt FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NULL ORDER BY Debt DESC LIMIT 12`).all(...a) as { source: string; label: string; debt: number }[])
      .map((r) => ({ source: r.source, label: r.label, debt: r.debt }));
  } catch { return []; }
}

/** The keys of the highest-debt open ledger items (the findings a paydown targets) — used to LINK a
 *  CTEM exposure to the specific debt it pays down, so CTEM remediation can later credit them. */
export function topOpenItemKeys(tenant: number | null, n = 5): string[] {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    return (xo.prepare(`SELECT ItemKey FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NULL ORDER BY Debt DESC LIMIT ?`).all(...a, n) as { ItemKey: string }[]).map((r) => r.ItemKey);
  } catch { return []; }
}

/** CTEM bridge — "pay down through CTEM": register an approved AOI paydown as a tracked CTEM exposure
 *  (classified CTEM-EXP-3, entered at the Prioritize stage) so it flows through the CTEM lifecycle and
 *  shows in /ctem. If `ledgerKeys` are given, the targeted ledger items are LINKED to the exposure so
 *  that reaching the Remediate stage later credits them (reverse re-credit). Returns the exposure id. */
export function mobilizeToCtem(tenant: number | null, p: { title: string; severity?: string; evidence?: string; ledgerKeys?: string[] }): { id: number } | null {
  try {
    const ex = createExposure({ ctemId: "CTEM-EXP-3", title: `AOI paydown: ${p.title}`.slice(0, 280), severity: p.severity || "High", source: "AOI paydown", stage: "Prioritize", evidence: p.evidence || "Generated from an approved Adversary Opportunity Index paydown action." }, tenant);
    if (p.ledgerKeys && p.ledgerKeys.length) {
      const xo = getDb("XORCISM");
      const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
      const ph = p.ledgerKeys.map(() => "?").join(",");
      const args = tenant != null ? [ex.id, ...p.ledgerKeys, tenant] : [ex.id, ...p.ledgerKeys];
      xo.prepare(`UPDATE THREATDEBTLEDGER SET CtemExposureID=? WHERE ItemKey IN (${ph}) AND ClosedDate IS NULL AND ${w}`).run(...args);
    }
    return ex;
  } catch { return null; }
}

/** The ledger ItemKeys credited by CTEM: items linked to an AOI-paydown CTEM exposure that has reached
 *  the Remediate stage. Reconcile treats these as remediated (closed + suppressed) even if a stale live
 *  scan still reports them — "credit the controls you can prove (via CTEM validation)". */
function ctemCreditedKeys(tenant: number | null): Set<string> {
  try {
    const exIds = (getDb("XVULNERABILITY").prepare("SELECT ExposureID FROM CTEMEXPOSURE WHERE Source='AOI paydown' AND (Stage='Remediate' OR Status LIKE 'Remediat%')").all() as { ExposureID: number }[]).map((r) => r.ExposureID);
    if (!exIds.length) return new Set();
    const xo = getDb("XORCISM");
    const ph = exIds.map(() => "?").join(",");
    const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
    const args = tenant != null ? [...exIds, tenant] : exIds;
    return new Set((xo.prepare(`SELECT DISTINCT ItemKey FROM THREATDEBTLEDGER WHERE CtemExposureID IN (${ph}) ${w}`).all(...args) as { ItemKey: string }[]).map((r) => r.ItemKey));
  } catch { return new Set(); }
}

/** The single highest-ROI paydown recommendation, for the loop-event summary + the orchestrator. */
function paydownReco(aoi: Aoi): string {
  const w = aoi.worklist[0];
  if (w) return `Top paydown: harden the choke point "${w.label}" (~ -${w.deltaEst} AOI, severs ${w.paths} path[s]).`;
  const src = aoi.bySource.filter((s) => s.items > 0).sort((a, b) => b.items - a.items)[0];
  if (src) return `Top paydown: reduce ${src.label.toLowerCase()} (${src.items} open).`;
  return "No dominant paydown — maintain.";
}

/** Read-only period FLOW from the ledger: debt opened (accrued) / closed (paid down) since a date,
 *  plus the current open balance. */
function ledgerFlow(tenant: number | null, sinceDate: string): LedgerFlow {
  try {
    const xo = getDb("XORCISM");
    const w = tenant != null ? "TenantID = ?" : "TenantID IS NULL";
    const a: unknown[] = tenant != null ? [tenant] : [];
    const accrued = (xo.prepare(`SELECT COALESCE(SUM(Debt),0) AS s FROM THREATDEBTLEDGER WHERE ${w} AND OpenedDate >= ?`).get(...a, sinceDate) as { s: number }).s;
    const paidDown = (xo.prepare(`SELECT COALESCE(SUM(Debt),0) AS s FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NOT NULL AND ClosedDate >= ?`).get(...a, sinceDate) as { s: number }).s;
    const o = xo.prepare(`SELECT COUNT(*) AS c, COALESCE(SUM(Debt),0) AS s FROM THREATDEBTLEDGER WHERE ${w} AND ClosedDate IS NULL`).get(...a) as { c: number; s: number };
    return { accrued: Math.round(accrued), paidDown: Math.round(paidDown), openItems: o.c, openDebt: Math.round(o.s) };
  } catch { return { accrued: 0, paidDown: 0, openItems: 0, openDebt: 0 }; }
}

/** Demo (tenant-scoped): back-date ~30 days of an improving (declining) AOI so the sparkline + FLOW
 *  render with a real trend. Idempotent; inserts history strictly before today (today stays live). */
export function seedThreatDebtDemo(tenant: number): { snapshots: number } {
  try {
    ensureThreatDebtTables();
    const xo = getDb("XORCISM");
    if ((xo.prepare("SELECT COUNT(*) AS n FROM THREATDEBTSNAPSHOT WHERE TenantID=? AND substr(CreatedDate,1,10) < ?").get(tenant, today()) as { n: number }).n > 0) return { snapshots: 0 };
    let nextId = (xo.prepare("SELECT COALESCE(MAX(SnapshotID),0)+1 AS n FROM THREATDEBTSNAPSHOT").get() as { n: number }).n;
    const ins = xo.prepare("INSERT INTO THREATDEBTSNAPSHOT (SnapshotID,TenantID,CreatedDate,AOI,RawDebt,Paths) VALUES (?,?,?,?,?,?)");
    let n = 0;
    for (let day = 31; day >= 1; day--) {
      const date = new Date(Date.now() - day * 86400000).toISOString().slice(0, 10);
      const t = (31 - day) / 30;                                  // 0 → 1 over the month
      const aoi = Math.max(0, Math.round(210 * Math.exp(-2.2 * t) + Math.sin(day) * 4)); // 210 → ~23, paid down
      ins.run(nextId++, tenant, date, aoi, aoi * 18, 3);
      n++;
    }
    return { snapshots: n };
  } catch { return { snapshots: 0 }; }
}
