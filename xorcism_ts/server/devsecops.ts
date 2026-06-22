/**
 * devsecops.ts — DevSecOps operations: run security in the SDLC/CI-CD pipeline as an operational
 * function. An inventory of applications/repos, the pipeline security scans across the standard scan
 * classes (SAST / DAST / SCA / Secrets / IaC / Container) with per-severity finding counts, the
 * security-gate policy (max allowed severity per class), and the derived posture — scan-type coverage,
 * gate-pass rate, open critical/high — plus a risk-ranked worklist. Reuses the AppSec connectors
 * (semgrep, gitleaks, trivy, burpwn, aikido, pyspector) as the scan tools. Surfaced at /devsecops.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { scaSeverityByAsset } from "./sca";

export const SCAN_TYPES = ["SAST", "DAST", "SCA", "Secrets", "IaC", "Container"] as const;
const DEFAULT_TOOL: Record<string, string> = { SAST: "semgrep", DAST: "burpwn", SCA: "trivy", Secrets: "gitleaks", IaC: "trivy", Container: "trivy" };
// the max severity a scan class may contain before the gate blocks the pipeline (secrets: none allowed)
const DEFAULT_GATE: Record<string, string> = { SAST: "High", DAST: "High", SCA: "High", Secrets: "None", IaC: "High", Container: "High" };
const SEV_RANK: Record<string, number> = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
function cols(t: string): Set<string> { try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } }
function nextId(t: string, pk: string): number { return (getDb("XORCISM").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${t}`).get() as { n: number }).n; }

/** Highest severity present in a scan's finding counts → rank. */
function scanMaxRank(s: { Critical?: unknown; High?: unknown; Medium?: unknown; Low?: unknown }): number {
  if (num(s.Critical) > 0) return 4; if (num(s.High) > 0) return 3; if (num(s.Medium) > 0) return 2; if (num(s.Low) > 0) return 1; return 0;
}

interface Gate { appId: number | null; scanType: string; maxSeverity: string; blockOnFail: boolean; enabled: boolean }
function loadGates(tenant: number | null): Gate[] {
  const xo = getDb("XORCISM");
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = xo.prepare(`SELECT AppID, ScanType, MaxSeverity, BlockOnFail, Enabled FROM DEVSECOPSGATE ${tw}`).all(...(tenant != null ? [tenant] : [])) as any[];
  return rows.map((g) => ({ appId: g.AppID != null ? Number(g.AppID) : null, scanType: String(g.ScanType), maxSeverity: String(g.MaxSeverity || "High"), blockOnFail: num(g.BlockOnFail) === 1, enabled: num(g.Enabled) === 1 }));
}
/** Resolve the applicable gate for an app + scan type (app-specific overrides global). */
function gateFor(gates: Gate[], appId: number, scanType: string): Gate | null {
  return gates.find((g) => g.appId === appId && g.scanType === scanType) || gates.find((g) => g.appId == null && g.scanType === scanType) || null;
}

/** Mean time-to-remediate over the scan history: for each (app, scan class) series, a "dirty streak"
 *  (a scan carrying critical/high findings) that later clears (a scan with none) is one remediation;
 *  MTTR = mean of those intervals (days). Streaks still open contribute to the open backlog age. */
function computeMttr(scans: any[]): { mttrDays: number | null; resolved: number; openStreaks: number; oldestOpenDays: number | null } {
  const byKey = new Map<string, any[]>();
  for (const s of scans) { const k = `${s.AppID}|${s.ScanType}`; (byKey.get(k) ?? byKey.set(k, []).get(k)!).push(s); }
  const intervals: number[] = []; let resolved = 0, openStreaks = 0; let oldestOpen: number | null = null; const now = Date.now();
  for (const series of byKey.values()) {
    const asc = [...series].sort((a, b) => (Date.parse(String(a.RanAt || a.CreatedDate || "")) || 0) - (Date.parse(String(b.RanAt || b.CreatedDate || "")) || 0));
    let streakStart: number | null = null;
    for (const s of asc) {
      const t = Date.parse(String(s.RanAt || s.CreatedDate || "")); if (!Number.isFinite(t)) continue;
      const dirty = num(s.Critical) + num(s.High) > 0;
      if (dirty) { if (streakStart == null) streakStart = t; }
      else if (streakStart != null) { intervals.push((t - streakStart) / 86400000); resolved++; streakStart = null; }
    }
    if (streakStart != null) { openStreaks++; const age = (now - streakStart) / 86400000; if (oldestOpen == null || age > oldestOpen) oldestOpen = age; }
  }
  return {
    mttrDays: intervals.length ? Math.round((intervals.reduce((a, b) => a + b, 0) / intervals.length) * 10) / 10 : null,
    resolved, openStreaks, oldestOpenDays: oldestOpen != null ? Math.round(oldestOpen) : null,
  };
}

/** The /devsecops cockpit: applications with their pipeline-scan coverage matrix + gate posture,
 *  recent scans, gates, a risk-ranked worklist and the program summary. */
export function devsecopsDashboard(tenant: number | null): any {
  const xo = getDb("XORCISM");
  if (!cols("DEVSECOPSAPP").size) return empty();
  // include NULL-tenant rows so connector-recorded apps/scans (tenant-agnostic, like import_findings) appear
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const appRows = xo.prepare(`SELECT * FROM DEVSECOPSAPP ${tw} ORDER BY AppID DESC`).all(...(tenant != null ? [tenant] : [])) as any[];
  const persons = new Map<number, string>();
  try { for (const p of xo.prepare("SELECT PersonID, FullName FROM PERSON").all() as any[]) persons.set(Number(p.PersonID), String(p.FullName || `#${p.PersonID}`)); } catch { /* */ }
  const gates = loadGates(tenant);

  // SCA class straight from the SBOM data (/sca): per-asset severity counts + app→asset resolution
  const scaByAsset = scaSeverityByAsset(tenant);
  const assetIdByName = new Map<string, number>();
  try { for (const a of xo.prepare("SELECT AssetID, AssetName FROM ASSET").all() as any[]) if (a.AssetName) assetIdByName.set(String(a.AssetName).toLowerCase(), Number(a.AssetID)); } catch { /* */ }
  const asvsByApp = asvsByAppMap(tenant); // OWASP ASVS verification coverage per app

  // latest scan per (app, scanType)
  const allScans = xo.prepare(`SELECT * FROM DEVSECOPSSCAN ${tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : ""} ORDER BY datetime(COALESCE(RanAt, CreatedDate)) DESC`).all(...(tenant != null ? [tenant] : [])) as any[];
  const latest = new Map<string, any>(); // appId|type → scan
  for (const s of allScans) { const k = `${s.AppID}|${s.ScanType}`; if (!latest.has(k)) latest.set(k, s); }

  const now = Date.now();
  const apps = appRows.map((a) => {
    const appId = Number(a.AppID);
    // resolve the app's asset (explicit link, else by name) → its live SBOM-derived SCA findings
    const appAssetId = a.AssetID != null ? Number(a.AssetID) : (assetIdByName.get(String(a.Name || "").toLowerCase()) ?? null);
    const sbom = appAssetId != null ? scaByAsset.get(appAssetId) : undefined;
    const matrix = SCAN_TYPES.map((t) => {
      // SCA class comes straight from the SBOM (/sca) when the app's asset has one (preferred over manual scans)
      if (t === "SCA" && sbom) {
        const g = gateFor(gates, appId, t);
        const pseudo = { Critical: sbom.critical, High: sbom.high, Medium: sbom.medium, Low: sbom.low };
        const passed = g && g.enabled ? scanMaxRank(pseudo) <= (SEV_RANK[g.maxSeverity] ?? 3) : null;
        return { type: t, status: passed === false ? "fail" : passed === true ? "pass" : "ran", tool: `SBOM · ${sbom.components} comp${sbom.sboms ? ` · ${sbom.sboms} SBOM` : ""}`, critical: sbom.critical, high: sbom.high, ranAt: null, gate: g ? g.maxSeverity : null, blocking: !!(g && g.blockOnFail), source: "sbom" };
      }
      const s = latest.get(`${appId}|${t}`);
      if (!s) return { type: t, status: "none", tool: DEFAULT_TOOL[t], critical: 0, high: 0, ranAt: null, gate: null };
      const g = gateFor(gates, appId, t);
      const passed = g && g.enabled ? scanMaxRank(s) <= (SEV_RANK[g.maxSeverity] ?? 3) : null;
      return { type: t, status: passed === false ? "fail" : passed === true ? "pass" : "ran", tool: String(s.Tool || DEFAULT_TOOL[t]), critical: num(s.Critical), high: num(s.High), ranAt: s.RanAt || s.CreatedDate || null, gate: g ? g.maxSeverity : null, blocking: !!(g && g.blockOnFail) };
    });
    const covered = matrix.filter((m) => m.status !== "none");
    const evaluated = matrix.filter((m) => m.status === "pass" || m.status === "fail");
    const passedGates = evaluated.filter((m) => m.status === "pass").length;
    const blockedFail = covered.some((m) => m.status === "fail" && m.blocking);
    const openCritical = covered.reduce((s, m) => s + m.critical, 0);
    const openHigh = covered.reduce((s, m) => s + m.high, 0);
    const gateStatus = evaluated.length === 0 ? "none" : passedGates === evaluated.length ? "pass" : "fail";
    const score = Math.round((covered.length / SCAN_TYPES.length) * 50 + (evaluated.length ? passedGates / evaluated.length : 0) * 30 + (openCritical === 0 ? (openHigh === 0 ? 20 : 10) : 0));
    return {
      id: appId, name: String(a.Name || `App #${appId}`), repo: a.Repo || null, language: a.Language || null,
      team: a.Team || null, owner: a.OwnerPersonID != null ? (persons.get(Number(a.OwnerPersonID)) || `#${a.OwnerPersonID}`) : null,
      criticality: String(a.Criticality || "Medium"), pipelineUrl: a.PipelineUrl || null,
      coverage: covered.length, coveragePct: Math.round((covered.length / SCAN_TYPES.length) * 100),
      matrix, gateStatus, blockedFail, openCritical, openHigh, score, asvs: asvsByApp.get(appId) || null,
    };
  });

  // worklist: blocking gate failures + open criticals, risk-ranked
  const worklist: any[] = [];
  for (const a of apps) for (const m of a.matrix) {
    if ((m.status === "fail" && m.blocking) || m.critical > 0) {
      worklist.push({ app: a.name, appId: a.id, criticality: a.criticality, scanType: m.type, tool: m.tool, critical: m.critical, high: m.high, status: m.status, gate: m.gate, ranAt: m.ranAt,
        score: (m.status === "fail" && m.blocking ? 100 : 0) + m.critical * 25 + m.high * 8 + ({ Critical: 30, High: 20, Medium: 10, Low: 0 } as any)[a.criticality === "Critical" ? "Critical" : a.criticality === "High" ? "High" : "Medium"] });
    }
  }
  worklist.sort((x, y) => y.score - x.score);

  const scans = allScans.slice(0, 40).map((s) => ({ id: Number(s.ScanID), appId: Number(s.AppID), app: apps.find((a) => a.id === Number(s.AppID))?.name || `#${s.AppID}`, scanType: String(s.ScanType), tool: String(s.Tool || ""), status: String(s.Status || ""), critical: num(s.Critical), high: num(s.High), medium: num(s.Medium), low: num(s.Low), gatePassed: s.GatePassed == null ? null : num(s.GatePassed) === 1, ranAt: s.RanAt || s.CreatedDate || null }));

  const byType = SCAN_TYPES.map((t) => ({ type: t, apps: apps.filter((a) => a.matrix.find((m) => m.type === t && m.status !== "none")).length, fails: apps.filter((a) => a.matrix.find((m) => m.type === t && m.status === "fail")).length }));
  const evaluatedApps = apps.filter((a) => a.gateStatus !== "none");
  const scans30 = allScans.filter((s) => { const t = Date.parse(String(s.RanAt || s.CreatedDate || "")); return Number.isFinite(t) && now - t <= 30 * 86400000; }).length;
  const mttr = computeMttr(allScans);

  return {
    apps, worklist: worklist.slice(0, 60), scans, gates: gates.map((g) => ({ ...g, scope: g.appId == null ? "global" : (apps.find((a) => a.id === g.appId)?.name || `#${g.appId}`) })), byType, scanTypes: SCAN_TYPES,
    summary: {
      apps: apps.length,
      avgCoverage: apps.length ? Math.round(apps.reduce((s, a) => s + a.coveragePct, 0) / apps.length) : 0,
      fullyCovered: apps.filter((a) => a.coverage === SCAN_TYPES.length).length,
      gatePassRate: evaluatedApps.length ? Math.round((evaluatedApps.filter((a) => a.gateStatus === "pass").length / evaluatedApps.length) * 100) : null,
      blockedApps: apps.filter((a) => a.blockedFail).length,
      openCritical: apps.reduce((s, a) => s + a.openCritical, 0), openHigh: apps.reduce((s, a) => s + a.openHigh, 0),
      scansLast30d: scans30,
      mttrDays: mttr.mttrDays, remediated: mttr.resolved, openStreaks: mttr.openStreaks, oldestOpenDays: mttr.oldestOpenDays,
      asvsApps: apps.filter((a) => a.asvs).length,
      asvsAvgCoverage: (() => { const v = apps.filter((a) => a.asvs); return v.length ? Math.round(v.reduce((s, a) => s + (a.asvs!.pct || 0), 0) / v.length) : null; })(),
      asvsFailed: apps.reduce((s, a) => s + (a.asvs ? a.asvs.failed : 0), 0),
    },
    generatedAt: new Date().toISOString(),
  };
}
const empty = () => ({ apps: [], worklist: [], scans: [], gates: [], byType: [], scanTypes: SCAN_TYPES, summary: { apps: 0, avgCoverage: 0, fullyCovered: 0, gatePassRate: null, blockedApps: 0, openCritical: 0, openHigh: 0, scansLast30d: 0, mttrDays: null, remediated: 0, openStreaks: 0, oldestOpenDays: null, asvsApps: 0, asvsAvgCoverage: null, asvsFailed: 0 }, generatedAt: new Date().toISOString() });

// ── mutations ────────────────────────────────────────────────────────────────────
export function createApp(p: { name: string; repo?: string; language?: string; team?: string; criticality?: string; pipelineUrl?: string; defaultBranch?: string; ownerPersonId?: number }, tenant: number | null): { id: number } {
  const xo = getDb("XORCISM"); const id = nextId("DEVSECOPSAPP", "AppID"); const now = new Date().toISOString();
  xo.prepare("INSERT INTO DEVSECOPSAPP (AppID, AppGUID, Name, Repo, Language, Team, OwnerPersonID, Criticality, PipelineUrl, DefaultBranch, Status, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.name.slice(0, 200), p.repo ?? null, p.language ?? null, p.team ?? null, p.ownerPersonId ?? null, p.criticality || "Medium", p.pipelineUrl ?? null, p.defaultBranch || "main", "Active", tenant, now);
  return { id };
}

export function recordScan(p: { appId: number; scanType: string; tool?: string; critical?: number; high?: number; medium?: number; low?: number; branch?: string; url?: string; status?: string }, tenant: number | null): { id: number; gatePassed: boolean | null } {
  const xo = getDb("XORCISM"); const id = nextId("DEVSECOPSSCAN", "ScanID"); const now = new Date().toISOString();
  const c = Math.max(0, Math.round(num(p.critical))), h = Math.max(0, Math.round(num(p.high))), m = Math.max(0, Math.round(num(p.medium))), l = Math.max(0, Math.round(num(p.low)));
  const findings = c + h + m + l;
  const g = gateFor(loadGates(tenant), Number(p.appId), p.scanType);
  const maxRank = c > 0 ? 4 : h > 0 ? 3 : m > 0 ? 2 : l > 0 ? 1 : 0;
  const gatePassed = g && g.enabled ? maxRank <= (SEV_RANK[g.maxSeverity] ?? 3) : null;
  const status = p.status || (gatePassed === false ? "fail" : "pass");
  xo.prepare("INSERT INTO DEVSECOPSSCAN (ScanID, ScanGUID, AppID, ScanType, Tool, Status, Critical, High, Medium, Low, Findings, GatePassed, Branch, Ref, Url, RanAt, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), Number(p.appId), p.scanType, p.tool || DEFAULT_TOOL[p.scanType] || "manual", status, c, h, m, l, findings, gatePassed == null ? null : (gatePassed ? 1 : 0), p.branch || "main", null, p.url ?? null, now, "manual", tenant, now);
  return { id, gatePassed };
}

export function setGate(p: { appId?: number | null; scanType: string; maxSeverity: string; blockOnFail?: boolean; enabled?: boolean }, tenant: number | null): { ok: boolean } {
  const xo = getDb("XORCISM"); const now = new Date().toISOString(); const appId = p.appId ?? null;
  const ex = xo.prepare("SELECT GateID FROM DEVSECOPSGATE WHERE IFNULL(AppID,-1)=IFNULL(?,-1) AND ScanType=? AND IFNULL(TenantID,-1)=IFNULL(?,-1)").get(appId, p.scanType, tenant) as { GateID: number } | undefined;
  if (ex) xo.prepare("UPDATE DEVSECOPSGATE SET MaxSeverity=?, BlockOnFail=?, Enabled=? WHERE GateID=?").run(p.maxSeverity, p.blockOnFail === false ? 0 : 1, p.enabled === false ? 0 : 1, ex.GateID);
  else { const id = nextId("DEVSECOPSGATE", "GateID"); xo.prepare("INSERT INTO DEVSECOPSGATE (GateID, AppID, ScanType, MaxSeverity, BlockOnFail, Enabled, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?)").run(id, appId, p.scanType, p.maxSeverity, p.blockOnFail === false ? 0 : 1, p.enabled === false ? 0 : 1, tenant, now); }
  return { ok: true };
}

// ── OWASP ASVS verification (per app) ────────────────────────────────────────────────
const ASVS_VOCAB = "OWASP ASVS 4.0.3";
const ASVS_STATUSES = ["Not tested", "Verified", "Failed", "N/A"];
export interface AsvsReq { shortcode: string; name: string; chapter: string; level: number; statement: string }

function shortcodeNum(sc: string): number { const m = /V(\d+)\.(\d+)\.(\d+)/.exec(sc); return m ? Number(m[1]) * 1e6 + Number(m[2]) * 1e3 + Number(m[3]) : 0; }

/** The ASVS requirement catalogue read from XORCISM.CONTROL (imported by import_asvs.py). */
export function asvsCatalogue(): AsvsReq[] {
  try {
    const xo = getDb("XORCISM");
    const v = xo.prepare("SELECT VocabularyID FROM VOCABULARY WHERE VocabularyName = ?").get(ASVS_VOCAB) as { VocabularyID: number } | undefined;
    if (!v) return [];
    return (xo.prepare("SELECT ControlName name, ControlDescription descr, Statement statement, CIS cis FROM CONTROL WHERE VocabularyID = ?").all(v.VocabularyID) as any[]).map((r) => {
      const name = String(r.name || ""); const descr = String(r.descr || "");
      const shortcode = (/^(V\d+\.\d+\.\d+)/.exec(name)?.[1]) || String(r.cis || "");
      const lvl = /·\s*L(\d)/.exec(descr); const ch = /OWASP ASVS\s*—\s*(.+?)\s*·/.exec(descr);
      return { shortcode, name, statement: String(r.statement || ""), chapter: ch ? ch[1].trim() : "", level: lvl ? Number(lvl[1]) : 1 };
    }).filter((r) => r.shortcode).sort((a, b) => shortcodeNum(a.shortcode) - shortcodeNum(b.shortcode));
  } catch { return []; }
}

function asvsStatuses(appId: number): Map<string, string> {
  const m = new Map<string, string>();
  try { for (const r of getDb("XORCISM").prepare("SELECT Shortcode, Status FROM DEVSECOPSASVS WHERE AppID = ?").all(appId) as any[]) m.set(String(r.Shortcode), String(r.Status)); } catch { /* */ }
  return m;
}
/** Verification coverage for an app at its target level: verified / (applicable − N/A). */
function asvsCoverage(cat: AsvsReq[], statuses: Map<string, string>, level: number): { applicable: number; inScope: number; verified: number; failed: number; na: number; pct: number } {
  const applicableReqs = cat.filter((r) => !level || r.level <= level);
  let verified = 0, failed = 0, na = 0;
  for (const r of applicableReqs) { const s = statuses.get(r.shortcode) || "Not tested"; if (s === "Verified") verified++; else if (s === "Failed") failed++; else if (/n\/?a/i.test(s)) na++; }
  const inScope = applicableReqs.length - na;
  return { applicable: applicableReqs.length, inScope, verified, failed, na, pct: inScope ? Math.round((verified / inScope) * 100) : 0 };
}

/** Per-app ASVS verification view: target level + every applicable requirement with its status + coverage. */
export function appAsvs(appId: number, tenant: number | null): any {
  const xo = getDb("XORCISM");
  const tg = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const app = xo.prepare(`SELECT Name, AsvsLevel FROM DEVSECOPSAPP WHERE AppID = ? ${tg}`).get(...(tenant != null ? [appId, tenant] : [appId])) as any;
  if (!app) return null;
  const level = app.AsvsLevel ? Number(app.AsvsLevel) : 0;
  const cat = asvsCatalogue(); const statuses = asvsStatuses(appId);
  const requirements = cat.filter((r) => !level || r.level <= level).map((r) => ({ ...r, status: statuses.get(r.shortcode) || "Not tested" }));
  // per-chapter coverage rollup
  const chMap = new Map<string, { chapter: string; applicable: number; verified: number; failed: number; na: number }>();
  for (const r of requirements) {
    let e = chMap.get(r.chapter); if (!e) { e = { chapter: r.chapter, applicable: 0, verified: 0, failed: 0, na: 0 }; chMap.set(r.chapter, e); }
    e.applicable++; if (r.status === "Verified") e.verified++; else if (r.status === "Failed") e.failed++; else if (/n\/?a/i.test(r.status)) e.na++;
  }
  const byChapter = [...chMap.values()].map((e) => ({ chapter: e.chapter, applicable: e.applicable, verified: e.verified, failed: e.failed, pct: e.applicable - e.na ? Math.round((e.verified / (e.applicable - e.na)) * 100) : 0 }));
  return { appId, app: String(app.Name), targetLevel: level, statuses: ASVS_STATUSES, requirements, byChapter, coverage: asvsCoverage(cat, statuses, level), catalogueSize: cat.length };
}

export function setAsvsLevel(appId: number, level: number, tenant: number | null): boolean {
  const tg = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const r = getDb("XORCISM").prepare(`UPDATE DEVSECOPSAPP SET AsvsLevel = ? WHERE AppID = ? ${tg}`).run(...(tenant != null ? [level || null, appId, tenant] : [level || null, appId]));
  return r.changes > 0;
}
export function setAsvsStatus(appId: number, shortcode: string, status: string, tenant: number | null): boolean {
  const xo = getDb("XORCISM"); const now = new Date().toISOString();
  const ex = xo.prepare("SELECT DevsecopsAsvsID FROM DEVSECOPSASVS WHERE AppID = ? AND Shortcode = ?").get(appId, shortcode) as { DevsecopsAsvsID: number } | undefined;
  if (ex) xo.prepare("UPDATE DEVSECOPSASVS SET Status = ?, VerifiedDate = ? WHERE DevsecopsAsvsID = ?").run(status, status === "Verified" ? now : null, ex.DevsecopsAsvsID);
  else xo.prepare("INSERT INTO DEVSECOPSASVS (DevsecopsAsvsID, AppID, Shortcode, Status, VerifiedDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?)").run(nextId("DEVSECOPSASVS", "DevsecopsAsvsID"), appId, shortcode, status, status === "Verified" ? now : null, tenant, now);
  return true;
}

/** Per-app ASVS summary (level + coverage) for the dashboard — precomputed once. */
function asvsByAppMap(tenant: number | null): Map<number, { level: number; verified: number; applicable: number; failed: number; pct: number }> {
  const out = new Map<number, { level: number; verified: number; applicable: number; failed: number; pct: number }>();
  try {
    const xo = getDb("XORCISM"); const cat = asvsCatalogue(); if (!cat.length) return out;
    const tg = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
    const apps = xo.prepare(`SELECT AppID, AsvsLevel FROM DEVSECOPSAPP ${tg}`).all(...(tenant != null ? [tenant] : [])) as any[];
    const byApp = new Map<number, Map<string, string>>();
    for (const r of xo.prepare("SELECT AppID, Shortcode, Status FROM DEVSECOPSASVS").all() as any[]) { const a = Number(r.AppID); let m = byApp.get(a); if (!m) { m = new Map(); byApp.set(a, m); } m.set(String(r.Shortcode), String(r.Status)); }
    for (const a of apps) { const lvl = a.AsvsLevel ? Number(a.AsvsLevel) : 0; if (!lvl && !byApp.has(Number(a.AppID))) continue; const c = asvsCoverage(cat, byApp.get(Number(a.AppID)) || new Map(), lvl); out.set(Number(a.AppID), { level: lvl, verified: c.verified, applicable: c.applicable, failed: c.failed, pct: c.pct }); }
  } catch { /* */ }
  return out;
}

/** Seed default global gates + a small demo app portfolio with scans. */
export function seedDevSecOps(tenant: number): { apps: number; scans: number; gates: number } {
  const xo = getDb("XORCISM");
  let gates = 0;
  if (!(xo.prepare("SELECT COUNT(*) n FROM DEVSECOPSGATE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) {
    for (const t of SCAN_TYPES) { setGate({ appId: null, scanType: t, maxSeverity: DEFAULT_GATE[t], blockOnFail: true, enabled: true }, tenant); gates++; }
  }
  if ((xo.prepare("SELECT COUNT(*) n FROM DEVSECOPSAPP WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { apps: 0, scans: 0, gates };
  const owner = (xo.prepare("SELECT PersonID FROM PERSON LIMIT 1").get() as { PersonID: number } | undefined)?.PersonID ?? null;
  const demo: { name: string; repo: string; lang: string; team: string; crit: string; scans: [string, number, number, number, number][] }[] = [
    { name: "payments-api", repo: "github.com/acme/payments-api", lang: "Go", team: "Payments", crit: "Critical", scans: [["SAST", 1, 4, 9, 12], ["SCA", 0, 3, 7, 5], ["Secrets", 1, 0, 0, 0], ["Container", 0, 2, 6, 10], ["DAST", 0, 1, 3, 4]] },
    { name: "web-frontend", repo: "github.com/acme/web-frontend", lang: "TypeScript", team: "Web", crit: "High", scans: [["SAST", 0, 2, 8, 20], ["SCA", 0, 5, 12, 18], ["Secrets", 0, 0, 0, 0], ["DAST", 0, 0, 2, 5]] },
    { name: "auth-service", repo: "github.com/acme/auth-service", lang: "Java", team: "Identity", crit: "Critical", scans: [["SAST", 0, 0, 3, 7], ["SCA", 0, 1, 4, 6], ["Secrets", 0, 0, 0, 0], ["IaC", 0, 1, 2, 3], ["Container", 0, 0, 1, 4], ["DAST", 0, 0, 1, 2]] },
    { name: "data-pipeline", repo: "github.com/acme/data-pipeline", lang: "Python", team: "Data", crit: "Medium", scans: [["SAST", 0, 1, 5, 9], ["SCA", 1, 2, 8, 11], ["IaC", 0, 3, 4, 2]] },
    { name: "legacy-portal", repo: "github.com/acme/legacy-portal", lang: "PHP", team: "Web", crit: "High", scans: [["SAST", 2, 6, 14, 22]] },
  ];
  let apps = 0, scans = 0;
  for (const d of demo) {
    const { id } = createApp({ name: d.name, repo: d.repo, language: d.lang, team: d.team, criticality: d.crit, pipelineUrl: `https://ci.acme.dev/${d.name}`, ownerPersonId: owner ?? undefined }, tenant);
    apps++;
    for (const [type, c, h, m, l] of d.scans) { recordScan({ appId: id, scanType: type as string, critical: c as number, high: h as number, medium: m as number, low: l as number }, tenant); scans++; }
  }
  return { apps, scans, gates };
}

/** Seed a demo ASVS verification: pick an app, target L2, verify most applicable reqs, fail one. Idempotent. */
export function seedDevSecOpsAsvs(tenant: number): { app: string; verified: number; failed: number; level: number } | null {
  const xo = getDb("XORCISM");
  if ((xo.prepare("SELECT COUNT(*) n FROM DEVSECOPSASVS WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return null;
  const app = (xo.prepare("SELECT AppID, Name FROM DEVSECOPSAPP WHERE (TenantID = ? OR TenantID IS NULL) AND Name = 'auth-service' LIMIT 1").get(tenant) as any)
    || (xo.prepare("SELECT AppID, Name FROM DEVSECOPSAPP WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY AppID LIMIT 1").get(tenant) as any);
  if (!app) return null;
  const level = 2;
  setAsvsLevel(Number(app.AppID), level, tenant);
  const cat = asvsCatalogue().filter((r) => r.level <= level);
  let verified = 0, failed = 0;
  cat.forEach((r, i) => {
    const status = i === 2 ? "Failed" : (i % 7 === 6 ? "Not tested" : "Verified"); // ~verify most, 1 fail, a few untested
    setAsvsStatus(Number(app.AppID), r.shortcode, status, tenant);
    if (status === "Verified") verified++; else if (status === "Failed") failed++;
  });
  return { app: String(app.Name), verified, failed, level };
}
