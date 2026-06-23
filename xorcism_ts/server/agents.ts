/**
 * agents.ts — "XOR" endpoint agent store (enhanced EDR).
 * XAGENT.db database:
 *   XAGENT       — enrolled endpoints (token, OS, last contact, linked asset)
 *   XAGENTEVENT  — reported events (AV detection, hunting hit, EDR, compliance)
 *   XAGENTJOB    — commands sent to the agent ("run a scan" from ASSET)
 *   XIOC         — indicators of compromise (fed by CTI: XTHREAT, OTX/AlienVault
 *                  connectors, feeds, STIX/TAXII) served to the agents
 */
import Database from "better-sqlite3";
import path from "path";
import crypto from "crypto";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const nowSql = () => new Date().toISOString().replace("T", " ").slice(0, 19);

let db: Database.Database | null = null;
export function getAgentDb(): Database.Database {
  if (db) return db;
  db = new Database(path.join(DB_DIR, "XAGENT.db"));
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.exec(`
    CREATE TABLE IF NOT EXISTS XAGENT(
      AgentID INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, asset_name TEXT,
      os TEXT, platform TEXT, version TEXT, ip TEXT, fqdn TEXT,
      status TEXT DEFAULT 'enrolled', enrolled_at TEXT, last_seen TEXT, intel_seen INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS XAGENTEVENT(
      EventID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT, type TEXT, severity TEXT, title TEXT, detail TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS XAGENTJOB(
      AgentJobID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, kind TEXT NOT NULL, params TEXT,
      status TEXT DEFAULT 'pending', created_at TEXT, started_at TEXT, finished_at TEXT,
      result_summary TEXT, created_by INTEGER);
    CREATE TABLE IF NOT EXISTS XIOC(
      IOCID INTEGER PRIMARY KEY AUTOINCREMENT,
      ioc_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT, threat TEXT,
      created_at TEXT, UNIQUE(ioc_type, value));
    CREATE TABLE IF NOT EXISTS FORENSICTRIAGE(
      TriageID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT, asset_name TEXT, host_os TEXT, collected_at TEXT,
      summary TEXT, artifacts TEXT, flag_count INTEGER DEFAULT 0, created_at TEXT);
    CREATE TABLE IF NOT EXISTS HONEYPOTHIT(
      HitID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, src_ip TEXT, src_port INTEGER, dst_port INTEGER,
      service TEXT, banner TEXT, hit_at TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS MEMORYDUMP(
      DumpID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, asset_name TEXT, host_os TEXT, tool TEXT, status TEXT,
      path TEXT, size_bytes INTEGER, sha256 TEXT, ram_total_bytes INTEGER,
      started_at TEXT, finished_at TEXT, duration_sec INTEGER, error TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS LOGHUNT(
      LogHuntID INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL, asset_name TEXT, host_os TEXT, source TEXT, event_count INTEGER,
      severity TEXT, summary TEXT, findings TEXT, techniques TEXT, model TEXT, ai_used INTEGER DEFAULT 0,
      hunt_id INTEGER, created_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_agentevent_agent ON XAGENTEVENT(agent);
    CREATE INDEX IF NOT EXISTS ix_agentjob_agent ON XAGENTJOB(agent, status);
    CREATE INDEX IF NOT EXISTS ix_forensictriage_agent ON FORENSICTRIAGE(agent);
    CREATE INDEX IF NOT EXISTS ix_honeypothit_agent ON HONEYPOTHIT(agent, HitID);
    CREATE INDEX IF NOT EXISTS ix_memorydump_agent ON MEMORYDUMP(agent, DumpID);
    CREATE INDEX IF NOT EXISTS ix_loghunt_agent ON LOGHUNT(agent, LogHuntID);
  `);
  return db;
}

export interface Agent {
  AgentID: number; name: string; asset_name: string | null; os: string | null;
  platform: string | null; version: string | null; ip: string | null; fqdn: string | null;
  status: string; enrolled_at: string | null; last_seen: string | null;
}

/** Enrols (or re-enrols) an endpoint and returns a token (shown to the agent once). */
export function enrollAgent(name: string, info: Record<string, string>): { token: string; agentId: number } {
  const d = getAgentDb();
  const token = crypto.randomBytes(24).toString("hex");
  const existing = d.prepare("SELECT AgentID FROM XAGENT WHERE name=?").get(name) as { AgentID: number } | undefined;
  if (existing) {
    d.prepare(`UPDATE XAGENT SET token_hash=?, os=?, platform=?, version=?, ip=?, fqdn=?, asset_name=?,
               status='enrolled', last_seen=? WHERE AgentID=?`)
      .run(sha256(token), info.os ?? null, info.platform ?? null, info.version ?? null,
           info.ip ?? null, info.fqdn ?? null, name, nowSql(), existing.AgentID);
    return { token, agentId: existing.AgentID };
  }
  const r = d.prepare(`INSERT INTO XAGENT(name, token_hash, asset_name, os, platform, version, ip, fqdn, enrolled_at, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(name, sha256(token), name, info.os ?? null, info.platform ?? null, info.version ?? null,
         info.ip ?? null, info.fqdn ?? null, nowSql(), nowSql());
  return { token, agentId: Number(r.lastInsertRowid) };
}

export function agentByToken(token: string): Agent | undefined {
  return getAgentDb().prepare("SELECT * FROM XAGENT WHERE token_hash=?").get(sha256(token)) as Agent | undefined;
}
export function touchAgent(name: string): void {
  getAgentDb().prepare("UPDATE XAGENT SET last_seen=?, status='online' WHERE name=?").run(nowSql(), name);
}
export function listAgents(): Agent[] {
  return getAgentDb().prepare("SELECT AgentID,name,asset_name,os,platform,version,ip,fqdn,status,enrolled_at,last_seen FROM XAGENT ORDER BY name").all() as Agent[];
}

export function addAgentEvent(agent: string, ev: { type: string; severity?: string; title?: string; detail?: unknown }): void {
  getAgentDb().prepare("INSERT INTO XAGENTEVENT(agent,type,severity,title,detail,created_at) VALUES (?,?,?,?,?,?)")
    .run(agent, ev.type, ev.severity ?? "info", ev.title ?? "", JSON.stringify(ev.detail ?? null), nowSql());
}
export function listAgentEvents(limit = 100, agent?: string): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM XAGENTEVENT WHERE agent=? ORDER BY EventID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM XAGENTEVENT ORDER BY EventID DESC LIMIT ?").all(limit);
}

export interface ForensicBundle {
  os?: string; collectedAt?: string;
  summary?: Record<string, unknown>; flags?: { category: string; detail: string; severity?: string }[];
  artifacts?: Record<string, unknown>;
}
/** Persist a forensic-triage bundle posted by the agent (live DFIR snapshot). The full
 *  artifacts blob + a counts/flags summary are stored in FORENSICTRIAGE; the caller also
 *  emits a forensic_triage agent event so it surfaces in the events feed. */
export function storeForensicTriage(agent: string, asset: string | null, bundle: ForensicBundle): { triageId: number; flags: number } {
  const d = getAgentDb();
  const flags = Array.isArray(bundle.flags) ? bundle.flags : [];
  const r = d.prepare(
    "INSERT INTO FORENSICTRIAGE(agent,asset_name,host_os,collected_at,summary,artifacts,flag_count,created_at) VALUES (?,?,?,?,?,?,?,?)",
  ).run(agent, asset, bundle.os ?? null, bundle.collectedAt ?? nowSql(),
    JSON.stringify(bundle.summary ?? {}), JSON.stringify(bundle.artifacts ?? {}), flags.length, nowSql());
  return { triageId: Number(r.lastInsertRowid), flags: flags.length };
}
export function listForensicTriage(limit = 50, agent?: string): unknown[] {
  const d = getAgentDb();
  const sel = "TriageID,agent,asset_name,host_os,collected_at,summary,flag_count,created_at"; // omit the big artifacts blob in lists
  return agent
    ? d.prepare(`SELECT ${sel} FROM FORENSICTRIAGE WHERE agent=? ORDER BY TriageID DESC LIMIT ?`).all(agent, limit)
    : d.prepare(`SELECT ${sel} FROM FORENSICTRIAGE ORDER BY TriageID DESC LIMIT ?`).all(limit);
}
export function getForensicTriage(id: number): unknown {
  return getAgentDb().prepare("SELECT * FROM FORENSICTRIAGE WHERE TriageID=?").get(id);
}

/** "Run a scan" command for an agent (from the ASSET window). */
export function createAgentJob(agent: string, kind: string, params: unknown, userId: number | null): number {
  const r = getAgentDb().prepare("INSERT INTO XAGENTJOB(agent,kind,params,created_at,created_by) VALUES (?,?,?,?,?)")
    .run(agent, kind, JSON.stringify(params ?? {}), nowSql(), userId);
  return Number(r.lastInsertRowid);
}
/** Pending jobs for an agent → moved to 'sent'. */
export function claimAgentJobs(agent: string): { AgentJobID: number; kind: string; params: string }[] {
  const d = getAgentDb();
  const rows = d.prepare("SELECT AgentJobID,kind,params FROM XAGENTJOB WHERE agent=? AND status='pending' ORDER BY AgentJobID")
    .all(agent) as { AgentJobID: number; kind: string; params: string }[];
  for (const r of rows) d.prepare("UPDATE XAGENTJOB SET status='sent', started_at=? WHERE AgentJobID=?").run(nowSql(), r.AgentJobID);
  return rows;
}
export function finishAgentJob(id: number, summary: string): void {
  getAgentDb().prepare("UPDATE XAGENTJOB SET status='done', finished_at=?, result_summary=? WHERE AgentJobID=?")
    .run(nowSql(), summary, id);
}
export function listAgentJobs(agent?: string, limit = 50): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM XAGENTJOB WHERE agent=? ORDER BY AgentJobID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM XAGENTJOB ORDER BY AgentJobID DESC LIMIT ?").all(limit);
}

// ── IOC (threat intelligence served to the agents) ───────────────────────────────
export function upsertIocs(iocs: { ioc_type: string; value: string; source?: string; threat?: string }[]): number {
  const d = getAgentDb();
  const ins = d.prepare("INSERT OR IGNORE INTO XIOC(ioc_type,value,source,threat,created_at) VALUES (?,?,?,?,?)");
  let n = 0;
  const tx = d.transaction(() => {
    for (const i of iocs) {
      if (!i.ioc_type || !i.value) continue;
      n += ins.run(i.ioc_type.toLowerCase(), String(i.value).trim(), i.source ?? null, i.threat ?? null, nowSql()).changes;
    }
  });
  tx();
  return n;
}
export function listIocs(): { ioc_type: string; value: string; threat: string | null }[] {
  return getAgentDb().prepare("SELECT ioc_type,value,threat FROM XIOC").all() as { ioc_type: string; value: string; threat: string | null }[];
}
export function iocCount(): number {
  return (getAgentDb().prepare("SELECT COUNT(*) c FROM XIOC").get() as { c: number }).c;
}

// ── Honeypot (agent-run deception sensor) ────────────────────────────────────────
export interface HoneypotHit { src_ip?: string; src_port?: number; dst_port?: number; service?: string; banner?: string; at?: string }

/**
 * Records the connection attempts captured by an agent-run honeypot. Each hit is stored in
 * HONEYPOTHIT, summarised as a single agent event, and the distinct source IPs are promoted
 * to the IOC store (attacker infrastructure that hit a decoy = high-signal indicator).
 */
export function recordHoneypotHits(agent: string, hits: HoneypotHit[]): { stored: number; uniqueIps: number } {
  const d = getAgentDb();
  const ins = d.prepare("INSERT INTO HONEYPOTHIT(agent,src_ip,src_port,dst_port,service,banner,hit_at,created_at) VALUES (?,?,?,?,?,?,?,?)");
  const ips = new Set<string>();
  let stored = 0;
  const tx = d.transaction(() => {
    for (const h of hits) {
      const ip = String(h.src_ip ?? "").trim();
      ins.run(agent, ip || null, h.src_port != null ? Number(h.src_port) : null, h.dst_port != null ? Number(h.dst_port) : null,
        h.service ? String(h.service).slice(0, 60) : null, h.banner ? String(h.banner).slice(0, 500) : null,
        h.at ? String(h.at) : nowSql(), nowSql());
      if (ip) ips.add(ip);
      stored++;
    }
  });
  tx();
  if (stored) {
    const ports = [...new Set(hits.map((h) => h.dst_port).filter((p) => p != null))].sort((a, b) => Number(a) - Number(b));
    addAgentEvent(agent, {
      type: "honeypot_hit", severity: ips.size ? "high" : "medium",
      title: `Honeypot: ${stored} connection attempt${stored > 1 ? "s" : ""} from ${ips.size} IP${ips.size === 1 ? "" : "s"} on port${ports.length > 1 ? "s" : ""} ${ports.join(", ")}`,
      detail: { hits: stored, uniqueIps: ips.size, ports },
    });
    // Attacker source IPs → IOC store (ipv4 / ipv6), tagged as honeypot-sourced.
    if (ips.size) upsertIocs([...ips].map((ip) => ({ ioc_type: ip.includes(":") ? "ipv6-addr" : "ipv4-addr", value: ip, source: `honeypot:${agent}`, threat: "honeypot-scanner" })));
  }
  return { stored, uniqueIps: ips.size };
}
export function listHoneypotHits(limit = 100, agent?: string): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM HONEYPOTHIT WHERE agent=? ORDER BY HitID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM HONEYPOTHIT ORDER BY HitID DESC LIMIT ?").all(limit);
}
/** Honeypot KPIs: total hits + distinct attacker IPs + top targeted ports (recent window). */
export function honeypotStats(): { hits: number; uniqueIps: number; topPorts: { port: number; hits: number }[] } {
  const d = getAgentDb();
  const hits = (d.prepare("SELECT COUNT(*) c FROM HONEYPOTHIT").get() as { c: number }).c;
  const uniqueIps = (d.prepare("SELECT COUNT(DISTINCT src_ip) c FROM HONEYPOTHIT WHERE src_ip IS NOT NULL").get() as { c: number }).c;
  const topPorts = (d.prepare("SELECT dst_port port, COUNT(*) hits FROM HONEYPOTHIT WHERE dst_port IS NOT NULL GROUP BY dst_port ORDER BY hits DESC LIMIT 6").all() as { port: number; hits: number }[]);
  return { hits, uniqueIps, topPorts };
}

// ── Memory acquisition (agent-run RAM dump for forensics) ────────────────────────
export interface MemoryDump {
  status?: string; tool?: string; path?: string; size?: number; sha256?: string;
  ramTotal?: number; os?: string; started?: string; finished?: string; duration?: number; error?: string;
}
function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

/**
 * Records a memory-acquisition (RAM dump) performed by the agent for forensics. The dump image
 * itself stays on the endpoint (it is GBs and must be preserved in place for chain of custody);
 * what XORCISM stores is the acquisition manifest — tool, output path, size, SHA-256, status —
 * in MEMORYDUMP, plus a memory_dump agent event so it surfaces in the fleet timeline.
 */
export function recordMemoryDump(agent: string, d: MemoryDump): { dumpId: number; status: string } {
  const db = getAgentDb();
  const a = listAgents().find((x) => x.name === agent);
  const status = String(d.status ?? "").trim().toLowerCase() || (d.error ? "error" : d.sha256 ? "completed" : "unknown");
  const r = db.prepare(
    `INSERT INTO MEMORYDUMP(agent,asset_name,host_os,tool,status,path,size_bytes,sha256,ram_total_bytes,started_at,finished_at,duration_sec,error,created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(agent, a?.asset_name ?? null, d.os ? String(d.os).slice(0, 120) : (a?.os ?? null),
    d.tool ? String(d.tool).slice(0, 120) : null, status, d.path ? String(d.path).slice(0, 500) : null,
    d.size != null ? Math.max(0, Math.round(Number(d.size))) : null, d.sha256 ? String(d.sha256).slice(0, 128) : null,
    d.ramTotal != null ? Math.max(0, Math.round(Number(d.ramTotal))) : null,
    d.started ? String(d.started) : null, d.finished ? String(d.finished) : null,
    d.duration != null ? Math.round(Number(d.duration)) : null, d.error ? String(d.error).slice(0, 1000) : null, nowSql());
  const ok = status === "completed";
  addAgentEvent(agent, {
    type: "memory_dump", severity: ok ? "high" : status === "error" || status === "no-tool" ? "medium" : "info",
    title: ok
      ? `RAM dump acquired: ${fmtBytes(Number(d.size ?? 0))} via ${d.tool || "?"}${d.sha256 ? ` (sha256 ${String(d.sha256).slice(0, 12)}…)` : ""}`
      : `RAM dump ${status}${d.error ? `: ${String(d.error).slice(0, 120)}` : ""}`,
    detail: { tool: d.tool, path: d.path, size: d.size, sha256: d.sha256, status, os: d.os },
  });
  return { dumpId: Number(r.lastInsertRowid), status };
}
export function listMemoryDumps(limit = 100, agent?: string): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM MEMORYDUMP WHERE agent=? ORDER BY DumpID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM MEMORYDUMP ORDER BY DumpID DESC LIMIT ?").all(limit);
}
/** Memory-acquisition KPIs: total dumps, completed, total acquired bytes. */
export function memDumpStats(): { dumps: number; completed: number; totalBytes: number } {
  const db = getAgentDb();
  const dumps = (db.prepare("SELECT COUNT(*) c FROM MEMORYDUMP").get() as { c: number }).c;
  const completed = (db.prepare("SELECT COUNT(*) c FROM MEMORYDUMP WHERE status='completed'").get() as { c: number }).c;
  const totalBytes = (db.prepare("SELECT COALESCE(SUM(size_bytes),0) s FROM MEMORYDUMP WHERE status='completed'").get() as { s: number }).s;
  return { dumps, completed, totalBytes };
}

// ── AI host-log threat hunt (LOGHUNT — written by loghunt.ts) ─────────────────────
export function listLogHunts(limit = 40, agent?: string): unknown[] {
  const d = getAgentDb();
  return agent
    ? d.prepare("SELECT * FROM LOGHUNT WHERE agent=? ORDER BY LogHuntID DESC LIMIT ?").all(agent, limit)
    : d.prepare("SELECT * FROM LOGHUNT ORDER BY LogHuntID DESC LIMIT ?").all(limit);
}
/** AI log-hunt KPIs: total runs, suspicious (high/critical), events analysed. */
export function logHuntStats(): { runs: number; suspicious: number; events: number } {
  const db = getAgentDb();
  const runs = (db.prepare("SELECT COUNT(*) c FROM LOGHUNT").get() as { c: number }).c;
  const suspicious = (db.prepare("SELECT COUNT(*) c FROM LOGHUNT WHERE LOWER(severity) IN ('high','critical')").get() as { c: number }).c;
  const events = (db.prepare("SELECT COALESCE(SUM(event_count),0) s FROM LOGHUNT").get() as { s: number }).s;
  return { runs, suspicious, events };
}

/** The scan kinds an agent can be tasked with (single source of truth, shared with /api/agent-scan). */
export const AGENT_SCAN_KINDS = ["inventory", "vuln", "oval", "av", "hunt", "full", "emulate", "forensics", "rustinel", "yara", "honeypot", "memdump", "loghunt", "aiguard"];

/** Aggregated view for the Agents-management page: inventory (+ computed freshness), recent jobs/events, summary. */
export function agentsOverview(): any {
  const fresh = (ls: string | null): { status: "online" | "idle" | "offline"; minsAgo: number | null } => {
    if (!ls) return { status: "offline", minsAgo: null };
    const t = Date.parse(ls.replace(" ", "T") + "Z"); // last_seen is UTC without a tz marker
    if (!Number.isFinite(t)) return { status: "offline", minsAgo: null };
    const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    return { status: mins <= 5 ? "online" : mins <= 60 ? "idle" : "offline", minsAgo: mins };
  };
  const agents = listAgents().map((a) => { const f = fresh(a.last_seen); return { ...a, freshness: f.status, minsAgo: f.minsAgo }; });
  const jobs = listAgentJobs(undefined, 40) as any[];
  const events = listAgentEvents(40) as any[];
  const hpHits = listHoneypotHits(60) as any[];
  const online = agents.filter((a) => a.freshness === "online").length;
  const idle = agents.filter((a) => a.freshness === "idle").length;
  const pending = jobs.filter((j) => j.status === "pending" || j.status === "sent").length;
  // Job outcomes: finishAgentJob always sets status='done'; a failure is a done job whose
  // result_summary starts with "error". Success rate = clean done / (clean done + failed).
  const isErr = (s: string): boolean => /^\s*error/i.test(String(s || ""));
  const done = jobs.filter((j) => j.status === "done" && !isErr(j.result_summary)).length;
  const failed = jobs.filter((j) => j.status === "done" && isErr(j.result_summary)).length;
  const successRate = done + failed ? Math.round((done / (done + failed)) * 100) : null;
  // Scans in the last 24h (created_at is UTC without a tz marker).
  const dayAgo = Date.now() - 86_400_000;
  const scans24h = jobs.filter((j) => { const t = Date.parse(String(j.created_at || "").replace(" ", "T") + "Z"); return Number.isFinite(t) && t >= dayAgo; }).length;
  // Alerts = events that demand attention (critical/high severity).
  const alerts = events.filter((e) => /^(critical|high)$/i.test(String(e.severity || ""))).length;
  const hp = honeypotStats();
  const md = memDumpStats();
  const memDumps = listMemoryDumps(40) as any[];
  const lh = logHuntStats();
  const logHunts = listLogHunts(40) as any[];
  return {
    agents, jobs, events, kinds: AGENT_SCAN_KINDS, honeypot: hpHits, honeypotTopPorts: hp.topPorts, memDumps, logHunts,
    summary: {
      total: agents.length, online, idle, offline: agents.length - online - idle,
      health: agents.length ? Math.round((online / agents.length) * 100) : null,
      jobsPending: pending, jobsTotal: jobs.length, jobsDone: done, jobsFailed: failed, successRate, scans24h,
      events: events.length, alerts, iocs: iocCount(),
      honeypotHits: hp.hits, honeypotIps: hp.uniqueIps,
      memDumps: md.dumps, memDumpsCompleted: md.completed, memDumpBytes: md.totalBytes,
      logHunts: lh.runs, logHuntsSuspicious: lh.suspicious, logHuntEvents: lh.events,
    },
  };
}
