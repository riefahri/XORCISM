/**
 * aidetect.ts — AI runtime anomaly detection ("ITDR for AI usage") (/ai-detection).
 *
 * The runtime layer of the AI-TRiSM suite (cf. the Orca LLM-security guide's "continuous runtime
 * monitoring"): it ingests per-AISYSTEM usage telemetry (daily rollups of requests, tokens, refusals,
 * injection attempts, distinct users), baselines normal behavior, and raises detections for the exact
 * runtime threats the guide names:
 *   - EXTRACTION  : request-volume spike vs. baseline (model-inversion / training-data extraction / scraping)
 *   - JAILBREAK   : a spike in injection attempts or refusals (repeated jailbreak / prompt-injection attempts)
 *   - DRIFT       : a large shift in refusal rate vs. baseline (a data-poisoning / behavior-change signal)
 *
 * Detections (XORCISM.AIDETECTION) emit a CROC loop event so the orchestrator can act. Compute-only +
 * deterministic; telemetry is fed by an agent / gateway connector (recordAiUsage). Mirrors itdr.ts.
 */
import { getDb } from "./db";
import { emitLoopEvent } from "./croc";

const now = (): string => new Date().toISOString();
const today = (): string => now().slice(0, 10);
const median = (xs: number[]): number => { if (!xs.length) return 0; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

export function ensureAiDetectTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS AIUSAGE (
      UsageID INTEGER PRIMARY KEY, AISystemID INTEGER, TenantID INTEGER, Day TEXT,
      Requests INTEGER, TokensIn INTEGER, TokensOut INTEGER, Refusals INTEGER,
      InjectionAttempts INTEGER, DistinctUsers INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_aiusage_sys ON AIUSAGE(AISystemID, Day);
    CREATE TABLE IF NOT EXISTS AIDETECTION (
      DetectionID INTEGER PRIMARY KEY, AISystemID INTEGER, TenantID INTEGER, Day TEXT,
      Type TEXT, Severity TEXT, Detail TEXT, Evidence TEXT, Status TEXT DEFAULT 'open', CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_aidet_sys ON AIDETECTION(AISystemID);
    CREATE INDEX IF NOT EXISTS ix_aidet_tenant ON AIDETECTION(TenantID);
  `);
}

export interface UsageRow { aiSystemId: number; day: string; requests: number; tokensIn?: number; tokensOut?: number; refusals?: number; injectionAttempts?: number; distinctUsers?: number }

/** Ingest a daily usage rollup (upsert by system+day). Fed by an AI agent / gateway connector. */
export function recordAiUsage(tenant: number | null, u: UsageRow): void {
  ensureAiDetectTables();
  const db = getDb("XORCISM");
  const ex = db.prepare("SELECT UsageID FROM AIUSAGE WHERE AISystemID=? AND Day=? AND (TenantID=? OR TenantID IS NULL)").get(u.aiSystemId, u.day, tenant) as { UsageID: number } | undefined;
  const vals = [u.requests || 0, u.tokensIn || 0, u.tokensOut || 0, u.refusals || 0, u.injectionAttempts || 0, u.distinctUsers || 0];
  if (ex) db.prepare("UPDATE AIUSAGE SET Requests=?,TokensIn=?,TokensOut=?,Refusals=?,InjectionAttempts=?,DistinctUsers=? WHERE UsageID=?").run(...vals, ex.UsageID);
  else {
    const id = (db.prepare("SELECT COALESCE(MAX(UsageID),0)+1 n FROM AIUSAGE").get() as { n: number }).n;
    db.prepare("INSERT INTO AIUSAGE (UsageID,AISystemID,TenantID,Day,Requests,TokensIn,TokensOut,Refusals,InjectionAttempts,DistinctUsers,CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?)").run(id, u.aiSystemId, tenant, u.day, ...vals, now());
  }
}

interface Det { aiSystemId: number; day: string; type: string; severity: string; detail: string; evidence: string }

/** Baseline each AI system's usage and detect extraction / jailbreak / drift on its latest day.
 *  Idempotent: a detection is recorded once per (system, type, day). Emits a loop event on high/critical. */
export function runAiDetections(tenant: number | null): { detections: number; scanned: number } {
  ensureAiDetectTables();
  const db = getDb("XORCISM");
  const sysIds = (db.prepare("SELECT DISTINCT AISystemID id FROM AIUSAGE WHERE (TenantID=? OR TenantID IS NULL)").all(tenant) as { id: number }[]).map((r) => r.id);
  let created = 0;
  const found: Det[] = [];
  for (const sid of sysIds) {
    const rows = db.prepare("SELECT * FROM AIUSAGE WHERE AISystemID=? AND (TenantID=? OR TenantID IS NULL) ORDER BY Day").all(sid, tenant) as any[];
    if (rows.length < 7) continue; // need a baseline window
    const hist = rows.slice(0, -1), last = rows[rows.length - 1];
    const baseReq = median(hist.map((r) => r.Requests || 0));
    const refusalRate = (r: any) => (r.Requests ? (r.Refusals || 0) / r.Requests : 0);
    const baseRefuse = hist.reduce((a, r) => a + refusalRate(r), 0) / Math.max(1, hist.length);
    const lr = refusalRate(last);
    // EXTRACTION — volume spike (systematic querying to extract memorized data)
    if (last.Requests > Math.max(50, baseReq * 3)) found.push({ aiSystemId: sid, day: last.Day, type: "extraction", severity: last.Requests > baseReq * 6 ? "critical" : "high", detail: `Request volume ${last.Requests} vs baseline ~${Math.round(baseReq)}/day (${baseReq ? Math.round(last.Requests / baseReq) : "∞"}×) — possible training-data extraction / scraping`, evidence: `users=${last.DistinctUsers}, tokensOut=${last.TokensOut}` });
    // JAILBREAK — injection-attempt or refusal spike (repeated prompt-injection / jailbreak)
    if ((last.InjectionAttempts || 0) >= 5 || lr > baseRefuse * 2 + 0.1) found.push({ aiSystemId: sid, day: last.Day, type: "jailbreak", severity: (last.InjectionAttempts || 0) >= 15 ? "high" : "medium", detail: `${last.InjectionAttempts} injection attempt(s); refusal rate ${(lr * 100).toFixed(0)}% vs baseline ${(baseRefuse * 100).toFixed(0)}% — repeated jailbreak / prompt-injection`, evidence: `requests=${last.Requests}, refusals=${last.Refusals}` });
    // DRIFT — large refusal-rate shift (behavior change → poisoning signal)
    else if (Math.abs(lr - baseRefuse) > 0.25) found.push({ aiSystemId: sid, day: last.Day, type: "drift", severity: "medium", detail: `Refusal rate shifted to ${(lr * 100).toFixed(0)}% from baseline ${(baseRefuse * 100).toFixed(0)}% — output/behavior drift (possible data poisoning)`, evidence: `requests=${last.Requests}` });
  }
  for (const d of found) {
    const dupe = db.prepare("SELECT 1 FROM AIDETECTION WHERE AISystemID=? AND Type=? AND Day=?").get(d.aiSystemId, d.type, d.day);
    if (dupe) continue;
    const id = (db.prepare("SELECT COALESCE(MAX(DetectionID),0)+1 n FROM AIDETECTION").get() as { n: number }).n;
    db.prepare("INSERT INTO AIDETECTION (DetectionID,AISystemID,TenantID,Day,Type,Severity,Detail,Evidence,Status,CreatedDate) VALUES (?,?,?,?,?,?,?,?,'open',?)").run(id, d.aiSystemId, tenant, d.day, d.type, d.severity, d.detail, d.evidence, now());
    created++;
    if (d.severity === "high" || d.severity === "critical") { try { emitLoopEvent({ type: "ai.anomaly_detected", source: "ai-detection", severity: d.severity, tenant, summary: `AI ${d.type}: ${d.detail}`.slice(0, 380) }); } catch { /* */ } }
  }
  return { detections: created, scanned: sysIds.length };
}

export function aiDetectionDashboard(tenant: number | null): any {
  ensureAiDetectTables();
  runAiDetections(tenant);
  const db = getDb("XORCISM");
  const dets = db.prepare(
    `SELECT d.*, s.Name AS SystemName FROM AIDETECTION d LEFT JOIN AISYSTEM s ON s.AISystemID=d.AISystemID
     WHERE (d.TenantID=? OR d.TenantID IS NULL) ORDER BY CASE LOWER(d.Severity) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, d.Day DESC LIMIT 200`
  ).all(tenant) as any[];
  const rows = dets.map((d) => ({ id: d.DetectionID, system: d.SystemName || `#${d.AISystemID}`, day: d.Day, type: d.Type, severity: d.Severity, detail: d.Detail, evidence: d.Evidence, status: d.Status }));
  const monitored = (db.prepare("SELECT COUNT(DISTINCT AISystemID) n FROM AIUSAGE WHERE (TenantID=? OR TenantID IS NULL)").get(tenant) as { n: number }).n;
  const summary = {
    monitored, detections: rows.length,
    open: rows.filter((r) => r.status === "open").length,
    extraction: rows.filter((r) => r.type === "extraction").length,
    jailbreak: rows.filter((r) => r.type === "jailbreak").length,
    drift: rows.filter((r) => r.type === "drift").length,
    critical: rows.filter((r) => ["critical", "high"].includes((r.severity || "").toLowerCase())).length,
  };
  return { summary, detections: rows };
}

/** Demo (tenant-scoped): 30 days of steady usage for the seeded AI systems + an anomaly on the latest
 *  day (an extraction volume spike + a jailbreak attempt burst). Idempotent. */
export function seedAiUsageDemo(tenant: number): { systems: number; days: number } {
  ensureAiDetectTables();
  const db = getDb("XORCISM");
  const sysIds = (db.prepare("SELECT AISystemID id FROM AISYSTEM WHERE (TenantID=? OR TenantID IS NULL) AND COALESCE(Lifecycle,'') LIKE '%rod%' ORDER BY AISystemID LIMIT 3").all(tenant) as { id: number }[]).map((r) => r.id);
  if (!sysIds.length) return { systems: 0, days: 0 };
  if ((db.prepare("SELECT COUNT(*) n FROM AIUSAGE WHERE (TenantID=? OR TenantID IS NULL)").get(tenant) as { n: number }).n > 0) return { systems: 0, days: 0 };
  let n = 0;
  for (const sid of sysIds) {
    for (let day = 30; day >= 0; day--) {
      const date = new Date(Date.now() - day * 86400000).toISOString().slice(0, 10);
      const base = 120 + Math.round(Math.sin(sid + day) * 20);
      const anomaly = day === 0; // today: spike
      recordAiUsage(tenant, {
        aiSystemId: sid, day: date,
        requests: anomaly ? base * 8 : base,
        tokensIn: base * 300, tokensOut: anomaly ? base * 8 * 800 : base * 400,
        refusals: anomaly ? Math.round(base * 0.4) : Math.round(base * 0.03),
        injectionAttempts: anomaly ? 22 : 0,
        distinctUsers: anomaly ? 2 : Math.round(base / 6),
      });
      n++;
    }
  }
  return { systems: sysIds.length, days: 31 };
}
