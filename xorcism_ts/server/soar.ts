/**
 * soar.ts — outbound SOAR / automation dispatch for the CROC loop (n8n & any webhook-driven SOAR).
 *
 * Every action the loop fires (escalate / ticket / constrain / notify / reprioritize) is also POSTed
 * as a compact JSON event to the configured automation webhooks, so an n8n / Tines / Shuffle workflow
 * can run arbitrary downstream playbooks (enrich, quarantine, page, open a bridge, …). This is the
 * generic "glue" rung: XORCISM decides + acts on the things it owns, and hands everything else to the
 * SOAR. Mirrors teams.ts (webhook store + env fallback N8N_WEBHOOK_URL / N8N_API_KEY). Fire-and-forget,
 * best-effort, never throws; nothing is posted unless a webhook is configured.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const now = (): string => new Date().toISOString();
const SEV_RANK: Record<string, number> = { info: 0, informational: 0, success: 0, low: 1, medium: 2, moderate: 2, warning: 2, high: 3, error: 3, critical: 4 };
const srank = (s: string | null | undefined): number => SEV_RANK[String(s || "info").toLowerCase()] ?? 0;

export interface SoarEvent { action: string; eventType: string; severity?: string | null; summary?: string | null; refs?: string[] }

export function ensureSoarTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS SOARWEBHOOK (
      WebhookID INTEGER PRIMARY KEY,
      WebhookGUID TEXT, Name TEXT, Url TEXT, ApiKey TEXT, MinSeverity TEXT DEFAULT 'high',
      EventFilter TEXT, Enabled INTEGER DEFAULT 1, CreatedDate TEXT, TenantID INTEGER);
    CREATE INDEX IF NOT EXISTS ix_soarwebhook_tenant ON SOARWEBHOOK(TenantID);
  `);
}

interface SoarRow { WebhookID: number; Name: string; Url: string; ApiKey: string | null; MinSeverity: string; EventFilter: string | null; Enabled: number; TenantID: number | null }

function listRows(tenant: number | null): SoarRow[] {
  try { ensureSoarTables(); return getDb("XORCISM").prepare("SELECT * FROM SOARWEBHOOK WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY WebhookID").all(tenant) as SoarRow[]; }
  catch { return []; }
}

function hostOf(u: string): string { try { return new URL(u).host; } catch { return "…"; } }

export function redactSoar(tenant: number | null): any[] {
  return listRows(tenant).map((r) => ({ id: r.WebhookID, name: r.Name, host: hostOf(r.Url || ""), minSeverity: r.MinSeverity, eventFilter: r.EventFilter, enabled: !!r.Enabled, hasKey: !!r.ApiKey }));
}

export function addSoar(tenant: number | null, p: { name?: string; url: string; apiKey?: string; minSeverity?: string; eventFilter?: string }): { id: number } {
  ensureSoarTables();
  const db = getDb("XORCISM");
  const id = (db.prepare("SELECT COALESCE(MAX(WebhookID),0)+1 n FROM SOARWEBHOOK").get() as { n: number }).n;
  const minSev = p.minSeverity && SEV_RANK[String(p.minSeverity).toLowerCase()] != null ? String(p.minSeverity).toLowerCase() : "high";
  db.prepare("INSERT INTO SOARWEBHOOK (WebhookID, WebhookGUID, Name, Url, ApiKey, MinSeverity, EventFilter, Enabled, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,1,?,?)")
    .run(id, randomUUID(), (p.name || "n8n / SOAR").slice(0, 120), String(p.url || "").slice(0, 400), p.apiKey || null, minSev, p.eventFilter || null, now(), tenant);
  return { id };
}

export function setSoar(tenant: number | null, id: number, patch: { enabled?: boolean; minSeverity?: string; eventFilter?: string | null; name?: string; url?: string; apiKey?: string }): boolean {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM SOARWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").get(id, tenant)) return false;
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.enabled != null) { sets.push("Enabled=?"); vals.push(patch.enabled ? 1 : 0); }
  if (patch.minSeverity && SEV_RANK[patch.minSeverity.toLowerCase()] != null) { sets.push("MinSeverity=?"); vals.push(patch.minSeverity.toLowerCase()); }
  if (patch.eventFilter !== undefined) { sets.push("EventFilter=?"); vals.push(patch.eventFilter || null); }
  if (patch.name) { sets.push("Name=?"); vals.push(patch.name.slice(0, 120)); }
  if (patch.url) { sets.push("Url=?"); vals.push(patch.url.slice(0, 400)); }
  if (patch.apiKey) { sets.push("ApiKey=?"); vals.push(String(patch.apiKey)); }
  if (sets.length) db.prepare(`UPDATE SOARWEBHOOK SET ${sets.join(", ")} WHERE WebhookID=?`).run(...vals, id);
  return true;
}

export function deleteSoar(tenant: number | null, id: number): boolean {
  return getDb("XORCISM").prepare("DELETE FROM SOARWEBHOOK WHERE WebhookID=? AND (TenantID = ? OR TenantID IS NULL)").run(id, tenant).changes > 0;
}

interface SoarTarget { url: string; apiKey: string | null }
function resolveSoar(tenant: number | null, severity: string, eventType?: string | null): SoarTarget[] {
  const out: SoarTarget[] = [];
  for (const r of listRows(tenant)) {
    if (!r.Enabled || !r.Url) continue;
    if (srank(severity) < srank(r.MinSeverity)) continue;
    if (r.EventFilter && eventType && !r.EventFilter.split(",").some((f) => String(eventType).toLowerCase().includes(f.trim().toLowerCase()))) continue;
    out.push({ url: r.Url, apiKey: r.ApiKey });
  }
  const envUrl = (process.env.N8N_WEBHOOK_URL || "").trim();
  if (envUrl && srank(severity) >= srank(process.env.SOAR_MIN_SEVERITY || "high")) out.push({ url: envUrl, apiKey: process.env.N8N_API_KEY || null });
  return out;
}

export function externalSoarConfigured(tenant: number | null): boolean { return resolveSoar(tenant, "critical").length > 0; }

async function postWebhook(t: SoarTarget, payload: unknown): Promise<boolean> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (t.apiKey) headers["X-API-Key"] = t.apiKey;
    const r = await fetch(t.url, { method: "POST", headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) });
    return r.ok;
  } catch { return false; }
}

/** Fan an action out to the configured SOAR webhooks. Best-effort, fire-and-forget. */
export async function dispatchSoar(tenant: number | null, ev: SoarEvent): Promise<{ sent: number; failed: number }> {
  let sent = 0, failed = 0;
  try {
    const targets = resolveSoar(tenant, ev.severity || "info", ev.eventType);
    if (!targets.length) return { sent, failed };
    const payload = { source: "xorcism-croc", action: ev.action, eventType: ev.eventType, severity: ev.severity || "info", summary: ev.summary || "", refs: ev.refs || [], at: now() };
    for (const t of targets) { if (await postWebhook(t, payload)) sent++; else failed++; }
  } catch { /* never throw */ }
  return { sent, failed };
}

/** Post one test event to a stored webhook (Settings "Test" button). */
export async function testSoar(tenant: number | null, id: number): Promise<{ ok: boolean } | null> {
  const row = listRows(tenant).find((r) => r.WebhookID === id);
  if (!row) return null;
  const ok = await postWebhook({ url: row.Url, apiKey: row.ApiKey }, { source: "xorcism-croc", action: "test", eventType: "test", severity: "high", summary: "CROC SOAR connectivity test", at: now() });
  return { ok };
}
