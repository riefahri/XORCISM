/**
 * policyval.ts — Policy validation: does a written policy's intent actually hold on-prem / cloud / hybrid?
 *
 * Pipeline (the "policy-vs-reality" bridge):
 *   1. EXTRACT (local AI, human-approved) — parse a POLICY's prose into structured, checkable
 *      requirements (attribute / op / value / scope) each bound to a CONTROL ref and a known collector.
 *   2. VALIDATE (deterministic) — run each approved requirement's collector against the evidence XORCISM
 *      already holds (cloud CIS findings, asset/identity MFA, agentless host baseline) → pass / fail /
 *      partial / unverifiable per target, with a cited evidence reference.
 *   3. REPORT — per-policy compliance %, by environment, with the violation worklist and the gaps.
 *
 * The AI structures and explains; the deterministic checks decide (auditor-grade, evidence-cited). First
 * slice covers password standards + MFA, the requirements with collectors already present in 3 environments.
 */
import { getDb } from "./db";
import { ollamaStatus, ollamaChat } from "./ai";

export type Op = ">=" | "<=" | "==" | "exists";
export type ValResult = "pass" | "fail" | "partial" | "unverifiable";
export interface Requirement {
  requirementId: number; policyId: number; attribute: string; op: string; value: string;
  scope: string; controlRef: string; collectorKey: string; description: string; source: string; approved: boolean;
}
export interface ValRow { env: string; target: string; result: ValResult; detail: string; evidenceRef: string }

// Known collectors the AI must map requirements to (constrained vocabulary). env is the default bucket.
export const COLLECTORS: Record<string, { env: string; control: string; label: string }> = {
  "cloud.password_policy": { env: "cloud", control: "NIST IA-5 / CIS 5", label: "Cloud account password policy (length/reuse/complexity)" },
  "cloud.mfa_users": { env: "cloud", control: "NIST IA-2 / CIS 6", label: "MFA on cloud console users" },
  "cloud.root_mfa": { env: "cloud", control: "NIST IA-2", label: "Root/super-admin MFA" },
  "cloud.root_keys": { env: "cloud", control: "NIST AC-6", label: "No root access keys" },
  "cloud.inactive_users": { env: "cloud", control: "NIST AC-2", label: "No inactive cloud users" },
  "cloud.key_rotation": { env: "cloud", control: "NIST IA-5", label: "Access-key rotation" },
  "identity.mfa_all": { env: "identity", control: "NIST IA-2 / CIS 6", label: "MFA on all accounts/assets" },
  "identity.mfa_privileged": { env: "identity", control: "NIST IA-2(1)", label: "MFA on privileged accounts" },
  "host.baseline": { env: "onprem", control: "CIS Benchmarks", label: "On-prem host hardening baseline (agentless scan)" },
  "host.password_policy": { env: "onprem", control: "NIST IA-5 / CIS 5", label: "On-prem password policy (length/age/lockout, agentless scan)" },
  "unmapped": { env: "—", control: "", label: "No collector — manual attestation required" },
};
const KEYS = Object.keys(COLLECTORS).filter((k) => k !== "unmapped");

function cols(db: ReturnType<typeof getDb>, t: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); }
}
const truthy = (v: unknown): boolean => v === 1 || v === true || ["1", "true", "yes", "enabled", "on"].includes(String(v ?? "").trim().toLowerCase());
const now = (): string => new Date().toISOString();

// ── tables ───────────────────────────────────────────────────────────────────────
export function ensurePolicyValTables(): void {
  try {
    getDb("XORCISM").exec(`
      CREATE TABLE IF NOT EXISTS POLICYREQUIREMENT (
        RequirementID INTEGER PRIMARY KEY, PolicyID INTEGER, Attribute TEXT, Op TEXT, Value TEXT,
        Scope TEXT, ControlRef TEXT, CollectorKey TEXT, Description TEXT, Source TEXT,
        Approved INTEGER DEFAULT 0, TenantID INTEGER, CreatedDate TEXT);
      CREATE TABLE IF NOT EXISTS POLICYVALIDATION (
        ValidationID INTEGER PRIMARY KEY, RequirementID INTEGER, PolicyID INTEGER, Env TEXT, Target TEXT,
        Result TEXT, Detail TEXT, EvidenceRef TEXT, RunAt TEXT, TenantID INTEGER);
      CREATE TABLE IF NOT EXISTS POLICYVALIDATIONSNAPSHOT (
        SnapshotID INTEGER PRIMARY KEY, PolicyID INTEGER, RunAt TEXT,
        CompliancePct INTEGER, Measurable INTEGER, Passed INTEGER, Violations INTEGER, TenantID INTEGER);
      CREATE INDEX IF NOT EXISTS ix_polreq_policy ON POLICYREQUIREMENT(PolicyID);
      CREATE INDEX IF NOT EXISTS ix_polval_req ON POLICYVALIDATION(RequirementID);
      CREATE INDEX IF NOT EXISTS ix_polsnap_policy ON POLICYVALIDATIONSNAPSHOT(PolicyID);`);
  } catch { /* */ }
}

function policyText(xo: ReturnType<typeof getDb>, policyId: number): { name: string; text: string } | null {
  const pc = cols(xo, "POLICY");
  if (!pc.size) return null;
  const row = xo.prepare("SELECT * FROM POLICY WHERE PolicyID = ?").get(policyId) as Record<string, unknown> | undefined;
  if (!row) return null;
  const name = String(row["PolicyName"] ?? row["Name"] ?? `Policy #${policyId}`);
  let text = "";
  for (const c of ["PolicyText", "PolicyContent", "Content", "Body", "PolicyBody", "PolicyDescription", "Description", "Summary"]) {
    const v = row[c]; if (typeof v === "string" && v.trim().length > text.length) text = v.trim();
  }
  return { name, text };
}

// ── extract (AI + offline fallback) ────────────────────────────────────────────────
function offlineExtract(text: string): Omit<Requirement, "requirementId" | "policyId" | "approved">[] {
  const t = text.toLowerCase();
  const out: Omit<Requirement, "requirementId" | "policyId" | "approved">[] = [];
  const add = (attribute: string, op: string, value: string, scope: string, collectorKey: string, description: string) =>
    out.push({ attribute, op, value, scope, collectorKey, controlRef: COLLECTORS[collectorKey].control, description, source: "offline" });
  if (/password|passphrase|credential/.test(t)) {
    const len = t.match(/(\d{1,2})\s*(?:characters?|chars?|length)/);
    add("password_policy", len ? ">=" : "exists", len ? len[1] : "compliant", "cloud", "cloud.password_policy",
      "Password standard enforced in cloud IAM" + (len ? ` (min length ${len[1]})` : ""));
    add("password_onprem", len ? ">=" : "exists", len ? len[1] : "compliant", "onprem", "host.password_policy",
      "Password policy enforced on on-prem hosts" + (len ? ` (min length ${len[1]})` : ""));
  }
  if (/\bmfa\b|multi-?factor|two-?factor|\b2fa\b/.test(t)) {
    const priv = /privileg|admin|root|elevated/.test(t);
    add("mfa_required", "==", "true", priv ? "privileged" : "all", priv ? "identity.mfa_privileged" : "identity.mfa_all",
      "MFA required on " + (priv ? "privileged accounts" : "all accounts"));
    add("mfa_cloud", "==", "true", "cloud", "cloud.mfa_users", "MFA required on cloud console users");
    if (/root|super-?admin/.test(t)) add("root_mfa", "==", "true", "cloud", "cloud.root_mfa", "Root/super-admin account must have MFA");
  }
  if (/inactive|stale|dormant|unused account/.test(t)) add("inactive_users", "==", "0", "cloud", "cloud.inactive_users", "No inactive cloud users");
  if (/rotat/.test(t)) add("key_rotation", "exists", "compliant", "cloud", "cloud.key_rotation", "Access keys rotated");
  if (/root.{0,20}(access )?key/.test(t)) add("root_keys", "==", "0", "cloud", "cloud.root_keys", "No root account access keys");
  return out;
}

export async function extractRequirements(policyId: number, tenant: number | null): Promise<{ requirements: Requirement[]; ai: boolean; model: string }> {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  const pt = policyText(xo, policyId);
  if (!pt) throw new Error("policy not found");
  let proposed: Omit<Requirement, "requirementId" | "policyId" | "approved">[] = [];
  let ai = false, model = "";
  const status = await ollamaStatus().catch(() => ({ reachable: false, model: "" }));
  if (status.reachable && pt.text.trim()) {
    try {
      const sys = `You extract technically-validatable requirements from a security policy. Reply with ONLY a JSON array. Each item: {"attribute":str,"op":">="|"<="|"=="|"exists","value":str,"scope":"all"|"privileged"|"onprem"|"cloud"|"hybrid","collectorKey":one of [${KEYS.join(", ")}] or "unmapped","control":str (NIST/CIS ref),"description":str}. Focus on password standards and MFA. Use "unmapped" when no collector fits. Output at most 12 items.`;
      const out = await ollamaChat([{ role: "system", content: sys }, { role: "user", content: pt.text.slice(0, 6000) }], 0.1, 60000);
      const m = out.match(/\[[\s\S]*\]/);
      if (m) {
        const arr = JSON.parse(m[0]) as any[];
        proposed = arr.filter((x) => x && x.attribute).map((x) => ({
          attribute: String(x.attribute).slice(0, 80), op: ["<=", ">=", "==", "exists"].includes(x.op) ? x.op : "exists",
          value: String(x.value ?? "").slice(0, 80), scope: String(x.scope || "all").slice(0, 20),
          collectorKey: COLLECTORS[x.collectorKey] ? x.collectorKey : "unmapped",
          controlRef: String(x.control || COLLECTORS[x.collectorKey]?.control || "").slice(0, 80),
          description: String(x.description || x.attribute).slice(0, 300), source: "ai",
        }));
        ai = proposed.length > 0; model = status.model || "";
      }
    } catch { /* fall back offline */ }
  }
  if (!proposed.length) proposed = offlineExtract(pt.text);

  // persist as proposed (Approved=0), idempotent by (PolicyID, Attribute, CollectorKey)
  for (const p of proposed) {
    const ex = xo.prepare("SELECT RequirementID FROM POLICYREQUIREMENT WHERE PolicyID=? AND Attribute=? AND CollectorKey=? LIMIT 1").get(policyId, p.attribute, p.collectorKey);
    if (ex) continue;
    const id = ((xo.prepare("SELECT COALESCE(MAX(RequirementID),0)+1 id FROM POLICYREQUIREMENT").get() as { id: number }).id) || 1;
    xo.prepare(`INSERT INTO POLICYREQUIREMENT (RequirementID,PolicyID,Attribute,Op,Value,Scope,ControlRef,CollectorKey,Description,Source,Approved,TenantID,CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)`).run(id, policyId, p.attribute, p.op, p.value, p.scope, p.controlRef, p.collectorKey, p.description, p.source, tenant, now());
  }
  return { requirements: listRequirements(policyId, tenant), ai, model };
}

export function listRequirements(policyId: number, tenant: number | null): Requirement[] {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const args = tenant != null ? [policyId, tenant] : [policyId];
  return (xo.prepare(`SELECT RequirementID requirementId, PolicyID policyId, Attribute attribute, Op op, Value value, Scope scope,
      ControlRef controlRef, CollectorKey collectorKey, Description description, Source source, Approved approved
      FROM POLICYREQUIREMENT WHERE PolicyID=? ${tw} ORDER BY RequirementID`).all(...args) as any[])
    .map((r) => ({ ...r, approved: !!r.approved }));
}

export function setRequirement(id: number, patch: { approved?: boolean; op?: string; value?: string; collectorKey?: string }, tenant: number | null): boolean {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  const sets: string[] = [], vals: unknown[] = [];
  if (patch.approved != null) { sets.push("Approved=?"); vals.push(patch.approved ? 1 : 0); }
  if (patch.op) { sets.push("Op=?"); vals.push(patch.op); }
  if (patch.value != null) { sets.push("Value=?"); vals.push(String(patch.value)); }
  if (patch.collectorKey && COLLECTORS[patch.collectorKey]) { sets.push("CollectorKey=?"); vals.push(patch.collectorKey); }
  if (!sets.length) return false;
  vals.push(id);
  return xo.prepare(`UPDATE POLICYREQUIREMENT SET ${sets.join(", ")} WHERE RequirementID=?`).run(...vals).changes > 0;
}
export function deleteRequirement(id: number): void {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  xo.prepare("DELETE FROM POLICYREQUIREMENT WHERE RequirementID=?").run(id);
  xo.prepare("DELETE FROM POLICYVALIDATION WHERE RequirementID=?").run(id);
}

// ── collectors (read evidence XORCISM already holds) ────────────────────────────────
function cloudFindings(tenant: number | null, like: string[]): ValRow[] {
  const xo = getDb("XORCISM");
  if (!cols(xo, "CLOUDFINDING").size) return [];
  const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const clause = like.map(() => "(LOWER(Title) LIKE ? OR LOWER(CheckID) LIKE ?)").join(" OR ");
  const args: unknown[] = [];
  for (const k of like) { args.push(`%${k}%`, `%${k}%`); }
  if (tenant != null) args.push(tenant);
  const rows = xo.prepare(`SELECT CheckID, Title, Account, Resource, Status, Detail FROM CLOUDFINDING WHERE (${clause}) ${tw}`).all(...args) as Record<string, unknown>[];
  return rows.map((r) => ({ env: "cloud", target: String(r.Resource || r.Account || "account"),
    result: (String(r.Status) === "pass" ? "pass" : String(r.Status) === "fail" ? "fail" : "unverifiable") as ValResult,
    detail: String(r.Title) + (r.Detail ? " — " + String(r.Detail) : ""), evidenceRef: "CLOUDFINDING " + String(r.CheckID || "") }));
}
function assetMfa(tenant: number | null, privilegedOnly: boolean): ValRow[] {
  const xo = getDb("XORCISM");
  const ac = cols(xo, "ASSET");
  if (!ac.has("MFAEnabled")) return [];
  const tw = tenant != null && ac.has("TenantID") ? "AND (TenantID=? OR TenantID IS NULL)" : "";
  const crit = privilegedOnly && ac.has("AssetCriticalityLevel") ? "AND LOWER(COALESCE(AssetCriticalityLevel,'')) IN ('high','critical','very high')" : "";
  const args = tenant != null && ac.has("TenantID") ? [tenant] : [];
  const rows = xo.prepare(`SELECT AssetName, MFAEnabled FROM ASSET WHERE MFAEnabled IS NOT NULL AND TRIM(COALESCE(MFAEnabled,''))<>'' ${crit} ${tw}`).all(...args) as { AssetName: string; MFAEnabled: unknown }[];
  return rows.map((r) => ({ env: "identity", target: r.AssetName || "asset",
    result: (truthy(r.MFAEnabled) ? "pass" : "fail") as ValResult,
    detail: "MFA " + (truthy(r.MFAEnabled) ? "enabled" : "NOT enabled") + (privilegedOnly ? " (privileged asset)" : ""), evidenceRef: "ASSET.MFAEnabled" }));
}
function hostBaseline(tenant: number | null): ValRow[] {
  try {
    const xv = getDb("XVULNERABILITY");
    if (!cols(xv, "VULNERABILITY").has("VULName")) return [];
    const rows = xv.prepare(`SELECT VULName, VULReferential FROM VULNERABILITY WHERE VULName LIKE 'Hardening:%' OR VULReferential LIKE 'AGENTLESS-%' LIMIT 500`).all() as { VULName: string; VULReferential: string }[];
    return rows.map((r) => ({ env: "onprem", target: String(r.VULName || r.VULReferential || "host check"),
      result: "fail" as ValResult, detail: "Open host-hardening finding from the agentless scan", evidenceRef: String(r.VULReferential || "agentless-scan") }));
  } catch { return []; }
}

// Threshold-aware comparison: when a requirement is numeric (e.g. min length >= 14) and the evidence
// carries an observed number ("MinimumPasswordLength = 8"), re-evaluate pass/fail against the POLICY's
// own threshold (not just the benchmark's), and report the actual numbers.
function numericReq(req?: Requirement): number | null {
  if (!req || !["<=", ">=", "=="].includes(req.op)) return null;
  const n = parseFloat(req.value); return Number.isFinite(n) ? n : null;
}
const cmp = (obs: number, op: string, want: number): boolean => op === ">=" ? obs >= want : op === "<=" ? obs <= want : op === "==" ? obs === want : true;
function applyThreshold(rows: ValRow[], req?: Requirement): ValRow[] {
  const want = numericReq(req);
  if (want == null) return rows;
  return rows.map((r) => {
    const m = (r.detail || "").match(/=\s*(\d+)|(\d+)\s*(?:day|char)/i);
    if (!m) return r;
    const obs = parseInt(m[1] || m[2], 10);
    return { ...r, result: (cmp(obs, req!.op, want) ? "pass" : "fail") as ValResult, detail: r.detail + ` → observed ${obs}, policy requires ${req!.op} ${want}` };
  });
}
function hostPassword(tenant: number | null, req?: Requirement): ValRow[] {
  try {
    const xv = getDb("XVULNERABILITY");
    if (!cols(xv, "VULNERABILITY").has("VULName")) return [];
    const rows = xv.prepare(`SELECT VULName, VULDescription, VULReferential FROM VULNERABILITY
      WHERE (LOWER(VULName) LIKE '%password%' OR LOWER(VULReferential) LIKE 'agentless-pwd%')
        AND (VULName LIKE 'Hardening:%' OR VULReferential LIKE 'AGENTLESS-%') LIMIT 300`).all() as { VULName: string; VULDescription: string; VULReferential: string }[];
    const want = numericReq(req);
    return rows.map((r) => {
      const text = `${r.VULName} ${r.VULDescription || ""}`;
      const m = want != null ? text.match(/=\s*(\d+)|(\d+)\s*(?:day|char)/i) : null;
      if (m) { const obs = parseInt(m[1] || m[2], 10); return { env: "onprem", target: String(r.VULName), result: (cmp(obs, req!.op, want!) ? "pass" : "fail") as ValResult, detail: `observed ${obs}, policy requires ${req!.op} ${want}`, evidenceRef: String(r.VULReferential || "agentless-scan") }; }
      return { env: "onprem", target: String(r.VULName), result: "fail" as ValResult, detail: "Open host password-policy finding (agentless baseline)", evidenceRef: String(r.VULReferential || "agentless-scan") };
    });
  } catch { return []; }
}

function runCollector(key: string, tenant: number | null, req?: Requirement): ValRow[] {
  switch (key) {
    case "cloud.password_policy": return applyThreshold(cloudFindings(tenant, ["password", "1.7", "1.8", "1.9"]), req);
    case "cloud.mfa_users": return cloudFindings(tenant, ["mfa enabled for", "1.10"]);
    case "cloud.root_mfa": return cloudFindings(tenant, ["root account mfa", "security defaults", "1.5"]);
    case "cloud.root_keys": return cloudFindings(tenant, ["root account access keys", "1.4"]);
    case "cloud.inactive_users": return cloudFindings(tenant, ["inactive", "1.12"]);
    case "cloud.key_rotation": return cloudFindings(tenant, ["rotat"]);
    case "identity.mfa_all": return assetMfa(tenant, false);
    case "identity.mfa_privileged": return assetMfa(tenant, true);
    case "host.baseline": return hostBaseline(tenant);
    case "host.password_policy": return hostPassword(tenant, req);
    default: return [];
  }
}

// ── validate + report ──────────────────────────────────────────────────────────────
function rollup(rows: ValRow[]): ValResult {
  if (!rows.length) return "unverifiable";
  const fail = rows.some((r) => r.result === "fail");
  const pass = rows.some((r) => r.result === "pass");
  return fail && pass ? "partial" : fail ? "fail" : pass ? "pass" : "unverifiable";
}

export interface Drift { requirementId: number; name: string; from: string; to: string; dir: "up" | "down" }

function snapshotTrend(policyId: number, tenant: number | null): { at: string; pct: number }[] {
  try {
    const xo = getDb("XORCISM");
    const tw = tenant != null ? "AND (TenantID=? OR TenantID IS NULL)" : "";
    const args = tenant != null ? [policyId, tenant] : [policyId];
    const rows = xo.prepare(`SELECT RunAt, CompliancePct FROM POLICYVALIDATIONSNAPSHOT WHERE PolicyID=? ${tw} ORDER BY SnapshotID DESC LIMIT 30`).all(...args) as { RunAt: string; CompliancePct: number }[];
    return rows.reverse().map((r) => ({ at: r.RunAt, pct: r.CompliancePct }));
  } catch { return []; }
}

export function validatePolicy(policyId: number, tenant: number | null): PolicyReport {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  const reqs = listRequirements(policyId, tenant).filter((r) => r.approved);
  // capture the prior per-requirement rollup BEFORE overwriting it, to compute drift after re-validation
  const prior = new Map<number, ValResult>();
  for (const r of reqs) {
    const old = xo.prepare("SELECT Result FROM POLICYVALIDATION WHERE RequirementID=?").all(r.requirementId) as { Result: string }[];
    prior.set(r.requirementId, rollup(old.map((x) => ({ result: x.Result } as ValRow))));
  }
  for (const r of reqs) {
    const rows = runCollector(r.collectorKey, tenant, r);
    xo.prepare("DELETE FROM POLICYVALIDATION WHERE RequirementID=?").run(r.requirementId);
    const runAt = now();
    for (const v of rows) {
      const id = ((xo.prepare("SELECT COALESCE(MAX(ValidationID),0)+1 id FROM POLICYVALIDATION").get() as { id: number }).id) || 1;
      xo.prepare(`INSERT INTO POLICYVALIDATION (ValidationID,RequirementID,PolicyID,Env,Target,Result,Detail,EvidenceRef,RunAt,TenantID)
        VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id, r.requirementId, policyId, v.env, v.target.slice(0, 200), v.result, v.detail.slice(0, 600), v.evidenceRef.slice(0, 120), runAt, tenant);
    }
  }
  const rep = policyReport(policyId, tenant);
  // drift vs the previous run (ignore unverifiable on either side)
  const rank: Record<string, number> = { gap: 0, unverifiable: 0, fail: 1, partial: 2, pass: 3 };
  for (const q of rep.requirements) {
    const before = prior.get(q.requirementId);
    if (before && before !== q.status && before !== "unverifiable" && q.status !== "unverifiable")
      rep.drift.push({ requirementId: q.requirementId, name: q.description || q.attribute, from: before, to: q.status, dir: (rank[q.status] >= rank[before]) ? "up" : "down" });
  }
  // persist a compliance snapshot (for the trend) and read it back
  const sid = ((xo.prepare("SELECT COALESCE(MAX(SnapshotID),0)+1 id FROM POLICYVALIDATIONSNAPSHOT").get() as { id: number }).id) || 1;
  xo.prepare(`INSERT INTO POLICYVALIDATIONSNAPSHOT (SnapshotID,PolicyID,RunAt,CompliancePct,Measurable,Passed,Violations,TenantID) VALUES (?,?,?,?,?,?,?,?)`)
    .run(sid, policyId, now(), rep.compliancePct, rep.measurable, rep.passed, rep.violations.length, tenant);
  rep.trend = snapshotTrend(policyId, tenant);
  return rep;
}

export interface PolicyReport {
  policyId: number; policyName: string; evaluatedAt: string | null;
  compliancePct: number; measurable: number; passed: number;
  byEnv: { env: string; pass: number; fail: number; total: number }[];
  requirements: { requirementId: number; attribute: string; description: string; collectorKey: string; controlRef: string; scope: string; approved: boolean; status: ValResult; pass: number; fail: number; total: number }[];
  violations: { requirement: string; env: string; target: string; detail: string; evidenceRef: string }[];
  gaps: { requirement: string; reason: string }[];
  trend: { at: string; pct: number }[];
  drift: { requirementId: number; name: string; from: string; to: string; dir: string }[];
}

export function policyReport(policyId: number, tenant: number | null): PolicyReport {
  ensurePolicyValTables();
  const xo = getDb("XORCISM");
  const pt = policyText(xo, policyId);
  const reqs = listRequirements(policyId, tenant);
  const byEnv: Record<string, { pass: number; fail: number; total: number }> = {};
  const requirements: PolicyReport["requirements"] = [];
  const violations: PolicyReport["violations"] = [];
  const gaps: PolicyReport["gaps"] = [];
  let measurable = 0, passed = 0, evaluatedAt: string | null = null;

  for (const r of reqs) {
    const rows = xo.prepare("SELECT Env, Target, Result, Detail, EvidenceRef, RunAt FROM POLICYVALIDATION WHERE RequirementID=?").all(r.requirementId) as Record<string, unknown>[];
    const status = r.approved ? rollup(rows.map((x) => ({ result: x.Result } as ValRow))) : "unverifiable";
    const pass = rows.filter((x) => x.Result === "pass").length;
    const fail = rows.filter((x) => x.Result === "fail").length;
    for (const x of rows) {
      const e = String(x.Env || "—"); byEnv[e] = byEnv[e] || { pass: 0, fail: 0, total: 0 };
      byEnv[e].total++; if (x.Result === "pass") byEnv[e].pass++; else if (x.Result === "fail") byEnv[e].fail++;
      if (x.RunAt && (!evaluatedAt || String(x.RunAt) > evaluatedAt)) evaluatedAt = String(x.RunAt);
      if (x.Result === "fail") violations.push({ requirement: r.description || r.attribute, env: e, target: String(x.Target), detail: String(x.Detail || ""), evidenceRef: String(x.EvidenceRef || "") });
    }
    if (r.approved && status !== "unverifiable") { measurable++; if (status === "pass") passed++; }
    if (r.approved && (status === "unverifiable" || r.collectorKey === "unmapped"))
      gaps.push({ requirement: r.description || r.attribute, reason: r.collectorKey === "unmapped" ? "no collector — manual attestation" : "no evidence collected yet (run the scan)" });
    requirements.push({ requirementId: r.requirementId, attribute: r.attribute, description: r.description, collectorKey: r.collectorKey, controlRef: r.controlRef, scope: r.scope, approved: r.approved, status, pass, fail, total: rows.length });
  }
  return {
    policyId, policyName: pt?.name || `Policy #${policyId}`, evaluatedAt,
    compliancePct: measurable ? Math.round((passed / measurable) * 100) : 0, measurable, passed,
    byEnv: Object.entries(byEnv).map(([env, v]) => ({ env, ...v })),
    requirements, violations: violations.slice(0, 200), gaps,
    trend: snapshotTrend(policyId, tenant), drift: [],
  };
}
