/**
 * cloudsec.ts — Cloud Security Management (CSPM-style governance pane).
 *
 * One pane over the tenant's cloud estate: assets identified as cloud (ASSET.cloud flag /
 * hosted-by-third-party / a cloud ASSETTAG / a cloud-looking hostname), enriched cross-DB with
 * their vulnerabilities (KEV / critical via ASSETVULNERABILITY ⋈ XVULNERABILITY.VULNERABILITY),
 * public-exposure and encryption posture, plus a CSA CCM coverage reference (the imported CCM
 * catalogue) and a risk-ranked misconfiguration/exposure worklist. Fed by the cloud connectors
 * (Entra ID, Wiz, Lacework, Upwind, Chainguard…). Read-only governance view.
 */
import { getDb } from "./db";

const CLOUD_TAGS = /^(cloud|aws|amazon|azure|gcp|google.?cloud|oci|oracle.?cloud|alibaba|saas|paas|iaas|serverless|lambda|s3|ec2|eks|aks|gke|kubernetes|k8s|container|ecs|fargate|cloudfront|rds|blob|vpc)$/i;
const CLOUD_HOST = /amazonaws\.com|azure|windows\.net|googleusercontent|gcp|cloudapp|herokuapp|cloudfront|\.run\.app/i;

function cols(dbName: string, table: string): Set<string> {
  try { return new Set((getDb(dbName).prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function truthy(v: unknown): boolean { return v === 1 || v === "1" || v === true || Number(v) === 1 || /^(y|yes|true)$/i.test(String(v ?? "")); }
const critRank = (c: string): number => ({ critical: 4, high: 3, medium: 2, moderate: 2, low: 1 } as Record<string, number>)[String(c).toLowerCase().split(/\s/)[0]] ?? 0;
const providerOf = (tags: string[], host: string, os: string): string => {
  const blob = `${tags.join(" ")} ${host} ${os}`.toLowerCase();
  if (/aws|amazon|ec2|s3|eks|amazonaws/.test(blob)) return "AWS";
  if (/azure|windows\.net|aks|entra/.test(blob)) return "Azure";
  if (/gcp|google|gke|googleusercontent|\.run\.app/.test(blob)) return "GCP";
  if (/oci|oracle/.test(blob)) return "OCI";
  if (/saas/.test(blob)) return "SaaS";
  return "Cloud";
};

export interface CloudInventory { rows: Record<string, unknown>[]; worklist: Record<string, unknown>[]; summary: Record<string, unknown>; }

export function cloudInventory(tenant: number | null): CloudInventory {
  const xo = getDb("XORCISM");
  const empty: CloudInventory = { rows: [], worklist: [], summary: { cloudAssets: 0, publicFacing: 0, unencrypted: 0, criticalAssets: 0, withCriticalVulns: 0, kev: 0, noOwner: 0, thirdParty: 0, byProvider: {}, ccmControls: 0, ccmDomains: 0 } };
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSET'").get()) return empty;
  const ac = cols("XORCISM", "ASSET");
  const sel = (c: string): string => (ac.has(c) ? c : `NULL AS ${c}`);
  const tw = tenant != null && ac.has("TenantID") ? `WHERE (TenantID = ${tenant} OR TenantID IS NULL)` : "";
  const assets = xo.prepare(
    `SELECT AssetID, AssetName, ${sel("AssetCriticalityLevel")}, ${sel("OSName")}, ${sel("hostname")},
            ${sel("ipaddressIPv4")}, ${sel("cloud")}, ${sel("hostedbythirdparty")}, ${sel("isEncrypted")},
            ${sel("PublicFacing")}, ${sel("HostPII")}, ${sel("AssetOwnershipID")}
     FROM ASSET ${tw}`
  ).all() as Record<string, any>[];

  // tags per asset
  const tagsBy = new Map<number, string[]>();
  if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETTAG'").get()) {
    for (const t of xo.prepare("SELECT AssetID, Tag FROM ASSETTAG").all() as { AssetID: number; Tag: string }[]) {
      const a = tagsBy.get(Number(t.AssetID)); if (a) a.push(String(t.Tag)); else tagsBy.set(Number(t.AssetID), [String(t.Tag)]);
    }
  }

  const isCloud = (a: Record<string, any>): boolean => {
    if (truthy(a.cloud)) return true;
    const tags = tagsBy.get(Number(a.AssetID)) || [];
    if (tags.some((t) => CLOUD_TAGS.test(t.trim()))) return true;
    if (truthy(a.hostedbythirdparty) && (CLOUD_HOST.test(String(a.hostname ?? "")) || tags.some((t) => /saas|cloud/i.test(t)))) return true;
    if (CLOUD_HOST.test(String(a.hostname ?? "")) || CLOUD_HOST.test(String(a.OSName ?? ""))) return true;
    return false;
  };
  const cloud = assets.filter(isCloud);
  if (!cloud.length) {
    const ccm = ccmRef();
    return { ...empty, summary: { ...empty.summary, ccmControls: ccm.controls, ccmDomains: ccm.domains } };
  }

  // cross-DB vuln enrichment (KEV / critical per asset)
  const vulnBy = new Map<number, { total: number; critical: number; kev: number }>();
  if (xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ASSETVULNERABILITY'").get()) {
    const avTw = tenant != null && cols("XORCISM", "ASSETVULNERABILITY").has("TenantID") ? `AND (TenantID = ${tenant} OR TenantID IS NULL)` : "";
    const links = xo.prepare(`SELECT AssetID, VulnerabilityID FROM ASSETVULNERABILITY WHERE VulnerabilityID IS NOT NULL ${avTw}`).all() as { AssetID: number; VulnerabilityID: number }[];
    const cloudIds = new Set(cloud.map((a) => Number(a.AssetID)));
    const relevant = links.filter((l) => cloudIds.has(Number(l.AssetID)));
    const vids = [...new Set(relevant.map((l) => Number(l.VulnerabilityID)))];
    const meta = new Map<number, { kev: boolean; cvss: number | null }>();
    const vc = cols("XVULNERABILITY", "VULNERABILITY");
    if (vids.length && vc.size) {
      const xv = getDb("XVULNERABILITY");
      const g = (c: string): string => (vc.has(c) ? c : `NULL AS ${c}`);
      for (let i = 0; i < vids.length; i += 400) {
        const ch = vids.slice(i, i + 400);
        for (const r of xv.prepare(`SELECT VulnerabilityID, ${g("KEV")}, ${g("CVSSBaseScore")} FROM VULNERABILITY WHERE VulnerabilityID IN (${ch.map(() => "?").join(",")})`).all(...ch) as Record<string, any>[])
          meta.set(Number(r.VulnerabilityID), { kev: truthy(r.KEV), cvss: r.CVSSBaseScore != null && r.CVSSBaseScore !== "" ? Number(r.CVSSBaseScore) : null });
      }
    }
    for (const l of relevant) {
      const aid = Number(l.AssetID); const m = meta.get(Number(l.VulnerabilityID));
      const e = vulnBy.get(aid) || { total: 0, critical: 0, kev: 0 };
      e.total++; if (m?.kev) e.kev++; if (m && m.cvss != null && m.cvss >= 9) e.critical++;
      vulnBy.set(aid, e);
    }
  }

  const rows = cloud.map((a) => {
    const id = Number(a.AssetID);
    const tags = tagsBy.get(id) || [];
    const provider = providerOf(tags, String(a.hostname ?? ""), String(a.OSName ?? ""));
    const v = vulnBy.get(id) || { total: 0, critical: 0, kev: 0 };
    const publicFacing = truthy(a.PublicFacing);
    const encrypted = truthy(a.isEncrypted);
    const crit = String(a.AssetCriticalityLevel ?? "").trim();
    const critical = critRank(crit) >= 4;
    const pii = truthy(a.HostPII);
    const owner = a.AssetOwnershipID != null && String(a.AssetOwnershipID) !== "";
    const flags: string[] = [];
    let score = 0;
    if (publicFacing && (v.kev || v.critical)) { flags.push("Internet-facing with KEV/critical vuln"); score += 50; }
    if (publicFacing && !encrypted) { flags.push("Public-facing & unencrypted"); score += 25; }
    if (pii && !encrypted) { flags.push("Holds PII without encryption"); score += 25; }
    if (critical && !encrypted) { flags.push("Business-critical & unencrypted"); score += 15; }
    if (!owner) { flags.push("No owner"); score += 8; }
    if (v.kev) score += 15;
    score += v.critical * 5 + critRank(crit) * 2 + (publicFacing ? 5 : 0);
    return { id, name: String(a.AssetName ?? `#${id}`), provider, criticality: crit, publicFacing, encrypted, pii,
      hostname: String(a.hostname ?? ""), ip: String(a.ipaddressIPv4 ?? ""), thirdParty: truthy(a.hostedbythirdparty),
      owner, tags: tags.slice(0, 6), vulns: v.total, criticalVulns: v.critical, kev: v.kev, flags, score: Math.min(100, score) };
  });
  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  const byProvider: Record<string, number> = {};
  for (const r of rows) byProvider[r.provider as string] = (byProvider[r.provider as string] || 0) + 1;
  const worklist = rows.filter((r) => r.flags.length).map((r) => ({
    id: r.id, name: r.name, provider: r.provider, severity: r.score >= 50 ? "Critical" : r.score >= 25 ? "High" : r.score >= 10 ? "Medium" : "Low",
    reason: r.flags[0], flags: r.flags, score: r.score,
  })).slice(0, 200);
  const ccm = ccmRef();

  return {
    rows, worklist,
    summary: {
      cloudAssets: rows.length,
      publicFacing: rows.filter((r) => r.publicFacing).length,
      unencrypted: rows.filter((r) => !r.encrypted).length,
      criticalAssets: rows.filter((r) => critRank(r.criticality) >= 4).length,
      withCriticalVulns: rows.filter((r) => r.criticalVulns > 0).length,
      kev: rows.filter((r) => r.kev > 0).length,
      noOwner: rows.filter((r) => !r.owner).length,
      thirdParty: rows.filter((r) => r.thirdParty).length,
      byProvider, ccmControls: ccm.controls, ccmDomains: ccm.domains,
    },
  };
}

// ── AWS compliance checker (CIS AWS Foundations subset) ─────────────────────────
// Evaluates a posture snapshot (account password policy, IAM users incl. MFA / access keys / last
// activity, root account, CloudTrail trails, AWS Config recorders) against the CIS AWS Foundations
// Benchmark checks the user asked for (password policy, MFA for IAM users, root access keys, inactive
// users 90d, key rotation, CloudTrail & AWS Config enablement). Produces CLOUDFINDING rows. The
// snapshot is produced by the aws-config / aws-cloudtrail connectors (or AWS CLI) and uploaded.
import { randomUUID } from "crypto";

export interface AwsAccessKey { active?: boolean; last_rotated_days?: number | null; last_used_days?: number | null }
export interface AwsUser {
  user: string; mfa?: boolean; console_access?: boolean;
  access_keys?: AwsAccessKey[]; password_last_used_days?: number | null; password_enabled?: boolean;
}
export interface AwsSnapshot {
  account?: string;
  password_policy?: {
    MinimumPasswordLength?: number; RequireSymbols?: boolean; RequireNumbers?: boolean;
    RequireUppercaseCharacters?: boolean; RequireLowercaseCharacters?: boolean;
    MaxPasswordAge?: number; PasswordReusePrevention?: number; ExpirePasswords?: boolean;
  } | null;
  root_account?: { mfa_enabled?: boolean; hardware_mfa?: boolean; access_keys?: number; password_last_used_days?: number | null };
  users?: AwsUser[];
  cloudtrail?: { trails?: { name?: string; is_multi_region?: boolean; log_file_validation?: boolean; cloudwatch_logs?: boolean; is_logging?: boolean; kms_encrypted?: boolean }[] };
  config?: { recorders?: { name?: string; recording?: boolean; all_regions?: boolean; all_supported?: boolean }[] };
}

export interface CloudFinding { checkId: string; title: string; service: string; category: string; severity: "Critical" | "High" | "Medium" | "Low" | "Info"; status: "pass" | "fail" | "info"; resource: string; detail: string; remediation: string; benchmark: string; }
export interface CloudCheckResult { account: string; provider: string; summary: { pass: number; fail: number; info: number; score: number; bySeverity: Record<string, number> }; findings: CloudFinding[]; }

const INACTIVE_DAYS = 90;     // user asked: inactive users (90 days)
const KEY_ROTATE_DAYS = 90;   // CIS: rotate access keys every 90 days

/** Evaluate an AWS posture snapshot → findings, and persist them to CLOUDFINDING (replacing the account's previous scan). */
export function evaluateAwsCompliance(snap: AwsSnapshot, tenant: number | null, opts: { persist?: boolean } = {}): CloudCheckResult {
  const account = String(snap.account || "unknown");
  const F: CloudFinding[] = [];
  const add = (checkId: string, title: string, service: string, severity: CloudFinding["severity"], ok: boolean, resource: string, detail: string, remediation: string, benchmark = "CIS AWS Foundations"): void => {
    F.push({ checkId, title, service, category: service, severity, status: ok ? "pass" : "fail", resource, detail, remediation, benchmark });
  };

  // ── IAM password policy ──
  const pp = snap.password_policy;
  if (pp !== undefined) {
    if (!pp) add("1.8", "IAM password policy is set", "IAM", "Medium", false, account, "No account password policy is configured.", "Create an IAM account password policy.");
    else {
      add("1.8", "Password minimum length >= 14", "IAM", "Medium", (pp.MinimumPasswordLength ?? 0) >= 14, account, `MinimumPasswordLength = ${pp.MinimumPasswordLength ?? 0}`, "Set the minimum password length to 14 or more.");
      add("1.9", "Password reuse prevention >= 24", "IAM", "Low", (pp.PasswordReusePrevention ?? 0) >= 24, account, `PasswordReusePrevention = ${pp.PasswordReusePrevention ?? 0}`, "Prevent reuse of the last 24 passwords.");
      add("1.7", "Password requires symbols, numbers, upper & lower case", "IAM", "Low", !!(pp.RequireSymbols && pp.RequireNumbers && pp.RequireUppercaseCharacters && pp.RequireLowercaseCharacters), account, `symbols=${!!pp.RequireSymbols} numbers=${!!pp.RequireNumbers} upper=${!!pp.RequireUppercaseCharacters} lower=${!!pp.RequireLowercaseCharacters}`, "Require all four character classes.");
    }
  }

  // ── Root account ──
  const root = snap.root_account;
  if (root !== undefined && root) {
    add("1.5", "Root account MFA enabled", "IAM", "Critical", !!root.mfa_enabled, "root", root.mfa_enabled ? "Root MFA enabled." : "Root account has no MFA.", "Enable MFA on the root account.");
    add("1.4", "No root account access keys", "IAM", "Critical", (root.access_keys ?? 0) === 0, "root", `Root access keys = ${root.access_keys ?? 0}`, "Delete all root account access keys.");
  }

  // ── IAM users: MFA / inactive / key rotation ──
  const users = snap.users;
  if (Array.isArray(users)) {
    const consoleUsers = users.filter((u) => u.console_access || u.password_enabled);
    const noMfa = consoleUsers.filter((u) => !u.mfa);
    if (!consoleUsers.length) add("1.10", "MFA enabled for all IAM console users", "IAM", "High", true, account, "No console users.", "n/a");
    else if (!noMfa.length) add("1.10", "MFA enabled for all IAM console users", "IAM", "High", true, account, `All ${consoleUsers.length} console users have MFA.`, "n/a");
    else for (const u of noMfa) add("1.10", "MFA enabled for IAM console user", "IAM", "High", false, u.user, `User '${u.user}' has console access without MFA.`, "Enable an MFA device for this user.");

    const inactive = users.filter((u) => {
      const pUsed = u.password_last_used_days;
      const keyUsed = Math.min(...(u.access_keys || []).filter((k) => k.active).map((k) => k.last_used_days ?? 1e9), 1e9);
      const lastActivity = Math.min(pUsed == null ? 1e9 : pUsed, keyUsed);
      return lastActivity > INACTIVE_DAYS && lastActivity < 1e9;
    });
    if (!inactive.length) add("1.12", `No IAM users inactive > ${INACTIVE_DAYS} days`, "IAM", "Medium", true, account, "No stale users.", "n/a");
    else for (const u of inactive) add("1.12", `IAM user inactive > ${INACTIVE_DAYS} days`, "IAM", "Medium", false, u.user, `User '${u.user}' has not been active in over ${INACTIVE_DAYS} days.`, "Disable or remove credentials of inactive users.");

    const staleKeys: { user: string; days: number }[] = [];
    for (const u of users) for (const k of u.access_keys || []) if (k.active && (k.last_rotated_days ?? 0) > KEY_ROTATE_DAYS) staleKeys.push({ user: u.user, days: k.last_rotated_days! });
    if (!staleKeys.length) add("1.14", `Access keys rotated within ${KEY_ROTATE_DAYS} days`, "IAM", "Medium", true, account, "No stale access keys.", "n/a");
    else for (const s of staleKeys) add("1.14", `Access key older than ${KEY_ROTATE_DAYS} days`, "IAM", "Medium", false, s.user, `An active access key for '${s.user}' is ${s.days} days old.`, "Rotate the access key.");
  }

  // ── CloudTrail ──
  const ct = snap.cloudtrail;
  if (ct !== undefined) {
    const trails = ct.trails || [];
    const multiRegion = trails.filter((t) => t.is_multi_region && (t.is_logging ?? true));
    add("3.1", "CloudTrail enabled in all regions", "CloudTrail", "High", multiRegion.length > 0, account, multiRegion.length ? `${multiRegion.length} multi-region trail(s) logging.` : "No multi-region CloudTrail trail is logging.", "Create a multi-region CloudTrail trail.");
    add("3.2", "CloudTrail log file validation enabled", "CloudTrail", "Medium", trails.some((t) => t.log_file_validation), account, trails.some((t) => t.log_file_validation) ? "Log file validation on." : "No trail has log-file validation.", "Enable log file validation on the trail.");
    add("3.4", "CloudTrail integrated with CloudWatch Logs", "CloudTrail", "Low", trails.some((t) => t.cloudwatch_logs), account, trails.some((t) => t.cloudwatch_logs) ? "CloudWatch Logs integrated." : "No trail delivers to CloudWatch Logs.", "Send CloudTrail to a CloudWatch Logs group for alerting.");
    add("3.7", "CloudTrail logs encrypted with KMS", "CloudTrail", "Low", trails.length ? trails.some((t) => t.kms_encrypted) : false, account, trails.some((t) => t.kms_encrypted) ? "KMS encryption on." : "Trails not KMS-encrypted.", "Encrypt CloudTrail logs with a KMS CMK.");
  }

  // ── AWS Config ──
  const cfg = snap.config;
  if (cfg !== undefined) {
    const rec = cfg.recorders || [];
    const allRegions = rec.filter((r) => r.recording && (r.all_regions ?? r.all_supported));
    add("3.5", "AWS Config enabled in all regions", "AWS Config", "High", allRegions.length > 0, account, allRegions.length ? `${allRegions.length} recorder(s) recording all regions.` : "No AWS Config recorder is recording all regions.", "Enable an all-regions AWS Config recorder.");
  }

  const fails = F.filter((f) => f.status === "fail");
  const bySeverity: Record<string, number> = {};
  for (const f of fails) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const total = F.length || 1;
  const score = Math.round((F.filter((f) => f.status === "pass").length / total) * 100);
  const result: CloudCheckResult = { account, provider: "AWS", summary: { pass: F.filter((f) => f.status === "pass").length, fail: fails.length, info: F.filter((f) => f.status === "info").length, score, bySeverity }, findings: F };

  if (opts.persist !== false) persistFindings("AWS", account, tenant, F);
  return result;
}

// Shared roll-up + persist (used by the Azure/GCP evaluators; AWS inlines its own equivalent).
function finalize(provider: string, account: string, F: CloudFinding[], tenant: number | null, opts: { persist?: boolean }): CloudCheckResult {
  const fails = F.filter((f) => f.status === "fail");
  const bySeverity: Record<string, number> = {};
  for (const f of fails) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const scored = F.filter((f) => f.status !== "info").length;
  const passN = F.filter((f) => f.status === "pass").length;
  const result: CloudCheckResult = { account, provider, summary: { pass: passN, fail: fails.length, info: F.filter((f) => f.status === "info").length, score: scored ? Math.round((passN / scored) * 100) : 0, bySeverity }, findings: F };
  if (opts.persist !== false) persistFindings(provider, account, tenant, F);
  return result;
}

export interface AzureSnapshot {
  tenant?: string; security_defaults_enabled?: boolean; legacy_auth_blocked?: boolean;
  password_policy?: { min_length?: number; complexity?: boolean; expiry_days?: number } | null;
  users?: { user: string; mfa?: boolean; admin?: boolean; guest?: boolean; last_sign_in_days?: number | null }[];
}
/** Evaluate an Entra ID / Azure posture snapshot → CLOUDFINDING (CIS Microsoft Azure Foundations subset). */
export function evaluateAzureCompliance(snap: AzureSnapshot, tenant: number | null, opts: { persist?: boolean } = {}): CloudCheckResult {
  const account = String(snap.tenant || "azure-tenant");
  const F: CloudFinding[] = [];
  const add = (checkId: string, title: string, severity: CloudFinding["severity"], ok: boolean, resource: string, detail: string, remediation: string): void =>
    void F.push({ checkId, title, service: "Entra ID", category: "Identity", severity, status: ok ? "pass" : "fail", resource, detail, remediation, benchmark: "CIS Microsoft Azure Foundations" });
  if (snap.security_defaults_enabled !== undefined)
    add("AZ-1.1", "Security defaults / MFA enforcement enabled", "High", !!snap.security_defaults_enabled, account, snap.security_defaults_enabled ? "Security defaults or an MFA Conditional Access policy is enabled." : "Security defaults disabled and no MFA enforcement.", "Enable security defaults or a Conditional Access policy requiring MFA.");
  const pp = snap.password_policy;
  if (pp !== undefined) {
    if (!pp) add("AZ-1.2", "Password policy is set", "Medium", false, account, "No password policy configured.", "Configure Entra password protection.");
    else add("AZ-1.2", "Password minimum length >= 14", "Medium", (pp.min_length ?? 0) >= 14, account, `MinimumPasswordLength = ${pp.min_length ?? 0}`, "Set a minimum password length of 14 or more.");
  }
  if (snap.legacy_auth_blocked !== undefined)
    add("AZ-1.3", "Legacy authentication blocked", "High", !!snap.legacy_auth_blocked, account, snap.legacy_auth_blocked ? "Legacy authentication blocked." : "Legacy authentication is allowed (bypasses MFA).", "Block legacy authentication via Conditional Access.");
  const users = snap.users;
  if (Array.isArray(users)) {
    const admins = users.filter((u) => u.admin), adminNoMfa = admins.filter((u) => !u.mfa);
    if (!admins.length) add("AZ-2.1", "MFA enabled for privileged users", "Critical", true, account, "No privileged users.", "n/a");
    else if (!adminNoMfa.length) add("AZ-2.1", "MFA enabled for privileged users", "Critical", true, account, `All ${admins.length} privileged users have MFA.`, "n/a");
    else for (const u of adminNoMfa) add("AZ-2.1", "MFA enabled for privileged user", "Critical", false, u.user, `Admin '${u.user}' has no MFA.`, "Require MFA for this administrator.");
    const noMfa = users.filter((u) => !u.mfa && !u.guest);
    if (!noMfa.length) add("AZ-2.2", "MFA enabled for all users", "High", true, account, "All users have MFA.", "n/a");
    else for (const u of noMfa.slice(0, 300)) add("AZ-2.2", "MFA enabled for user", "High", false, u.user, `User '${u.user}' has no MFA.`, "Enable MFA for this user.");
    const inactive = users.filter((u) => (u.last_sign_in_days ?? 0) > INACTIVE_DAYS);
    if (!inactive.length) add("AZ-3.1", `No inactive users > ${INACTIVE_DAYS} days`, "Medium", true, account, "No stale users.", "n/a");
    else for (const u of inactive.slice(0, 300)) add("AZ-3.1", `Inactive user > ${INACTIVE_DAYS} days`, "Medium", false, u.user, `User '${u.user}' inactive > ${INACTIVE_DAYS} days.`, "Disable or remove inactive accounts.");
  }
  return finalize("Azure", account, F, tenant, opts);
}

export interface GcpSnapshot {
  project?: string;
  users?: { user: string; mfa?: boolean; two_step?: boolean; admin?: boolean; last_login_days?: number | null }[];
  service_accounts?: { name: string; user_managed_keys?: number; oldest_key_age_days?: number | null }[];
  primitive_owner_bindings?: number;
}
/** Evaluate a Google Cloud posture snapshot → CLOUDFINDING (CIS GCP Foundations subset). */
export function evaluateGcpCompliance(snap: GcpSnapshot, tenant: number | null, opts: { persist?: boolean } = {}): CloudCheckResult {
  const account = String(snap.project || "gcp-project");
  const F: CloudFinding[] = [];
  const add = (checkId: string, title: string, severity: CloudFinding["severity"], ok: boolean, resource: string, detail: string, remediation: string, service = "IAM"): void =>
    void F.push({ checkId, title, service, category: service, severity, status: ok ? "pass" : "fail", resource, detail, remediation, benchmark: "CIS Google Cloud Foundations" });
  const has2sv = (u: { mfa?: boolean; two_step?: boolean }): boolean => !!(u.mfa || u.two_step);
  const users = snap.users;
  if (Array.isArray(users)) {
    const admins = users.filter((u) => u.admin), adminNo = admins.filter((u) => !has2sv(u));
    if (!admins.length) add("GCP-1.1", "MFA enabled for privileged users", "Critical", true, account, "No privileged users.", "n/a");
    else if (!adminNo.length) add("GCP-1.1", "MFA enabled for privileged users", "Critical", true, account, `All ${admins.length} admins enforce 2-Step Verification.`, "n/a");
    else for (const u of adminNo) add("GCP-1.1", "MFA enabled for privileged user", "Critical", false, u.user, `Admin '${u.user}' has no 2-Step Verification (MFA).`, "Enforce 2-Step Verification.");
    const no2 = users.filter((u) => !has2sv(u));
    if (!no2.length) add("GCP-1.2", "MFA enabled for all users", "High", true, account, "All users enforce 2-Step Verification.", "n/a");
    else for (const u of no2.slice(0, 300)) add("GCP-1.2", "MFA enabled for user", "High", false, u.user, `User '${u.user}' has no 2-Step Verification (MFA).`, "Enforce 2-Step Verification.");
    const inactive = users.filter((u) => (u.last_login_days ?? 0) > INACTIVE_DAYS);
    if (!inactive.length) add("GCP-3.1", `No inactive users > ${INACTIVE_DAYS} days`, "Medium", true, account, "No stale users.", "n/a");
    else for (const u of inactive.slice(0, 300)) add("GCP-3.1", `Inactive user > ${INACTIVE_DAYS} days`, "Medium", false, u.user, `User '${u.user}' inactive > ${INACTIVE_DAYS} days.`, "Disable inactive accounts.");
  }
  const sas = snap.service_accounts;
  if (Array.isArray(sas)) {
    const withKeys = sas.filter((s) => (s.user_managed_keys ?? 0) > 0);
    if (!withKeys.length) add("GCP-2.1", "No user-managed service account keys", "High", true, account, "No user-managed service-account keys.", "n/a");
    else for (const s of withKeys) add("GCP-2.1", "User-managed service account keys present", "High", false, s.name, `SA '${s.name}' has ${s.user_managed_keys} user-managed key(s).`, "Avoid user-managed keys; use workload identity.");
    const stale = sas.filter((s) => (s.oldest_key_age_days ?? 0) > KEY_ROTATE_DAYS);
    if (!stale.length) add("GCP-2.2", `Service account key rotation <= ${KEY_ROTATE_DAYS} days`, "Medium", true, account, "All service-account keys within the rotation window.", "n/a");
    else for (const s of stale) add("GCP-2.2", `Service account key rotation > ${KEY_ROTATE_DAYS} days`, "Medium", false, s.name, `SA '${s.name}' oldest key is ${s.oldest_key_age_days} days old.`, "Rotate service-account keys.");
  }
  if (snap.primitive_owner_bindings !== undefined)
    add("GCP-4.1", "No primitive Owner role bindings", "High", (snap.primitive_owner_bindings ?? 0) === 0, account, `Primitive Owner bindings = ${snap.primitive_owner_bindings ?? 0}`, "Replace primitive Owner with least-privilege roles.");
  return finalize("GCP", account, F, tenant, opts);
}

function persistFindings(provider: string, account: string, tenant: number | null, findings: CloudFinding[]): void {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CLOUDFINDING'").get()) return;
  const now = new Date().toISOString();
  const tx = xo.transaction(() => {
    xo.prepare("DELETE FROM CLOUDFINDING WHERE Provider = ? AND Account = ? AND TenantID IS ?").run(provider, account, tenant);
    const maxRow = xo.prepare("SELECT COALESCE(MAX(CloudFindingID),0) m FROM CLOUDFINDING").get() as { m: number };
    let id = Number(maxRow.m);
    const insert = xo.prepare(`INSERT INTO CLOUDFINDING (CloudFindingID, FindingGUID, Provider, Account, CheckID, Title, Service, Category, Severity, Status, Resource, Detail, Remediation, Benchmark, ScanDate, TenantID, CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    for (const f of findings) {
      insert.run(++id, randomUUID(), provider, account, f.checkId, f.title, f.service, f.category, f.severity, f.status, f.resource, f.detail, f.remediation, f.benchmark, now, tenant, now);
    }
  });
  tx();
}

/** Stored cloud-compliance findings + summary for the /cloud-security page. */
export function cloudComplianceView(tenant: number | null): { findings: Record<string, unknown>[]; summary: Record<string, unknown> } {
  const xo = getDb("XORCISM");
  if (!xo.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CLOUDFINDING'").get()) return { findings: [], summary: { pass: 0, fail: 0, accounts: 0, score: null, byService: {}, bySeverity: {}, scanDate: null } };
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = xo.prepare(`SELECT Provider, Account, CheckID, Title, Service, Severity, Status, Resource, Detail, Remediation, Benchmark, ScanDate FROM CLOUDFINDING ${tw} ORDER BY (Status='fail') DESC, CASE Severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, CheckID`).all(...(tenant != null ? [tenant] : [])) as Record<string, unknown>[];
  const pass = rows.filter((r) => r.Status === "pass").length;
  const fail = rows.filter((r) => r.Status === "fail").length;
  const byService: Record<string, { pass: number; fail: number }> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of rows) {
    const s = String(r.Service || "Other"); byService[s] = byService[s] || { pass: 0, fail: 0 };
    if (r.Status === "pass") byService[s].pass++; else if (r.Status === "fail") { byService[s].fail++; bySeverity[String(r.Severity)] = (bySeverity[String(r.Severity)] || 0) + 1; }
  }
  const accounts = new Set(rows.map((r) => String(r.Account))).size;
  const total = pass + fail;
  return { findings: rows, summary: { pass, fail, accounts, score: total ? Math.round((pass / total) * 100) : null, byService, bySeverity, scanDate: rows[0]?.ScanDate ?? null } };
}

/** CSA CCM coverage reference — counts from the imported CCM catalogue (import_csa_ccm.py). */
function ccmRef(): { controls: number; domains: number } {
  try {
    const xo = getDb("XORCISM");
    const vc = xo.prepare("SELECT VocabularyID FROM VOCABULARY WHERE VocabularyName = 'CSA CCM'").get() as { VocabularyID: number } | undefined;
    if (!vc) return { controls: 0, domains: 0 };
    const controls = (xo.prepare("SELECT COUNT(*) c FROM CONTROL WHERE VocabularyID = ?").get(vc.VocabularyID) as { c: number }).c;
    const ids = xo.prepare("SELECT CIS FROM CONTROL WHERE VocabularyID = ? AND CIS IS NOT NULL").all(vc.VocabularyID) as { CIS: string }[];
    const domains = new Set(ids.map((r) => String(r.CIS).split("-")[0])).size;
    return { controls, domains };
  } catch { return { controls: 0, domains: 0 }; }
}
