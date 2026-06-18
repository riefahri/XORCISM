/**
 * identities.ts — Identity & Access Management (IAM) inventory + risk worklist.
 *
 * One pane over BOTH human identities (mapped to PERSON through IDENTITYPERSON)
 * and non-human identities / NHI (AI agents, APIs, containers, service accounts,
 * hardcoded credentials, certificates, devices, workloads…). It resolves each
 * identity's accountable owner and bound asset, then derives the governance
 * findings a security team actually cares about: orphaned non-human identities,
 * privileged principals, stale/unused identities, expiring or never-rotated
 * credentials, hardcoded secrets, and privileged humans missing MFA.
 *
 * Read-only; IDENTITY / IDENTITYPERSON CRUD is the schema-driven explorer.
 */
import { getDb } from "./db";

export interface IdentityRow {
  id: number;
  name: string;
  type: string;
  klass: "Human" | "Non-Human";
  status: string;
  owner: string | null;            // resolved PERSON.FullName (or external owner ref)
  asset: string | null;            // resolved bound ASSET.AssetName
  provider: string;
  privilege: string;
  environment: string;
  credentialType: string;
  mfa: string;
  risk: string;                    // stored RiskLevel (free text)
  expiry: string | null;          // YYYY-MM-DD
  lastUsed: string | null;
  lastRotated: string | null;
  persons: number;                 // count of mapped PERSON rows (IDENTITYPERSON)
  flags: string[];                 // derived governance findings
  score: number;                   // 0-100 derived risk priority
}

export interface IdentityFinding {
  kind: string;                    // category key (orphaned, privileged, stale…)
  label: string;                   // human-readable
  severity: "Critical" | "High" | "Medium" | "Low";
  identityId: number;
  identity: string;
}

export interface IdentityInventory {
  rows: IdentityRow[];
  findings: IdentityFinding[];
  summary: {
    total: number; human: number; nonHuman: number;
    privileged: number; orphaned: number; stale: number;
    expiring: number; hardcoded: number; compromised: number; mfaGaps: number;
    byType: Record<string, number>;
    byClass: Record<string, number>;
  };
}

const EMPTY: IdentityInventory = {
  rows: [], findings: [],
  summary: { total: 0, human: 0, nonHuman: 0, privileged: 0, orphaned: 0, stale: 0, expiring: 0, hardcoded: 0, compromised: 0, mfaGaps: 0, byType: {}, byClass: {} },
};

const STALE_DAYS = 90;             // unused for longer → candidate for deprovisioning
const EXPIRY_WARN_DAYS = 30;       // credential expiring within → warn
const ROTATION_MAX_DAYS = 365;     // secret older than → "never/stale rotation"
const PRIVILEGED = new Set(["privileged", "admin", "administrator", "root", "owner", "superuser"]);
const HUMAN_TYPES = new Set(["human", "user", "employee", "person", "contractor"]);
const SECRET_CREDS = new Set(["password", "api key", "apikey", "ssh key", "token", "secret", "oauth secret"]);

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}

function daysSince(date: string | null): number | null {
  if (!date) return null;
  const t = Date.parse(String(date));
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

const d10 = (v: unknown): string | null => (v ? String(v).slice(0, 10) : null);

/** Full IAM inventory with resolved owners/assets + derived governance findings. */
export function identityInventory(tenant: number | null): IdentityInventory {
  const db = getDb("XORCISM");
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='IDENTITY'").get()) return { ...EMPTY };

  const ic = cols("IDENTITY");
  const has = (c: string): boolean => ic.has(c);
  const tw = tenant != null && ic.has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
  const ids = db.prepare(`SELECT * FROM IDENTITY ${tw}`).all() as Record<string, unknown>[];
  if (!ids.length) return { ...EMPTY };

  // Resolve owner (PERSON.FullName) + bound asset (ASSET.AssetName).
  const persons = new Map<number, string>();
  if (cols("PERSON").has("FullName")) {
    for (const p of db.prepare(`SELECT PersonID, FullName FROM PERSON`).all() as { PersonID: number; FullName: string }[]) persons.set(Number(p.PersonID), p.FullName);
  }
  const assets = new Map<number, string>();
  if (cols("ASSET").has("AssetName")) {
    for (const a of db.prepare(`SELECT AssetID, AssetName FROM ASSET`).all() as { AssetID: number; AssetName: string }[]) assets.set(Number(a.AssetID), a.AssetName);
  }
  // Count PERSON mappings per identity (human linkage via IDENTITYPERSON).
  const mapCount = new Map<number, number>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='IDENTITYPERSON'").get()) {
    const ipw = tenant != null && cols("IDENTITYPERSON").has("TenantID") ? `WHERE TenantID = ${tenant}` : "";
    for (const r of db.prepare(`SELECT IdentityID, COUNT(*) n FROM IDENTITYPERSON ${ipw} GROUP BY IdentityID`).all() as { IdentityID: number; n: number }[]) {
      mapCount.set(Number(r.IdentityID), Number(r.n));
    }
  }

  const findings: IdentityFinding[] = [];
  const rows: IdentityRow[] = ids.map((r) => {
    const id = Number(r.IdentityID);
    const type = String(r.IdentityType ?? "").trim() || "Unknown";
    const explicitClass = String(r.IdentityClass ?? "").trim();
    const klass: "Human" | "Non-Human" = explicitClass
      ? (/human/i.test(explicitClass) && !/non/i.test(explicitClass) ? "Human" : "Non-Human")
      : (HUMAN_TYPES.has(type.toLowerCase()) ? "Human" : "Non-Human");
    const status = String(r.Status ?? "").trim() || "Active";
    const privilege = String(r.PrivilegeLevel ?? "").trim();
    const credType = String(r.CredentialType ?? "").trim();
    const mfa = String(r.MFAEnabled ?? "").trim();
    const ownerId = r.OwnerPersonID != null ? Number(r.OwnerPersonID) : null;
    const owner = ownerId != null ? (persons.get(ownerId) ?? `#${ownerId}`) : null;
    const assetId = r.AssetID != null ? Number(r.AssetID) : null;
    const asset = assetId != null ? (assets.get(assetId) ?? `#${assetId}`) : null;
    const expiry = d10(r.ExpiryDate);
    const lastUsed = d10(r.LastUsedDate);
    const lastRotated = d10(r.LastRotatedDate);
    const name = String(r.IdentityName ?? "").trim() || `Identity #${id}`;
    const nPersons = mapCount.get(id) ?? 0;

    const isPriv = PRIVILEGED.has(privilege.toLowerCase());
    const isSecret = SECRET_CREDS.has(credType.toLowerCase()) || /hardcoded|credential|certificate|key|token|secret/i.test(type);
    const flags: string[] = [];
    let score = 0;
    const add = (kind: string, label: string, severity: IdentityFinding["severity"], pts: number): void => {
      flags.push(label); score += pts;
      findings.push({ kind, label: `${name}: ${label}`, severity, identityId: id, identity: name });
    };

    if (/compromis|breach/i.test(status)) add("compromised", "Compromised", "Critical", 50);
    if (klass === "Non-Human" && ownerId == null && nPersons === 0) add("orphaned", "Orphaned — no accountable owner", "High", 25);
    if (isPriv) add("privileged", `Privileged (${privilege})`, "High", 20);
    if (/hardcoded/i.test(type)) add("hardcoded", "Hardcoded credential", "Critical", 30);

    const expDays = expiry != null ? -1 * (daysSince(expiry) ?? 0) : null; // days until expiry (negative = expired)
    if (expDays != null && expDays < 0) add("expired", `Credential expired ${-expDays}d ago`, "High", 25);
    else if (expDays != null && expDays <= EXPIRY_WARN_DAYS) add("expiring", `Credential expires in ${expDays}d`, "Medium", 12);

    const rotAge = daysSince(lastRotated);
    if (isSecret && (lastRotated == null || (rotAge != null && rotAge > ROTATION_MAX_DAYS))) {
      add("rotation", lastRotated == null ? "Secret never rotated" : `Secret not rotated for ${rotAge}d`, "Medium", isPriv ? 15 : 8);
    }
    const useAge = daysSince(lastUsed);
    if (/active/i.test(status) && useAge != null && useAge > STALE_DAYS) add("stale", `Unused for ${useAge}d`, "Medium", 10);

    if (klass === "Human" && isPriv && mfa && !/^(y|yes|true|enabled|on)$/i.test(mfa)) add("mfa", "Privileged human without MFA", "High", 20);

    return {
      id, name, type, klass, status, owner, asset,
      provider: String(r.Provider ?? "").trim(), privilege, environment: String(r.Environment ?? "").trim(),
      credentialType: credType, mfa, risk: String(r.RiskLevel ?? "").trim(),
      expiry, lastUsed, lastRotated, persons: nPersons, flags, score: Math.min(100, score),
    };
  });

  rows.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const sevRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || a.identity.localeCompare(b.identity));

  const byType: Record<string, number> = {};
  const byClass: Record<string, number> = {};
  for (const r of rows) { byType[r.type] = (byType[r.type] || 0) + 1; byClass[r.klass] = (byClass[r.klass] || 0) + 1; }
  const countFlag = (k: string): number => rows.filter((r) => r.flags.some((f) => f.toLowerCase().includes(k))).length;

  return {
    rows, findings,
    summary: {
      total: rows.length,
      human: rows.filter((r) => r.klass === "Human").length,
      nonHuman: rows.filter((r) => r.klass === "Non-Human").length,
      privileged: rows.filter((r) => PRIVILEGED.has(r.privilege.toLowerCase())).length,
      orphaned: rows.filter((r) => r.flags.some((f) => f.startsWith("Orphaned"))).length,
      stale: countFlag("unused"),
      expiring: rows.filter((r) => r.flags.some((f) => /expire|expired/i.test(f))).length,
      hardcoded: rows.filter((r) => /hardcoded/i.test(r.type)).length,
      compromised: rows.filter((r) => /compromis|breach/i.test(r.status)).length,
      mfaGaps: countFlag("without mfa"),
      byType, byClass,
    },
  };
}
