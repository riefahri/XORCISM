/**
 * itdr.ts — Identity Threat Detection & Response (ITDR).
 *
 * The detection-and-response layer on top of the IAM inventory ([[identity-iam]]) and the sign-in
 * telemetry ([[IDENTITYSIGNIN]] ingested by entra-signin/okta-signin). Rule-based detectors run over:
 *   - IDENTITYSIGNIN — behavioral signals (brute force, password spray, impossible travel, MFA fatigue,
 *     IdP-flagged risk, successful login after a failed burst, dormant-account reactivation);
 *   - IDENTITY — posture exposures with attack relevance (MFA-less privileged, orphaned privileged,
 *     stale privileged).
 * Each detection is mapped to a MITRE ATT&CK technique (mostly Credential Access / Initial Access /
 * Persistence), carries a recommended response action, and flows through an analyst workflow
 * (open → investigating → contained → resolved | dismissed). XORCISM models & recommends response;
 * live enforcement (disable / revoke / reset) stays with the IdP — an analyst can also raise an
 * incident (XINCIDENT.ALERT) from a detection.
 *
 * Detections are persisted in XORCISM.IDENTITYDETECTION and upserted idempotently by (DedupKey,
 * TenantID); a resolved/dismissed detection is never silently reopened by a re-scan.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { geoCountry } from "./zerotrust";

const SIGNIN_WINDOW_DAYS = 7;        // behavioral detectors look back this far
const BRUTE_FAIL_THRESHOLD = 5;      // failures for one account → brute force
const SPRAY_ACCOUNT_THRESHOLD = 3;   // distinct accounts failed from one IP → password spray
const STALE_PRIV_DAYS = 90;          // privileged account unused this long → dormant exposure
const IMPOSSIBLE_TRAVEL_HOURS = 4;   // country change within this window → impossible travel

export type Severity = "critical" | "high" | "medium" | "low";
const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export interface ItdrRule {
  key: string; title: string; severity: Severity;
  tactic: string; technique: string; techniqueName: string;
  response: string; kind: "behavioral" | "posture";
}

/** The detection-rule catalogue (ATT&CK-mapped). */
export const ITDR_RULES: Record<string, ItdrRule> = {
  brute_force: {
    key: "brute_force", title: "Brute-force / password guessing", severity: "high", kind: "behavioral",
    tactic: "Credential Access", technique: "T1110.001", techniqueName: "Brute Force: Password Guessing",
    response: "Lock the account, enforce MFA, and reset the credential. Block the source IP and review for a successful follow-on sign-in.",
  },
  password_spray: {
    key: "password_spray", title: "Password spraying", severity: "high", kind: "behavioral",
    tactic: "Credential Access", technique: "T1110.003", techniqueName: "Brute Force: Password Spraying",
    response: "Block the source IP, enforce MFA tenant-wide, and reset any account that subsequently authenticated. Hunt for additional sprayed accounts.",
  },
  cred_compromise: {
    key: "cred_compromise", title: "Successful sign-in after a failed burst", severity: "critical", kind: "behavioral",
    tactic: "Initial Access", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Treat as a likely account takeover: revoke sessions & tokens, force a password reset, require MFA re-registration, and investigate post-auth activity.",
  },
  impossible_travel: {
    key: "impossible_travel", title: "Impossible travel", severity: "high", kind: "behavioral",
    tactic: "Initial Access", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Verify with the user; if unconfirmed, revoke sessions/tokens and reset credentials. Review conditional-access/geo policies.",
  },
  mfa_fatigue: {
    key: "mfa_fatigue", title: "MFA fatigue / push bombing", severity: "high", kind: "behavioral",
    tactic: "Credential Access", technique: "T1621", techniqueName: "Multi-Factor Authentication Request Generation",
    response: "Switch to number-matching / phishing-resistant MFA, reset the credential (password is likely known), and confirm with the user.",
  },
  idp_risk: {
    key: "idp_risk", title: "IdP-flagged risky sign-in", severity: "medium", kind: "behavioral",
    tactic: "Initial Access", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Investigate the risk reason from the IdP; require MFA / re-authentication and revoke sessions if the risk is confirmed.",
  },
  dormant_reactivation: {
    key: "dormant_reactivation", title: "Dormant / disabled account sign-in", severity: "high", kind: "behavioral",
    tactic: "Persistence", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Verify legitimacy; a sign-in on a disabled or long-dormant account is a strong takeover/persistence signal — disable and investigate.",
  },
  mfa_less_priv: {
    key: "mfa_less_priv", title: "Privileged identity without MFA", severity: "high", kind: "posture",
    tactic: "Credential Access", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Enforce phishing-resistant MFA on this privileged identity; it is a single-factor path to admin access.",
  },
  priv_orphaned: {
    key: "priv_orphaned", title: "Privileged identity with no owner", severity: "high", kind: "posture",
    tactic: "Persistence", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Assign an accountable owner or deprovision; an unowned privileged principal is a prime persistence / shadow-admin target.",
  },
  stale_priv: {
    key: "stale_priv", title: "Stale privileged account", severity: "medium", kind: "posture",
    tactic: "Persistence", technique: "T1078", techniqueName: "Valid Accounts",
    response: "Disable or deprovision the dormant privileged account to remove a low-noise takeover path.",
  },
  // ── Active Directory / Kerberos detectors (activate when a DC/Kerberos-log source populates
  //    IDENTITYSIGNIN.ClientApp / FailureReason — e.g. a domain-controller event connector) ──
  kerberoasting: {
    key: "kerberoasting", title: "Kerberoasting (service-ticket harvesting)", severity: "high", kind: "behavioral",
    tactic: "Credential Access", technique: "T1558.003", techniqueName: "Steal or Forge Kerberos Tickets: Kerberoasting",
    response: "Rotate the targeted service-account passwords (prefer gMSA), disable RC4 in favour of AES, and hunt for offline cracking and follow-on service-account logons.",
  },
  asrep_roasting: {
    key: "asrep_roasting", title: "AS-REP roasting", severity: "high", kind: "behavioral",
    tactic: "Credential Access", technique: "T1558.004", techniqueName: "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    response: "Re-enable Kerberos pre-authentication on the affected accounts and reset their passwords (likely harvested for offline cracking).",
  },
  dcsync: {
    key: "dcsync", title: "DCSync — directory replication from a non-DC", severity: "critical", kind: "behavioral",
    tactic: "Credential Access", technique: "T1003.006", techniqueName: "OS Credential Dumping: DCSync",
    response: "Treat as domain compromise: rotate krbtgt twice, reset privileged credentials, remove replication rights from the non-DC principal, and engage full DFIR.",
  },
  golden_ticket: {
    key: "golden_ticket", title: "Golden / forged Kerberos ticket", severity: "critical", kind: "behavioral",
    tactic: "Persistence", technique: "T1558.001", techniqueName: "Steal or Forge Kerberos Tickets: Golden Ticket",
    response: "Rotate krbtgt twice to invalidate forged tickets, reset privileged credentials, hunt for persistence, and engage full DFIR.",
  },
};

const PRIVILEGED = new Set(["privileged", "admin", "administrator", "root", "owner", "superuser"]);
const mfaOn = (s: string): boolean => /^(y|yes|true|enabled|on|1)$/i.test(String(s || "").trim());
const isOpenStatus = (s: string): boolean => !/^(resolved|dismissed)$/i.test(String(s || ""));

interface Detection {
  ruleKey: string; dedupKey: string; title: string; severity: Severity;
  identityName: string | null; identityId: number | null; sourceIP: string | null; country: string | null;
  evidence: string; eventCount: number; firstSeen: string | null; lastSeen: string | null;
}

interface SigninRow { IdentityName: string; IdentityID: number | null; Timestamp: string | null; SourceIP: string | null; Country: string | null; MFAUsed: string | null; Result: string | null; FailureReason: string | null; RiskLevel: string | null; ClientApp: string | null; }

function tableCols(db: ReturnType<typeof getDb>, table: string): Set<string> {
  try { return new Set((db.prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function dayOf(ts: string | null): string { return String(ts || "").slice(0, 10) || "?"; }
function isFail(r: SigninRow): boolean { return /fail|denied|error|block/i.test(String(r.Result || "")); }
function isSuccess(r: SigninRow): boolean { return /success|allow|ok|pass/i.test(String(r.Result || "")); }
function countryOf(r: SigninRow): string {
  const c = String(r.Country || "").trim();
  if (c) return c;
  const g = geoCountry(String(r.SourceIP || ""));
  return g || "";
}

function loadSignins(tenant: number | null): SigninRow[] {
  const db = getDb("XORCISM");
  if (!tableCols(db, "IDENTITYSIGNIN").size) return [];
  const since = new Date(Date.now() - SIGNIN_WINDOW_DAYS * 86_400_000).toISOString();
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const sql = `SELECT IdentityName, IdentityID, Timestamp, SourceIP, Country, MFAUsed, Result, FailureReason, RiskLevel, ClientApp
    FROM IDENTITYSIGNIN WHERE (Timestamp IS NULL OR Timestamp >= ?) ${w} ORDER BY IdentityName, Timestamp`;
  const args = tenant != null ? [since, tenant] : [since];
  try { return db.prepare(sql).all(...args) as SigninRow[]; } catch { return []; }
}

// ── Behavioral detectors over IDENTITYSIGNIN ─────────────────────────────────
function detectFromSignins(tenant: number | null): Detection[] {
  const rows = loadSignins(tenant);
  const out: Detection[] = [];
  if (!rows.length) return out;

  // group by identity (ordered by timestamp from the query)
  const byId = new Map<string, SigninRow[]>();
  for (const r of rows) {
    const n = String(r.IdentityName || "").trim(); if (!n) continue;
    (byId.get(n) ?? byId.set(n, []).get(n)!).push(r);
  }

  for (const [name, evs] of byId) {
    const idOf = evs.find((e) => e.IdentityID != null)?.IdentityID ?? null;
    const fails = evs.filter(isFail);
    const succ = evs.filter(isSuccess);

    // 1) Brute force — many failures for one account
    if (fails.length >= BRUTE_FAIL_THRESHOLD) {
      const ip = fails[fails.length - 1].SourceIP || null;
      out.push(det("brute_force", `brute_force|${name}|${dayOf(fails[fails.length - 1].Timestamp)}`,
        name, idOf, ip, countryOf(fails[fails.length - 1]) || null,
        `${fails.length} failed sign-ins in ${SIGNIN_WINDOW_DAYS}d (last reason: ${fails[fails.length - 1].FailureReason || "n/a"}).`,
        fails.length, fails[0].Timestamp, fails[fails.length - 1].Timestamp));
    }

    // 2) Successful sign-in after a failed burst — likely compromise
    if (fails.length >= BRUTE_FAIL_THRESHOLD - 1) {
      const lastFail = fails[fails.length - 1];
      const winningSuccess = succ.find((s) => s.Timestamp && lastFail.Timestamp && s.Timestamp >= lastFail.Timestamp);
      if (winningSuccess) {
        out.push(det("cred_compromise", `cred_compromise|${name}|${dayOf(winningSuccess.Timestamp)}`,
          name, idOf, winningSuccess.SourceIP || null, countryOf(winningSuccess) || null,
          `${fails.length} failures then a successful sign-in${mfaOn(String(winningSuccess.MFAUsed)) ? "" : " (without MFA)"} from ${winningSuccess.SourceIP || "?"}.`,
          fails.length + 1, fails[0].Timestamp, winningSuccess.Timestamp));
      }
    }

    // 3) Impossible travel — two successes, different non-internal countries within the window
    const sc = succ.filter((e) => e.Timestamp);
    for (let i = 1; i < sc.length; i++) {
      const a = sc[i - 1], b = sc[i];
      const ca = countryOf(a), cb = countryOf(b);
      const ta = Date.parse(a.Timestamp!), tb = Date.parse(b.Timestamp!);
      if (ca && cb && ca !== "Internal" && cb !== "Internal" && ca !== cb &&
          Number.isFinite(ta) && Number.isFinite(tb) && Math.abs(tb - ta) < IMPOSSIBLE_TRAVEL_HOURS * 3600e3) {
        out.push(det("impossible_travel", `impossible_travel|${name}|${dayOf(b.Timestamp)}`,
          name, idOf, b.SourceIP || null, cb,
          `Sign-ins from ${ca} then ${cb} within ${Math.round(Math.abs(tb - ta) / 60000)} min.`,
          2, a.Timestamp, b.Timestamp));
        break;
      }
    }

    // 4) MFA fatigue — repeated MFA-related failures (push bombing)
    const mfaFails = fails.filter((e) => /mfa|otp|second factor|2fa|push|authenticat/i.test(String(e.FailureReason || "")));
    if (mfaFails.length >= 3) {
      out.push(det("mfa_fatigue", `mfa_fatigue|${name}|${dayOf(mfaFails[mfaFails.length - 1].Timestamp)}`,
        name, idOf, mfaFails[mfaFails.length - 1].SourceIP || null, countryOf(mfaFails[mfaFails.length - 1]) || null,
        `${mfaFails.length} MFA challenges denied/failed — possible push-bombing.`,
        mfaFails.length, mfaFails[0].Timestamp, mfaFails[mfaFails.length - 1].Timestamp));
    }

    // 5) IdP-flagged risky sign-in (medium+ from the provider's own risk engine)
    const risky = evs.filter((e) => /high|medium/i.test(String(e.RiskLevel || "")));
    if (risky.length) {
      const top = risky.find((e) => /high/i.test(String(e.RiskLevel))) || risky[risky.length - 1];
      out.push({ ...det("idp_risk", `idp_risk|${name}|${dayOf(top.Timestamp)}`,
        name, idOf, top.SourceIP || null, countryOf(top) || null,
        `IdP flagged ${risky.length} ${/high/i.test(String(top.RiskLevel)) ? "high" : "medium"}-risk sign-in(s).`,
        risky.length, risky[0].Timestamp, top.Timestamp),
        severity: /high/i.test(String(top.RiskLevel)) ? "high" : "medium" });
    }
  }
  return out;
}

// 6) Password spray — one source IP with failures across many distinct accounts
function detectSpray(tenant: number | null): Detection[] {
  const rows = loadSignins(tenant).filter(isFail);
  const byIp = new Map<string, Set<string>>();
  const meta = new Map<string, { count: number; last: string | null; first: string | null }>();
  for (const r of rows) {
    const ip = String(r.SourceIP || "").trim(); const n = String(r.IdentityName || "").trim();
    if (!ip || !n) continue;
    (byIp.get(ip) ?? byIp.set(ip, new Set()).get(ip)!).add(n);
    const m = meta.get(ip) ?? { count: 0, last: null, first: r.Timestamp };
    m.count++; m.last = r.Timestamp; if (!m.first) m.first = r.Timestamp;
    meta.set(ip, m);
  }
  const out: Detection[] = [];
  for (const [ip, accts] of byIp) {
    if (accts.size >= SPRAY_ACCOUNT_THRESHOLD) {
      const m = meta.get(ip)!;
      out.push(det("password_spray", `password_spray|${ip}|${dayOf(m.last)}`,
        null, null, ip, geoCountry(ip) || null,
        `${m.count} failed sign-ins across ${accts.size} accounts from ${ip}: ${[...accts].slice(0, 6).join(", ")}${accts.size > 6 ? "…" : ""}.`,
        m.count, m.first, m.last));
    }
  }
  return out;
}

// ── Active Directory / Kerberos detectors ────────────────────────────────────
// Marker-based: keyed off IDENTITYSIGNIN.ClientApp / FailureReason as populated by a
// domain-controller / Kerberos-log connector (Security event IDs 4768/4769/4662, etc.).
function detectKerberos(tenant: number | null): Detection[] {
  const rows = loadSignins(tenant).filter((r) => /kerberos|krb|tgs|tgt|spn|replicat|drsuapi|dcsync|as.?rep|preauth|golden|forged/i.test(`${r.ClientApp || ""} ${r.FailureReason || ""}`));
  if (!rows.length) return [];
  const out: Detection[] = [];
  const byId = new Map<string, SigninRow[]>();
  for (const r of rows) { const n = String(r.IdentityName || "").trim(); if (n) (byId.get(n) ?? byId.set(n, []).get(n)!).push(r); }
  for (const [name, evs] of byId) {
    const idOf = evs.find((e) => e.IdentityID != null)?.IdentityID ?? null;
    const blob = (e: SigninRow) => `${e.ClientApp || ""} ${e.FailureReason || ""}`.toLowerCase();
    const last = evs[evs.length - 1];

    // DCSync — directory replication requested by a non-DC principal
    const dcs = evs.filter((e) => /replicat|drsuapi|dcsync|get.?nc.?changes/i.test(blob(e)));
    if (dcs.length) {
      out.push(det("dcsync", `dcsync|${name}|${dayOf(dcs[dcs.length - 1].Timestamp)}`, name, idOf,
        dcs[dcs.length - 1].SourceIP || null, countryOf(dcs[dcs.length - 1]) || null,
        `Directory replication (DCSync) requested by non-DC principal: ${dcs[dcs.length - 1].FailureReason || dcs[dcs.length - 1].ClientApp || "DRSUAPI"}.`,
        dcs.length, dcs[0].Timestamp, dcs[dcs.length - 1].Timestamp));
    }
    // Golden / forged ticket — TGT anomaly markers
    const gold = evs.filter((e) => /golden|forged|tgt anomaly|ticket lifetime/i.test(blob(e)));
    if (gold.length) {
      out.push(det("golden_ticket", `golden_ticket|${name}|${dayOf(gold[gold.length - 1].Timestamp)}`, name, idOf,
        gold[gold.length - 1].SourceIP || null, countryOf(gold[gold.length - 1]) || null,
        `Forged Kerberos ticket markers: ${gold[gold.length - 1].FailureReason || "anomalous TGT"}.`,
        gold.length, gold[0].Timestamp, gold[gold.length - 1].Timestamp));
    }
    // AS-REP roasting — AS-REP / pre-auth-disabled markers
    const asrep = evs.filter((e) => /as.?rep|preauth|pre-auth/i.test(blob(e)));
    if (asrep.length) {
      out.push(det("asrep_roasting", `asrep_roasting|${name}|${dayOf(asrep[asrep.length - 1].Timestamp)}`, name, idOf,
        asrep[asrep.length - 1].SourceIP || null, countryOf(asrep[asrep.length - 1]) || null,
        `AS-REP request for a pre-authentication-disabled account (${asrep.length} event(s)).`,
        asrep.length, asrep[0].Timestamp, asrep[asrep.length - 1].Timestamp));
    }
    // Kerberoasting — volume of TGS / RC4 service-ticket requests
    const tgs = evs.filter((e) => /tgs|service ticket|spn/i.test(blob(e)));
    const rc4 = tgs.filter((e) => /rc4|etype 23|0x17/i.test(blob(e)));
    if (rc4.length >= 3 || tgs.length >= 8) {
      out.push(det("kerberoasting", `kerberoasting|${name}|${dayOf((tgs[tgs.length - 1] || last).Timestamp)}`, name, idOf,
        (tgs[tgs.length - 1] || last).SourceIP || null, countryOf(tgs[tgs.length - 1] || last) || null,
        `${tgs.length} service-ticket (TGS) requests${rc4.length ? `, ${rc4.length} using weak RC4 encryption` : ""} — service-account credential harvesting.`,
        tgs.length || rc4.length, tgs[0]?.Timestamp || last.Timestamp, (tgs[tgs.length - 1] || last).Timestamp));
    }
  }
  return out;
}

// ── Posture detectors over IDENTITY ──────────────────────────────────────────
function detectPosture(tenant: number | null): Detection[] {
  const db = getDb("XORCISM");
  const cols = tableCols(db, "IDENTITY");
  if (!cols.size) return [];
  const w = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  let rows: Record<string, any>[] = [];
  try { rows = db.prepare(`SELECT IdentityID, IdentityName, IdentityClass, IdentityType, Status, PrivilegeLevel, MFAEnabled, OwnerPersonID, LastUsedDate FROM IDENTITY ${w}`).all(...(tenant != null ? [tenant] : [])) as Record<string, any>[]; }
  catch { return []; }
  const out: Detection[] = [];
  const now = Date.now();
  for (const r of rows) {
    const id = Number(r.IdentityID); const name = String(r.IdentityName || "").trim() || `Identity #${id}`;
    const priv = PRIVILEGED.has(String(r.PrivilegeLevel || "").trim().toLowerCase());
    if (!priv) continue;
    const mfa = String(r.MFAEnabled || "").trim();
    const status = String(r.Status || "").trim() || "Active";
    if (mfa && !mfaOn(mfa)) {
      out.push(det("mfa_less_priv", `mfa_less_priv|${id}`, name, id, null, null,
        `Privileged identity (${r.PrivilegeLevel}) with MFA not enabled.`, 1, null, null));
    }
    if (r.OwnerPersonID == null) {
      out.push(det("priv_orphaned", `priv_orphaned|${id}`, name, id, null, null,
        `Privileged identity (${r.PrivilegeLevel}) has no accountable owner.`, 1, null, null));
    }
    const lu = Date.parse(String(r.LastUsedDate || ""));
    if (/active/i.test(status) && Number.isFinite(lu) && (now - lu) / 86_400_000 > STALE_PRIV_DAYS) {
      out.push(det("stale_priv", `stale_priv|${id}`, name, id, null, null,
        `Privileged identity unused for ${Math.round((now - lu) / 86_400_000)}d.`, 1, String(r.LastUsedDate), String(r.LastUsedDate)));
    }
  }
  return out;
}

function det(ruleKey: string, dedupKey: string, name: string | null, id: number | null, ip: string | null, country: string | null,
             evidence: string, eventCount: number, firstSeen: string | null, lastSeen: string | null): Detection {
  const rule = ITDR_RULES[ruleKey];
  return { ruleKey, dedupKey, title: rule.title, severity: rule.severity, identityName: name, identityId: id,
    sourceIP: ip, country, evidence, eventCount, firstSeen, lastSeen };
}

/** Run every detector and upsert the results. Returns {scanned, created, updated, open}. */
export function runItdrDetectors(tenant: number | null): { created: number; updated: number; total: number } {
  const db = getDb("XORCISM");
  const dets = [...detectFromSignins(tenant), ...detectSpray(tenant), ...detectKerberos(tenant), ...detectPosture(tenant)];
  const ten = tenant ?? null;
  const now = new Date().toISOString();
  const fresh: Detection[] = []; // newly-created high/critical → emitted to the CROC loop after commit
  let created = 0, updated = 0;
  const upsert = db.prepare(`
    INSERT INTO IDENTITYDETECTION
      (DetectionGUID, RuleKey, DedupKey, Title, Severity, Tactic, Technique, TechniqueName,
       IdentityName, IdentityID, SourceIP, Country, Evidence, EventCount, Status, ResponseAction,
       FirstSeen, LastSeen, TenantID, CreatedDate, ModifiedDate)
    VALUES (@guid,@ruleKey,@dedupKey,@title,@severity,@tactic,@technique,@techniqueName,
       @identityName,@identityId,@sourceIP,@country,@evidence,@eventCount,'open',@response,
       @firstSeen,@lastSeen,@tenant,@now,@now)
    ON CONFLICT(DedupKey, TenantID) DO UPDATE SET
      LastSeen=excluded.LastSeen, EventCount=excluded.EventCount, Evidence=excluded.Evidence,
      Severity=excluded.Severity, ModifiedDate=excluded.ModifiedDate
    WHERE IDENTITYDETECTION.Status NOT IN ('resolved','dismissed')`);
  const existsStmt = db.prepare("SELECT 1 FROM IDENTITYDETECTION WHERE DedupKey=? AND (TenantID IS ? OR TenantID = ?)");
  const tx = db.transaction((items: Detection[]) => {
    for (const d of items) {
      const rule = ITDR_RULES[d.ruleKey];
      const existed = existsStmt.get(d.dedupKey, ten, ten);
      upsert.run({
        guid: randomUUID(), ruleKey: d.ruleKey, dedupKey: d.dedupKey, title: d.title, severity: d.severity,
        tactic: rule.tactic, technique: rule.technique, techniqueName: rule.techniqueName,
        identityName: d.identityName, identityId: d.identityId, sourceIP: d.sourceIP, country: d.country,
        evidence: d.evidence, eventCount: d.eventCount, response: rule.response,
        firstSeen: d.firstSeen, lastSeen: d.lastSeen, tenant: ten, now,
      });
      if (existed) updated++; else { created++; if (d.severity === "critical" || d.severity === "high") fresh.push(d); }
    }
  });
  tx(dets);

  // Publish newly-detected high/critical identity threats onto the CROC event bus, so the
  // pre-authorization policies can fire a response (escalate / constrain / ticket) at machine speed.
  // Best-effort and decoupled (dynamic import avoids a hard load-order/circular dependency).
  if (fresh.length) {
    try {
      const croc = require("./croc") as typeof import("./croc");
      for (const d of fresh) {
        const rule = ITDR_RULES[d.ruleKey];
        croc.emitLoopEvent({
          type: "identity.threat_detected", source: "itdr",
          summary: `[ITDR] ${d.title}${d.identityName ? " — " + d.identityName : (d.sourceIP ? " — " + d.sourceIP : "")}`,
          severity: d.severity, attackId: rule.technique, tenant: ten,
        });
      }
    } catch { /* the loop must never break detection */ }
  }
  return { created, updated, total: dets.length };
}

// ── Read model for the cockpit ───────────────────────────────────────────────
export interface DetectionRow {
  DetectionID: number; RuleKey: string; Title: string; Severity: Severity; Tactic: string; Technique: string;
  TechniqueName: string; IdentityName: string | null; IdentityID: number | null; SourceIP: string | null;
  Country: string | null; Evidence: string; EventCount: number; Status: string; ResponseAction: string;
  FirstSeen: string | null; LastSeen: string | null; IncidentAlertID: number | null; Notes: string | null;
}

export function itdrDashboard(tenant: number | null): any {
  const db = getDb("XORCISM");
  if (!tableCols(db, "IDENTITYDETECTION").size) return { summary: emptySummary(), coverage: [], worklist: [], detections: [] };
  const w = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const args = tenant != null ? [tenant] : [];
  const rows = db.prepare(`SELECT DetectionID, RuleKey, Title, Severity, Tactic, Technique, TechniqueName,
      IdentityName, IdentityID, SourceIP, Country, Evidence, EventCount, Status, ResponseAction,
      FirstSeen, LastSeen, IncidentAlertID, Notes
    FROM IDENTITYDETECTION ${w} ORDER BY DetectionID DESC`).all(...args) as DetectionRow[];

  const open = rows.filter((r) => isOpenStatus(r.Status));
  const bySev = (s: Severity) => open.filter((r) => r.Severity === s).length;
  const identitiesAtRisk = new Set(open.filter((r) => r.IdentityName).map((r) => r.IdentityName)).size;

  // MTTR over resolved detections (FirstSeen → ResolvedDate)
  const resolved = db.prepare(`SELECT FirstSeen, ResolvedDate FROM IDENTITYDETECTION ${w ? w + " AND" : "WHERE"} Status='resolved' AND ResolvedDate IS NOT NULL AND FirstSeen IS NOT NULL`).all(...args) as { FirstSeen: string; ResolvedDate: string }[];
  let mttrHours: number | null = null;
  if (resolved.length) {
    const hrs = resolved.map((r) => (Date.parse(r.ResolvedDate) - Date.parse(r.FirstSeen)) / 3600e3).filter((h) => Number.isFinite(h) && h >= 0);
    if (hrs.length) mttrHours = Math.round((hrs.reduce((a, b) => a + b, 0) / hrs.length) * 10) / 10;
  }

  // ATT&CK tactic coverage (open detections grouped by tactic, with technique set)
  const tacticMap = new Map<string, { tactic: string; count: number; techniques: Set<string>; topSeverity: Severity }>();
  for (const r of open) {
    const t = tacticMap.get(r.Tactic) ?? { tactic: r.Tactic, count: 0, techniques: new Set(), topSeverity: "low" as Severity };
    t.count++; t.techniques.add(r.Technique);
    if (SEV_RANK[r.Severity] > SEV_RANK[t.topSeverity]) t.topSeverity = r.Severity;
    tacticMap.set(r.Tactic, t);
  }
  const coverage = [...tacticMap.values()].map((t) => ({ tactic: t.tactic, count: t.count, techniques: [...t.techniques], topSeverity: t.topSeverity }))
    .sort((a, b) => b.count - a.count);

  // worklist: open, ranked by severity then recency
  const worklist = [...open].sort((a, b) => SEV_RANK[b.Severity] - SEV_RANK[a.Severity] || (b.DetectionID - a.DetectionID)).slice(0, 100);

  return {
    summary: {
      total: rows.length, open: open.length, critical: bySev("critical"), high: bySev("high"),
      medium: bySev("medium"), low: bySev("low"), identitiesAtRisk,
      tacticsCovered: tacticMap.size, techniquesCovered: new Set(open.map((r) => r.Technique)).size,
      mttrHours, raisedIncidents: rows.filter((r) => r.IncidentAlertID != null).length,
    },
    coverage, worklist, detections: rows.slice(0, 250),
  };
}

function emptySummary() {
  return { total: 0, open: 0, critical: 0, high: 0, medium: 0, low: 0, identitiesAtRisk: 0, tacticsCovered: 0, techniquesCovered: 0, mttrHours: null, raisedIncidents: 0 };
}

// ── Response workflow ────────────────────────────────────────────────────────
const VALID_STATUS = new Set(["open", "investigating", "contained", "resolved", "dismissed"]);

export function setDetectionStatus(id: number, status: string, tenant: number | null, user: string, notes?: string): boolean {
  if (!VALID_STATUS.has(status)) return false;
  const db = getDb("XORCISM");
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const resolved = (status === "resolved" || status === "dismissed");
  const sql = `UPDATE IDENTITYDETECTION SET Status=?, Notes=COALESCE(?, Notes),
      ResolvedDate=${resolved ? "?" : "ResolvedDate"}, ResolvedBy=${resolved ? "?" : "ResolvedBy"}, ModifiedDate=?
    WHERE DetectionID=? ${w}`;
  const now = new Date().toISOString();
  const params: any[] = [status, notes ?? null];
  if (resolved) params.push(now, user);
  params.push(now, id);
  if (tenant != null) params.push(tenant);
  try { return db.prepare(sql).run(...params).changes > 0; } catch { return false; }
}

/** Raise an incident (XINCIDENT.ALERT) from a detection and link it back. */
export function raiseIncidentFromDetection(id: number, tenant: number | null, user: string): { ok: boolean; alertId?: number; error?: string } {
  const xo = getDb("XORCISM");
  const w = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  const d = xo.prepare(`SELECT * FROM IDENTITYDETECTION WHERE DetectionID=? ${w}`).get(...[id, ...(tenant != null ? [tenant] : [])]) as DetectionRow & { IncidentAlertID: number | null } | undefined;
  if (!d) return { ok: false, error: "not found" };
  if (d.IncidentAlertID) return { ok: true, alertId: d.IncidentAlertID };
  let alertId: number | undefined;
  try {
    const inc = getDb("XINCIDENT");
    const cols = tableCols(inc, "ALERT");
    if (!cols.has("AlertID")) return { ok: false, error: "ALERT table unavailable" };
    const sevMap: Record<string, string> = { critical: "High", high: "High", medium: "Medium", low: "Low" };
    const now = new Date().toISOString();
    const field: Record<string, unknown> = {
      AlertGUID: randomUUID(),
      AlertName: `[ITDR] ${d.Title}${d.IdentityName ? " — " + d.IdentityName : ""}`,
      AlertDescription: `${d.Evidence}\n\nRecommended response: ${d.ResponseAction}`,
      CreatedDate: now, Severity: sevMap[d.Severity] || "Medium", Status: "New",
      Category: "Identity Threat", AttackTechniques: `${d.Technique} ${d.TechniqueName}`,
      RecommendedActions: d.ResponseAction, DetectionSource: "XORCISM ITDR",
      ExternalID: `itdr-${id}`, TenantID: tenant ?? null,
    };
    const names = Object.keys(field).filter((k) => cols.has(k));
    const sql = `INSERT INTO ALERT (${names.join(",")}) VALUES (${names.map(() => "?").join(",")})`;
    const info = inc.prepare(sql).run(...names.map((k) => field[k]));
    alertId = Number(info.lastInsertRowid);
  } catch (e) { return { ok: false, error: (e as Error).message }; }
  try { xo.prepare("UPDATE IDENTITYDETECTION SET IncidentAlertID=?, Status=CASE WHEN Status='open' THEN 'investigating' ELSE Status END, ModifiedDate=? WHERE DetectionID=?").run(alertId, new Date().toISOString(), id); } catch { /* link best-effort */ }
  return { ok: true, alertId };
}

// ── Demo seed (tenant 3) ─────────────────────────────────────────────────────
/** Adds a small password-spray burst (additive, idempotent) then runs the detectors so the cockpit
 * shows real detections derived from the seeded sign-in telemetry (impossible travel, brute force,
 * credential compromise, spray) + posture exposures. */
export function seedItdrDemo(tenant: number): void {
  try {
    const xo = getDb("XORCISM");
    if (!tableCols(xo, "IDENTITYSIGNIN").size) return;
    const ins = xo.prepare("INSERT INTO IDENTITYSIGNIN (SigninGUID, IdentityName, IdentityID, Timestamp, Country, SourceIP, MFAUsed, Result, FailureReason, RiskLevel, Source, ExternalID, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    const t0 = Date.now();
    const iso = (hAgo: number) => new Date(t0 - hAgo * 3600e3).toISOString();
    const has = (extId: string) => xo.prepare("SELECT 1 FROM IDENTITYSIGNIN WHERE Source='itdr-demo' AND ExternalID=? AND TenantID=? LIMIT 1").get(extId, tenant);
    // Block A — spray + MFA-bombing (guarded independently so it can be added to older demo instances)
    if (!has("spray-0")) {
      const sprayIp = "45.155.205.0";
      ["alice@demo.local", "bob@demo.local", "carol@demo.local", "dave@demo.local", "erin@demo.local"]
        .forEach((n, i) => ins.run(randomUUID(), n, null, iso(3), "NL", sprayIp, "no", "failure", "invalid password", "low", "itdr-demo", `spray-${i}`, tenant, new Date().toISOString()));
      for (let i = 0; i < 4; i++) ins.run(randomUUID(), "bob@demo.local", null, iso(2), "US", "203.0.113.77", "no", "failure", "MFA challenge denied", "medium", "itdr-demo", `mfa-${i}`, tenant, new Date().toISOString());
    }
    // Block B — AD / Kerberos telemetry (ClientApp/FailureReason as a DC-log connector would populate)
    if (!has("krb-dcsync")) {
      // Kerberoasting: a normal user requesting many RC4 service tickets
      for (let i = 0; i < 10; i++) ins.run(randomUUID(), "carol@demo.local", null, iso(2), "US", "10.0.0.40", "n/a", "success", `TGS-REQ RC4 etype 23 (SPN MSSQLSvc/db0${i})`, "low", "itdr-demo", `krb-tgs-${i}`, tenant, new Date().toISOString());
      // DCSync: directory replication requested by a non-DC workstation account
      ins.run(randomUUID(), "ws-pentest$@demo.local", null, iso(1), "US", "10.0.0.88", "n/a", "success", "DRSUAPI DsGetNCChanges (DCSync) from non-DC", "high", "itdr-demo", "krb-dcsync", tenant, new Date().toISOString());
      // AS-REP roasting: AS-REQ for a pre-auth-disabled account
      ins.run(randomUUID(), "svc-legacy@demo.local", null, iso(3), "US", "10.0.0.41", "n/a", "success", "AS-REP no-preauth (DONT_REQUIRE_PREAUTH)", "low", "itdr-demo", "krb-asrep", tenant, new Date().toISOString());
    }
    runItdrDetectors(tenant);
  } catch { /* best-effort demo */ }
}
