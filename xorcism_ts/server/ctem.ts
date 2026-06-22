/**
 * ctem.ts — CTEM (Continuous Threat Exposure Management), the ctem.org / SecureCoders standard.
 *
 * ctem.org publishes a vendor-neutral, standardized **exposure-identifier taxonomy** — a "CVE/CWE for
 * exposures": identifiers `CTEM-<CAT>-<n>` across 8 categories (Brand, Credentials, Domain, System
 * Exposure, Financial, Infection, Ransomware, Source-Code), licensed CC BY-NC-SA 4.0. This module
 * supports that standard: CTEMIDENTIFIER is the reference catalogue (seeded from the embedded list,
 * refreshable from ctem.org/source.json via tools/import_ctem.py) and CTEMEXPOSURE tracks a tenant's
 * observed exposures, each classified against an identifier and run through the 3-stage CTEM program
 * (Discover → Prioritize → Remediate). Surfaced at /ctem.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const CATS: Record<string, string> = {
  BND: "Brand Impersonation", CRD: "Credential Dump", DOM: "Look-alike Domains", EXP: "System Exposure",
  FIN: "Financial Info Exposure", INF: "Infected Device", RAN: "Ransomware", SRC: "Source-Code Exposure",
};
const STAGES = ["Discover", "Prioritize", "Remediate"];
const SEV_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const OPEN = (s: string): boolean => !/remediat|accept|false.?positive|closed/i.test(s || "");
const SRC_VERSION = "1.0";

// Embedded ctem.org catalogue (v1.0, 29 identifiers / 8 categories). [CtemId, name, categoryCode, description]
const IDENT: [string, string, string, string][] = [
  ["CTEM-BND-1", "Counterfeit Product Offered for Sale or Use", "BND", "Counterfeit versions of an organization's products are being sold, often without authorization, on dark-web marketplaces, online pharmacies or mainstream e-commerce platforms."],
  ["CTEM-CRD-1", "Employee Credentials Dumped Publicly", "CRD", "Employee credentials (and a hostname) exposed on public platforms / paste sites / combolists."],
  ["CTEM-CRD-2", "Vendor System Dump with Credentials", "CRD", "Vendor-system credentials and a hostname exposed on public platforms."],
  ["CTEM-DOM-1", "Typo-Squatted Domain", "DOM", "Domains that closely resemble a legitimate domain but contain slight misspellings."],
  ["CTEM-DOM-2", "Homoglyph Attack Domain", "DOM", "Domains that exploit characters which look visually similar to a legitimate name."],
  ["CTEM-DOM-3", "Phishing Indicator Domain", "DOM", "Domains that exhibit characteristics suggesting they are intended for phishing."],
  ["CTEM-DOM-4", "Brand Impersonation Domain", "DOM", "Domains that mimic the naming conventions or structure of a legitimate organization."],
  ["CTEM-EXP-1", "Directly Connected Internal System", "EXP", "A system directly connected to the customer's internal network."],
  ["CTEM-EXP-2", "Remote Site-Owned System Presumed Connected", "EXP", "A system owned by a subsidiary, presumed connected to the customer network."],
  ["CTEM-EXP-3", "Corporate Internet-Exposed Gateway Device", "EXP", "An internet gateway device publicly exposed to the Internet."],
  ["CTEM-EXP-4", "Corporate Cloud-Connected System", "EXP", "A business application exposed to the Internet."],
  ["CTEM-EXP-5", "Presumed Company System by Branding", "EXP", "A system believed to belong to the company without clear ownership documentation."],
  ["CTEM-EXP-6", "Contractor/Vendor-Managed System", "EXP", "A system managed by a contractor or vendor supporting operations."],
  ["CTEM-FIN-1", "Corporate Bank Account / Routing Information Exposed", "FIN", "Corporate bank-account or routing information is exposed."],
  ["CTEM-FIN-2", "Accounts Payable Information Exposure", "FIN", "Accounts-payable information is exposed."],
  ["CTEM-INF-1", "Infected Corporate Owned Device", "INF", "A corporate-owned device infected with malware."],
  ["CTEM-INF-2", "Infected Vendor Owned Device", "INF", "A vendor device infected and connected to systems they manage."],
  ["CTEM-INF-3", "Infected Employee Owned Device (Corporate Credentials)", "INF", "A personal device connected to corporate systems via credentials."],
  ["CTEM-INF-4", "Infected Employee Owned Device (Personal Use of Corporate Identity)", "INF", "A personal device using corporate email for external services."],
  ["CTEM-INF-5", "Infected Customer Owned Device", "INF", "A customer's infected device holding credentials to a company-owned service."],
  ["CTEM-INF-6", "Infected Employee Owned Device (Internal Network Connected)", "INF", "A personal device connected to corporate systems / internal network."],
  ["CTEM-INF-7", "Infected Employee Owned Device (3rd Party Business Use of Corporate Identity)", "INF", "A personal device using the corporate identity for third-party business use."],
  ["CTEM-RAN-1", "Ransom Dump (Supplier)", "RAN", "A supplier's sensitive data leaked via a ransomware attack."],
  ["CTEM-RAN-2", "Ransom Dump (Customer)", "RAN", "A customer's data leaked due to a ransomware attack."],
  ["CTEM-SRC-1", "Public Source Code Repository - Company Sanctioned", "SRC", "A company-sanctioned public source-code repository."],
  ["CTEM-SRC-2", "Public Source Code Repository - Employee Created", "SRC", "An employee-created public source-code repository."],
  ["CTEM-SRC-3", "Public Source Code Repository - Vendor Owned", "SRC", "A vendor-owned public source-code repository."],
  ["CTEM-SRC-4", "Public Source Code Repository - Unrelated 3rd Party", "SRC", "An unrelated third-party public source-code repository."],
  ["CTEM-SRC-5", "Public Source Code Repository - Unrelated Company Comment / Issue", "SRC", "An unrelated company comment or issue in a public source-code repository."],
];

function cols(dbn: string, t: string): Set<string> { try { return new Set((getDb(dbn).prepare(`PRAGMA table_info("${t}")`).all() as { name: string }[]).map((c) => c.name)); } catch { return new Set(); } }
function nextId(t: string, pk: string): number { return (getDb("XVULNERABILITY").prepare(`SELECT COALESCE(MAX(${pk}),0)+1 n FROM ${t}`).get() as { n: number }).n; }
const codeOf = (ctemId: string): string => (ctemId.split("-")[1] || "").toUpperCase();

function isPublicV4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim()); if (!m) return false;
  const o = m.slice(1).map(Number); if (o.some((n) => n > 255)) return false;
  const [a, b] = o;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false; // multicast / reserved
  return true;
}

/** Seed the embedded ctem.org catalogue into CTEMIDENTIFIER (idempotent, additive by CtemId). */
export function seedCtemIdentifiers(): number {
  const xv = getDb("XVULNERABILITY");
  let n = 0; const now = new Date().toISOString();
  const ins = xv.prepare("INSERT INTO CTEMIDENTIFIER (CtemIdentifierID, CtemId, Title, CategoryCode, Category, Description, Link, Version, UpdatedDate, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)");
  for (const [ctemId, name, code, desc] of IDENT) {
    if (xv.prepare("SELECT 1 FROM CTEMIDENTIFIER WHERE CtemId = ?").get(ctemId)) continue;
    ins.run(nextId("CTEMIDENTIFIER", "CtemIdentifierID"), ctemId, name, code, CATS[code] ?? code, desc, `https://ctem.org/docs/${ctemId.toLowerCase()}`, SRC_VERSION, "", now); n++;
  }
  return n;
}

interface IdentRow { ctemId: string; title: string; categoryCode: string; category: string; description: string; link: string }
function identifiers(): IdentRow[] {
  try {
    return (getDb("XVULNERABILITY").prepare("SELECT CtemId, Title, CategoryCode, Category, Description, Link FROM CTEMIDENTIFIER ORDER BY CtemId").all() as any[])
      .map((r) => ({ ctemId: String(r.CtemId), title: String(r.Title ?? ""), categoryCode: String(r.CategoryCode ?? codeOf(String(r.CtemId))), category: String(r.Category ?? ""), description: String(r.Description ?? ""), link: String(r.Link ?? "") }));
  } catch { return []; }
}

/** The reference catalogue grouped by category (for the catalogue browser). */
export function ctemCatalogue(): any {
  const rows = identifiers();
  const groups = Object.keys(CATS).map((code) => ({ code, name: CATS[code], items: rows.filter((r) => r.categoryCode === code) }));
  return { version: SRC_VERSION, total: rows.length, license: "CC BY-NC-SA 4.0", source: "https://ctem.org", groups };
}

interface Exp { id: number; ctemId: string; title: string; categoryCode: string; category: string; stage: string; severity: string; status: string; assetId: number | null; asset: string | null; owner: string | null; source: string; evidence: string; firstSeen: string; open: boolean }

function exposures(tenant: number | null): Exp[] {
  const xv = getDb("XVULNERABILITY");
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = xv.prepare(`SELECT * FROM CTEMEXPOSURE ${tw} ORDER BY ExposureID DESC`).all(...(tenant != null ? [tenant] : [])) as any[];
  const titleOf = new Map(identifiers().map((i) => [i.ctemId, i.title]));
  // asset + owner names (XORCISM)
  const xo = getDb("XORCISM");
  const assetName = new Map<number, string>(); const personName = new Map<number, string>();
  try { for (const a of xo.prepare("SELECT AssetID, AssetName FROM ASSET").all() as any[]) assetName.set(Number(a.AssetID), String(a.AssetName || `#${a.AssetID}`)); } catch { /* */ }
  try { for (const p of xo.prepare("SELECT PersonID, FullName FROM PERSON").all() as any[]) personName.set(Number(p.PersonID), String(p.FullName || `#${p.PersonID}`)); } catch { /* */ }
  return rows.map((r) => {
    const ctemId = String(r.CtemId ?? "");
    const status = String(r.Status ?? "Open");
    return {
      id: Number(r.ExposureID), ctemId, title: String(r.Title ?? "") || titleOf.get(ctemId) || ctemId,
      categoryCode: String(r.CategoryCode ?? codeOf(ctemId)), category: CATS[String(r.CategoryCode ?? codeOf(ctemId))] ?? "",
      stage: String(r.Stage ?? "Discover"), severity: String(r.Severity ?? "Medium"), status,
      assetId: r.AssetID != null ? Number(r.AssetID) : null, asset: r.AssetID != null ? (assetName.get(Number(r.AssetID)) || `#${r.AssetID}`) : null,
      owner: r.RemediationOwnerPersonID != null ? (personName.get(Number(r.RemediationOwnerPersonID)) || `#${r.RemediationOwnerPersonID}`) : null,
      source: String(r.Source ?? ""), evidence: String(r.Evidence ?? ""), firstSeen: r.FirstSeen ? String(r.FirstSeen).slice(0, 10) : "", open: OPEN(status),
    };
  });
}

/** The /ctem cockpit: 3-stage program counts, category coverage, severity mix, risk worklist + catalogue. */
export function ctemDashboard(tenant: number | null): any {
  const exps = exposures(tenant);
  const cat = ctemCatalogue();
  const open = exps.filter((e) => e.open);
  const remediated = exps.filter((e) => /remediat/i.test(e.status));
  const stageCounts: Record<string, number> = { Discover: 0, Prioritize: 0, Remediate: 0 };
  for (const e of open) stageCounts[STAGES.includes(e.stage) ? e.stage : "Discover"]++;
  const sevMix: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const e of open) sevMix[e.severity in sevMix ? e.severity : "Medium"]++;
  const observedCats = new Set(exps.map((e) => e.categoryCode));
  const categories = Object.keys(CATS).map((code) => ({
    code, name: CATS[code], catalogue: cat.groups.find((g: any) => g.code === code)?.items.length ?? 0,
    open: open.filter((e) => e.categoryCode === code).length, tracked: exps.filter((e) => e.categoryCode === code).length,
  }));
  const stageW: Record<string, number> = { Discover: 8, Prioritize: 18, Remediate: 4 };
  const worklist = open.map((e) => ({ ...e, score: (4 - (SEV_RANK[e.severity] ?? 2)) * 20 + (stageW[e.stage] ?? 8) + (e.owner ? 0 : 6) }))
    .sort((a, b) => b.score - a.score).slice(0, 80);

  return {
    catalogue: cat, categories, worklist,
    stages: STAGES.map((s) => ({ stage: s, open: stageCounts[s] })),
    severityMix: sevMix,
    summary: {
      tracked: exps.length, open: open.length, remediated: remediated.length,
      catalogueSize: cat.total, categoriesCovered: observedCats.size, categoriesTotal: Object.keys(CATS).length,
      criticalOpen: open.filter((e) => e.severity === "Critical").length, highOpen: open.filter((e) => e.severity === "High").length,
      unassigned: open.filter((e) => !e.owner).length, inDiscover: stageCounts.Discover, inPrioritize: stageCounts.Prioritize, inRemediate: stageCounts.Remediate,
    },
    generatedAt: new Date().toISOString(),
  };
}

// ── discovery bridge: classify existing XORCISM signals against CTEM identifiers ─────────────────
/** Auto-classify internet-exposed assets as CTEM exposures (EXP-4 web apps / EXP-3 gateways). Idempotent. */
export function discoverCtemExposures(tenant: number | null): { created: number; scanned: number } {
  const xo = getDb("XORCISM"), xv = getDb("XVULNERABILITY");
  const ac = cols("XORCISM", "ASSET");
  if (!ac.has("AssetID")) return { created: 0, scanned: 0 };
  const tw = tenant != null && ac.has("TenantID") ? "WHERE TenantID = ?" : "";
  const sel = (c: string) => (ac.has(c) ? c : `NULL AS ${c}`);
  const assets = xo.prepare(`SELECT AssetID, AssetName, ${sel("ipaddressIPv4")}, ${sel("websiteurl")} FROM ASSET ${tw}`).all(...(tw ? [tenant] : [])) as any[];
  const now = new Date().toISOString();
  let created = 0;
  const has = xv.prepare("SELECT 1 FROM CTEMEXPOSURE WHERE CtemId = ? AND IFNULL(AssetID,-1) = ? AND IFNULL(TenantID,-1)=IFNULL(?,-1) AND Source = 'asset-discovery'");
  const ins = xv.prepare("INSERT INTO CTEMEXPOSURE (ExposureID, ExposureGUID, CtemId, Title, CategoryCode, Stage, Severity, Status, AssetID, Source, Evidence, FirstSeen, LastSeen, DiscoveredDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  const titleOf = new Map(IDENT.map((i) => [i[0], i[1]]));
  for (const a of assets) {
    const web = a.websiteurl ? String(a.websiteurl).trim() : "";
    const ip = a.ipaddressIPv4 ? String(a.ipaddressIPv4).trim() : "";
    let ctemId = "", sev = "Medium", evidence = "";
    if (web) { ctemId = "CTEM-EXP-4"; sev = "Medium"; evidence = web; }
    else if (ip && isPublicV4(ip)) { ctemId = "CTEM-EXP-3"; sev = "High"; evidence = ip; }
    else continue;
    if (has.get(ctemId, Number(a.AssetID), tenant)) continue;
    ins.run(nextId("CTEMEXPOSURE", "ExposureID"), randomUUID(), ctemId, titleOf.get(ctemId) ?? ctemId, "EXP", "Discover", sev, "Open", Number(a.AssetID), "asset-discovery", evidence, now, now, now, tenant, now);
    created++;
  }
  return { created, scanned: assets.length };
}

// ── mutations ────────────────────────────────────────────────────────────────────
export function createExposure(p: { ctemId: string; title?: string; severity?: string; assetId?: number; evidence?: string; source?: string; stage?: string }, tenant: number | null): { id: number } {
  const xv = getDb("XVULNERABILITY"); const id = nextId("CTEMEXPOSURE", "ExposureID"); const now = new Date().toISOString();
  const code = codeOf(p.ctemId);
  const title = p.title || (IDENT.find((i) => i[0] === p.ctemId)?.[1]) || p.ctemId;
  const stage = STAGES.includes(p.stage || "") ? p.stage! : "Discover";
  xv.prepare("INSERT INTO CTEMEXPOSURE (ExposureID, ExposureGUID, CtemId, Title, CategoryCode, Stage, Severity, Status, AssetID, Source, Evidence, FirstSeen, LastSeen, DiscoveredDate, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), p.ctemId, title.slice(0, 300), code, stage, p.severity || "Medium", "Open", p.assetId ?? null, p.source || "manual", (p.evidence || "").slice(0, 2000), now, now, now, tenant, now);
  return { id };
}

function getExp(id: number, tenant: number | null): any {
  const xv = getDb("XVULNERABILITY");
  const tw = tenant != null ? "AND (TenantID = ? OR TenantID IS NULL)" : "";
  return xv.prepare(`SELECT * FROM CTEMEXPOSURE WHERE ExposureID = ? ${tw}`).get(...(tenant != null ? [id, tenant] : [id]));
}

/** Advance an exposure to the next CTEM stage (Discover → Prioritize → Remediate). */
export function advanceStage(id: number, tenant: number | null): { stage: string } | null {
  const row = getExp(id, tenant); if (!row) return null;
  const cur = String(row.Stage ?? "Discover"); const i = STAGES.indexOf(cur);
  const next = STAGES[Math.min(STAGES.length - 1, (i < 0 ? 0 : i) + 1)];
  getDb("XVULNERABILITY").prepare("UPDATE CTEMEXPOSURE SET Stage = ?, LastSeen = ? WHERE ExposureID = ?").run(next, new Date().toISOString(), id);
  return { stage: next };
}

/** Set status / severity / stage. Status 'Remediated' stamps RemediatedDate and moves to the Remediate stage. */
export function setExposureStatus(id: number, p: { status?: string; severity?: string; stage?: string }, tenant: number | null): boolean {
  const row = getExp(id, tenant); if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (p.status) { sets.push("Status = ?"); vals.push(p.status); if (/remediat/i.test(p.status)) { sets.push("RemediatedDate = ?", "Stage = ?"); vals.push(new Date().toISOString(), "Remediate"); } }
  if (p.severity) { sets.push("Severity = ?"); vals.push(p.severity); }
  if (p.stage && STAGES.includes(p.stage)) { sets.push("Stage = ?"); vals.push(p.stage); }
  if (!sets.length) return true;
  sets.push("LastSeen = ?"); vals.push(new Date().toISOString()); vals.push(id);
  getDb("XVULNERABILITY").prepare(`UPDATE CTEMEXPOSURE SET ${sets.join(", ")} WHERE ExposureID = ?`).run(...vals);
  return true;
}

export function assignExposure(id: number, p: { ownerPersonId?: number; severity?: string }, tenant: number | null): boolean {
  const row = getExp(id, tenant); if (!row) return false;
  const sets: string[] = []; const vals: unknown[] = [];
  if (p.ownerPersonId != null) { sets.push("RemediationOwnerPersonID = ?"); vals.push(p.ownerPersonId); }
  if (p.severity) { sets.push("Severity = ?"); vals.push(p.severity); }
  if (!sets.length) return true;
  vals.push(id);
  getDb("XVULNERABILITY").prepare(`UPDATE CTEMEXPOSURE SET ${sets.join(", ")} WHERE ExposureID = ?`).run(...vals);
  return true;
}

// ── seed (demo) ────────────────────────────────────────────────────────────────────
export function seedCtemDemo(tenant: number): { exposures: number } {
  const xv = getDb("XVULNERABILITY");
  if ((xv.prepare("SELECT COUNT(*) n FROM CTEMEXPOSURE WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { exposures: 0 };
  const xo = getDb("XORCISM");
  let firstAsset: number | null = null;
  try { firstAsset = (xo.prepare(`SELECT AssetID FROM ASSET ${cols("XORCISM", "ASSET").has("TenantID") ? "WHERE TenantID = ?" : ""} ORDER BY AssetID LIMIT 1`).get(...(cols("XORCISM", "ASSET").has("TenantID") ? [tenant] : [])) as any)?.AssetID ?? null; } catch { /* */ }
  const seed: { ctemId: string; sev: string; stage: string; status?: string; asset?: boolean; evidence?: string }[] = [
    { ctemId: "CTEM-EXP-3", sev: "Critical", stage: "Prioritize", asset: true, evidence: "edge firewall 203.0.113.10 — admin UI reachable" },
    { ctemId: "CTEM-CRD-1", sev: "High", stage: "Discover", evidence: "12 employee creds in a combolist (paste site)" },
    { ctemId: "CTEM-DOM-1", sev: "Medium", stage: "Prioritize", evidence: "xorc1sm-login[.]com registered 3 days ago" },
    { ctemId: "CTEM-RAN-1", sev: "Critical", stage: "Remediate", evidence: "supplier ACME named on a leak site" },
    { ctemId: "CTEM-INF-1", sev: "High", stage: "Remediate", status: "Remediated", asset: true, evidence: "stealer infection — reimaged + creds rotated" },
    { ctemId: "CTEM-SRC-2", sev: "Medium", stage: "Discover", evidence: "private API key in an employee's public repo" },
    { ctemId: "CTEM-FIN-1", sev: "High", stage: "Prioritize", evidence: "routing info in an exposed invoice PDF" },
    { ctemId: "CTEM-BND-1", sev: "Low", stage: "Discover", evidence: "counterfeit goods on a marketplace" },
  ];
  for (const s of seed) {
    const { id } = createExposure({ ctemId: s.ctemId, severity: s.sev, stage: s.stage, source: "demo", evidence: s.evidence, assetId: s.asset ? (firstAsset ?? undefined) : undefined }, tenant);
    if (s.status) setExposureStatus(id, { status: s.status }, tenant);
  }
  return { exposures: seed.length };
}
