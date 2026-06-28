/**
 * arf.ts — Asset Reporting Format (ARF) import / export for the asset estate.
 *
 * Implements the NIST **Asset Reporting Format 1.1** (NISTIR 7694) transport document around the
 * **Asset Identification 1.1** (NISTIR 7693) data model, the asset/relationship/report container used
 * across SCAP (OpenSCAP, SCAP-validated scanners emit ARF result documents). An ARF document
 * (`<arf:asset-report-collection>`) carries three sibling collections:
 *   • `<arf:assets>`     — each `<arf:asset id="…">` wraps one Asset-Identification element. For a host
 *                          that is `<ai:computing-device>` with `cpe / fqdn / hostname / motherboard-guid /
 *                          network-interface(ip-address(ip-v4|ip-v6), mac-address)`.
 *   • `<arf:reports>`    — report payloads (XCCDF/OVAL results in a scanner's ARF). We carry a XORCISM
 *                          inventory-extension report so GRC-only fields (criticality, environment,
 *                          business/financial value, PII, MFA, owner notes) survive a round-trip — the
 *                          AI model itself has no slot for them.
 *   • `<core:relationships>` — typed links; we emit the inventory report `isAbout` every asset
 *                          (ARF relationship vocabulary `…/arf/vocabulary/relationships/1.0#isAbout`).
 *
 * Export builds the XML by template string (same approach as ovaleditor.ts — the codebase has no XML
 * parser dependency). Import uses a small namespace-tolerant scanner (matches by element local-name so
 * any prefix — arf:/ai:/core: or none — is accepted), so we can ingest a foreign scanner's ARF (we read
 * the AI asset identity) as well as our own (we additionally merge the XORCISM extension). Standard AI
 * fields create/upsert assets; the XORCISM extension enriches them. CPEs are exported (from CPEFORASSET)
 * but not re-linked on import (CPE links are derived data, re-creatable via the CVE matcher).
 */
import { getDb } from "./db";
import { createAsset, type AssetImportResult } from "./assets";

// ── Namespaces (NISTIR 7694 / 7693 + the ARF relationship vocabulary) ─────────────
const NS = {
  arf: "http://scap.nist.gov/schema/asset-reporting-format/1.1",
  ai: "http://scap.nist.gov/schema/asset-identification/1.1",
  core: "http://scap.nist.gov/schema/reporting-core/1.1",
  rel: "http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#",
  xor: "http://xorcism.io/schema/asset-extension/1.0",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
};

function cols(table: string): Set<string> {
  try { return new Set((getDb("XORCISM").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
const truthy = (v: unknown): boolean => v === 1 || v === "1" || v === true || String(v ?? "").toLowerCase() === "true";
const xesc = (v: unknown): string => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c]!));
// xs:ID / xs:NCName-safe identifier (must not start with a digit; restricted char set).
const ncname = (s: string): string => "a" + String(s).replace(/[^A-Za-z0-9._-]/g, "_");

// ── Export ────────────────────────────────────────────────────────────────────
/** Build an ARF 1.1 document for the tenant's assets (null tenant = all, super-admin). */
export function exportAssetsArf(tenant: number | null): string {
  const db = getDb("XORCISM");
  const ac = cols("ASSET");
  if (!ac.size) throw new Error("ASSET table not available");
  const tw = tenant != null && ac.has("TenantID") ? `WHERE TenantID = ${Number(tenant)}` : "";
  const assets = db.prepare(`SELECT * FROM ASSET ${tw}`).all() as Record<string, unknown>[];

  // CPE names per asset (CPEFORASSET → CPE) — optional, best-effort.
  const cpeByAsset = new Map<number, string[]>();
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='CPEFORASSET'").get() && cols("CPE").has("CPEName")) {
    try {
      for (const r of db.prepare(
        `SELECT fa.AssetID AssetID, c.CPEName CPEName FROM CPEFORASSET fa JOIN CPE c ON c.CPEID = fa.CPEID WHERE c.CPEName IS NOT NULL AND c.CPEName <> ''`,
      ).all() as { AssetID: number; CPEName: string }[]) {
        const k = Number(r.AssetID);
        const arr = cpeByAsset.get(k) ?? [];
        if (!arr.includes(r.CPEName)) arr.push(r.CPEName);
        cpeByAsset.set(k, arr);
      }
    } catch { /* ignore — CPE export is best-effort */ }
  }

  const idFor = (a: Record<string, unknown>): string =>
    ncname(`asset_${(a.AssetGUID ? String(a.AssetGUID) : `id${a.AssetID}`)}`);
  const reportId = "report_xorcism_inventory";

  const assetEls: string[] = [];
  const extEls: string[] = [];
  const refEls: string[] = [];

  for (const a of assets) {
    const aid = idFor(a);
    refEls.push(`        <core:ref>${aid}</core:ref>`);

    // ai:computing-device — element order per the AI 1.1 schema: cpe, fqdn, hostname,
    // motherboard-guid, network-interface(s). Emit only what we have.
    const dev: string[] = [];
    for (const cpe of cpeByAsset.get(Number(a.AssetID)) ?? []) dev.push(`        <ai:cpe>${xesc(cpe)}</ai:cpe>`);
    if (a.fqdn) dev.push(`        <ai:fqdn>${xesc(a.fqdn)}</ai:fqdn>`);
    if (a.hostname) dev.push(`        <ai:hostname>${xesc(a.hostname)}</ai:hostname>`);
    if (a.motherboardguid) dev.push(`        <ai:motherboard-guid>${xesc(a.motherboardguid)}</ai:motherboard-guid>`);
    // One network-interface per IP (ai:ip-address is a choice of ip-v4 | ip-v6).
    if (a.ipaddressIPv4) dev.push(`        <ai:network-interface><ai:ip-address><ai:ip-v4>${xesc(a.ipaddressIPv4)}</ai:ip-v4></ai:ip-address></ai:network-interface>`);
    if (a.ipaddressIPv6) dev.push(`        <ai:network-interface><ai:ip-address><ai:ip-v6>${xesc(a.ipaddressIPv6)}</ai:ip-v6></ai:ip-address></ai:network-interface>`);

    assetEls.push(
      `      <arf:asset id="${aid}">\n` +
      `        <ai:computing-device>\n${dev.length ? dev.join("\n") + "\n" : ""}        </ai:computing-device>\n` +
      `      </arf:asset>`,
    );

    // XORCISM inventory extension (GRC fields the AI model can't express), keyed by ref=asset-id.
    const env = truthy(a.cloud) ? "cloud" : (truthy(a.managedbythirdparty) || truthy(a.hostedbythirdparty)) ? "third-party" : truthy(a.virtual) ? "virtual" : "on-premises";
    const at: string[] = [`ref="${aid}"`, `name="${xesc(a.AssetName ?? "")}"`];
    if (a.AssetCriticalityLevel) at.push(`criticality="${xesc(a.AssetCriticalityLevel)}"`);
    at.push(`environment="${env}"`);
    if (a.OSName) at.push(`os="${xesc(a.OSName)}"`);
    if (a.networkname) at.push(`networkName="${xesc(a.networkname)}"`);
    at.push(`publicFacing="${truthy(a.PublicFacing)}"`, `hostPii="${truthy(a.HostPII) || truthy(a.personal)}"`, `mfaEnabled="${truthy(a.MFAEnabled)}"`);
    if (a.BusinessValue != null && String(a.BusinessValue) !== "") at.push(`businessValue="${xesc(a.BusinessValue)}"`);
    if (a.FinancialValue != null && String(a.FinancialValue) !== "") at.push(`financialValue="${xesc(a.FinancialValue)}"`);
    if (a.Currency) at.push(`currency="${xesc(a.Currency)}"`);
    const kids: string[] = [];
    if (a.AssetDescription) kids.push(`          <xorcism:description>${xesc(a.AssetDescription)}</xorcism:description>`);
    if (a.notes) kids.push(`          <xorcism:notes>${xesc(a.notes)}</xorcism:notes>`);
    extEls.push(kids.length
      ? `        <xorcism:asset ${at.join(" ")}>\n${kids.join("\n")}\n        </xorcism:asset>`
      : `        <xorcism:asset ${at.join(" ")}/>`);
  }

  const now = new Date().toISOString();
  const collId = ncname(`xorcism_asset_export_${now.replace(/[^0-9]/g, "").slice(0, 14)}`);
  const relationships = refEls.length
    ? `  <core:relationships>\n    <core:relationship type="rel:isAbout" subject="${reportId}">\n${refEls.join("\n")}\n    </core:relationship>\n  </core:relationships>\n`
    : "";

  return `<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="${NS.arf}"
    xmlns:ai="${NS.ai}"
    xmlns:core="${NS.core}"
    xmlns:rel="${NS.rel}"
    xmlns:xorcism="${NS.xor}"
    xmlns:xsi="${NS.xsi}"
    id="${collId}">
${relationships}  <arf:assets>
${assetEls.join("\n") || ""}
  </arf:assets>
  <arf:reports>
    <arf:report id="${reportId}">
      <arf:content>
        <xorcism:inventory generated="${now}" tool="XORCISM" count="${assets.length}"${tenant != null ? ` tenant="${Number(tenant)}"` : ""}>
${extEls.join("\n") || ""}
        </xorcism:inventory>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
`;
}

// ── Import (namespace-tolerant scanner) ──────────────────────────────────────────
export interface ParsedArfAsset {
  arfId: string;
  name?: string; description?: string; criticality?: string; environment?: string; os?: string; notes?: string;
  hostname?: string; fqdn?: string; ipv4?: string; ipv6?: string; networkName?: string; motherboardGuid?: string;
  cpes: string[];
  publicFacing?: boolean; hostPii?: boolean; mfaEnabled?: boolean;
  businessValue?: string; financialValue?: number | null; currency?: string;
}

const xdec = (s: string): string =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&amp;/g, "&");

// Element value by local-name (any/no prefix). Returns the first match, decoded + trimmed.
const tagRe = (name: string, g = ""): RegExp =>
  new RegExp(`<(?:[\\w.\\-]+:)?${name}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[\\w.\\-]+:)?${name}\\s*>`, g);
function first(xml: string, name: string): string | undefined {
  const m = tagRe(name).exec(xml);
  return m ? xdec(m[1]).trim() || undefined : undefined;
}
function allOf(xml: string, name: string): string[] {
  const re = tagRe(name, "g"); const out: string[] = []; let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) { const v = xdec(m[1]).trim(); if (v) out.push(v); }
  return out;
}
const attr = (attrs: string, name: string): string | undefined => {
  const m = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`).exec(attrs);
  return m ? xdec(m[1]) : undefined;
};
const toBoolU = (v: string | undefined): boolean | undefined =>
  v == null ? undefined : ["1", "true", "yes", "y", "x", "oui"].includes(v.trim().toLowerCase());

/** Parse an ARF/AI document into a flat asset list (standard AI fields + any XORCISM extension). */
export function parseArf(xml: string): { assets: ParsedArfAsset[]; tool?: string; count: number } {
  // 1) XORCISM extension records (asset elements that carry a `ref` attribute), keyed by ref.
  const ext = new Map<string, Partial<ParsedArfAsset>>();
  // `asset(?=[\s/>])` (not `asset\b`) so we never match `asset-report-collection` / `assets`.
  const extRe = /<(?:[\w.\-]+:)?asset(?=[\s/>])([^>]*?\bref\s*=\s*"([^"]*)"[^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[\w.\-]+:)?asset\s*>)/g;
  let em: RegExpExecArray | null;
  while ((em = extRe.exec(xml)) !== null) {
    const attrs = em[1], ref = xdec(em[2]), inner = em[3] || "";
    const fv = attr(attrs, "financialValue");
    ext.set(ref, {
      name: attr(attrs, "name"),
      criticality: attr(attrs, "criticality"),
      environment: attr(attrs, "environment"),
      os: attr(attrs, "os"),
      networkName: attr(attrs, "networkName"),
      publicFacing: toBoolU(attr(attrs, "publicFacing")),
      hostPii: toBoolU(attr(attrs, "hostPii")),
      mfaEnabled: toBoolU(attr(attrs, "mfaEnabled")),
      businessValue: attr(attrs, "businessValue"),
      financialValue: fv != null && fv !== "" ? Number(fv.replace(/[^0-9.\-]/g, "")) || null : undefined,
      currency: attr(attrs, "currency"),
      description: first(inner, "description"),
      notes: first(inner, "notes"),
    });
  }

  // 2) Asset wrappers (asset elements that carry an `id` attribute) → the AI identity.
  const out: ParsedArfAsset[] = [];
  const seen = new Set<string>();
  const wrapRe = /<(?:[\w.\-]+:)?asset(?=[\s>])([^>]*)>([\s\S]*?)<\/(?:[\w.\-]+:)?asset\s*>/g;
  let wm: RegExpExecArray | null;
  while ((wm = wrapRe.exec(xml)) !== null) {
    const attrs = wm[1], inner = wm[2];
    const id = attr(attrs, "id");
    if (!id || attr(attrs, "ref") != null) continue;   // extension records carry ref, not id
    if (seen.has(id)) continue; seen.add(id);
    const e = ext.get(id) || {};
    const hostname = first(inner, "hostname");
    const fqdn = first(inner, "fqdn");
    const ipv4 = first(inner, "ip-v4");
    const ipv6 = first(inner, "ip-v6");
    const name = e.name || hostname || fqdn || ipv4 || ipv6 || `ARF asset ${id}`;
    out.push({
      arfId: id, name,
      description: e.description, criticality: e.criticality, environment: e.environment,
      os: e.os, notes: e.notes, networkName: e.networkName,
      hostname, fqdn, ipv4, ipv6,
      motherboardGuid: first(inner, "motherboard-guid"),
      cpes: allOf(inner, "cpe"),
      publicFacing: e.publicFacing, hostPii: e.hostPii, mfaEnabled: e.mfaEnabled,
      businessValue: e.businessValue, financialValue: e.financialValue, currency: e.currency,
    });
  }

  const inv = /<(?:[\w.\-]+:)?inventory\b([^>]*)>/.exec(xml);
  return { assets: out, tool: inv ? attr(inv[1], "tool") : undefined, count: out.length };
}

function envFlags(env: string | undefined): Record<string, number> | null {
  if (!env) return null;
  const e = env.toLowerCase();
  return { cloud: e === "cloud" ? 1 : 0, virtual: e === "virtual" ? 1 : 0, managedbythirdparty: (e === "third-party" || e === "thirdparty") ? 1 : 0 };
}

// Set the AI columns createAsset() does not (fqdn / IPv6 / network name / motherboard GUID).
function patchAiColumns(db: ReturnType<typeof getDb>, ac: Set<string>, assetId: number, a: ParsedArfAsset): void {
  const set: Record<string, unknown> = {};
  if (a.fqdn && ac.has("fqdn")) set.fqdn = String(a.fqdn).slice(0, 255);
  if (a.ipv6 && ac.has("ipaddressIPv6")) set.ipaddressIPv6 = String(a.ipv6).slice(0, 45);
  if (a.networkName && ac.has("networkname")) set.networkname = String(a.networkName).slice(0, 255);
  if (a.motherboardGuid && ac.has("motherboardguid")) set.motherboardguid = String(a.motherboardGuid).slice(0, 100);
  const keys = Object.keys(set);
  if (keys.length) db.prepare(`UPDATE ASSET SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE AssetID = ?`).run(...keys.map((k) => set[k]), assetId);
}

// Update every column an ARF asset provides (upsert path). Never clobbers with blanks.
function updateArfColumns(db: ReturnType<typeof getDb>, ac: Set<string>, assetId: number, a: ParsedArfAsset): void {
  const set: Record<string, unknown> = {};
  const put = (col: string, v: unknown, max = 4000): void => { if (ac.has(col) && v != null && String(v).trim() !== "") set[col] = String(v).slice(0, max); };
  put("AssetDescription", a.description); put("AssetCriticalityLevel", a.criticality, 60);
  put("OSName", a.os, 200); put("hostname", a.hostname, 255); put("ipaddressIPv4", a.ipv4, 45);
  put("fqdn", a.fqdn, 255); put("ipaddressIPv6", a.ipv6, 45); put("networkname", a.networkName, 255);
  put("motherboardguid", a.motherboardGuid, 100); put("BusinessValue", a.businessValue, 60);
  put("Currency", a.currency, 10); put("notes", a.notes);
  const ef = envFlags(a.environment);
  if (ef) for (const [k, v] of Object.entries(ef)) if (ac.has(k)) set[k] = v;
  if (a.publicFacing !== undefined && ac.has("PublicFacing")) set.PublicFacing = a.publicFacing ? 1 : 0;
  if (a.hostPii !== undefined && ac.has("HostPII")) set.HostPII = a.hostPii ? 1 : 0;
  if (a.mfaEnabled !== undefined && ac.has("MFAEnabled")) set.MFAEnabled = a.mfaEnabled ? 1 : 0;
  if (a.financialValue != null && ac.has("FinancialValue")) set.FinancialValue = a.financialValue;
  if (ac.has("LastCheckedDate")) set.LastCheckedDate = new Date().toISOString();
  const keys = Object.keys(set);
  if (keys.length) db.prepare(`UPDATE ASSET SET ${keys.map((k) => `"${k}" = ?`).join(", ")} WHERE AssetID = ?`).run(...keys.map((k) => set[k]), assetId);
}

/**
 * Import assets from an ARF XML document. Creates assets from the AI identity (+ XORCISM extension);
 * with `upsert`, an existing asset of the same name (within the tenant) is updated in place.
 */
export function importAssetsArf(xml: string, tenant: number | null, opts: { upsert?: boolean } = {}): AssetImportResult & { parsed: number } {
  const db = getDb("XORCISM");
  const ac = cols("ASSET");
  if (!ac.size) throw new Error("ASSET table not available");
  const { assets } = parseArf(xml);
  const out: AssetImportResult & { parsed: number } = { created: 0, updated: 0, skipped: 0, errors: [], parsed: assets.length };
  const findByName = db.prepare("SELECT AssetID FROM ASSET WHERE AssetName = ? COLLATE NOCASE AND TenantID IS ? LIMIT 1");

  const tx = db.transaction((items: ParsedArfAsset[]) => {
    items.forEach((a, i) => {
      const name = String(a.name ?? "").trim();
      if (!name) { out.skipped++; return; }
      try {
        if (opts.upsert) {
          const ex = findByName.get(name, tenant) as { AssetID: number } | undefined;
          if (ex) { updateArfColumns(db, ac, ex.AssetID, a); out.updated++; return; }
        }
        const { id } = createAsset({
          name,
          description: a.description, criticality: a.criticality, os: a.os,
          hostname: a.hostname, ip: a.ipv4, environment: a.environment,
          publicFacing: a.publicFacing ?? false, hostPii: a.hostPii ?? false, mfaEnabled: a.mfaEnabled ?? false,
          businessValue: a.businessValue, financialValue: a.financialValue ?? null, currency: a.currency,
          notes: a.notes,
        }, tenant);
        patchAiColumns(db, ac, id, a);
        out.created++;
      } catch (e) { out.errors.push({ row: i + 1, error: String((e as Error).message || e) }); }
    });
  });
  tx(assets);
  return out;
}
