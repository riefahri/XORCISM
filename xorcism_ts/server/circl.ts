/**
 * circl.ts — Integration with CIRCL vulnerability-lookup (https://vulnerability.circl.lu/).
 *
 * - Searches the catalogues (CVE by id, or vendor/product) — notably the
 *   KEV (Known Exploited Vulnerabilities): the marker comes from the CISA ADP
 *   container (SSVC "Exploitation: active").
 * - Enriches the VULNERABILITY form and imports into XVULNERABILITY (with the
 *   KEV / Exploited flag). Reuses upsertVulnerability (shared with OSV).
 */
import { upsertVulnerability, OsvImportResult } from "./osv";

const CIRCL_API = (process.env.CIRCL_API_URL || "https://vulnerability.circl.lu").replace(/\/$/, "");
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const SAFE_TERM = /^[A-Za-z0-9 ._@:+\-/]{1,64}$/;

const AV_WORD: Record<string, string> = { N: "NETWORK", A: "ADJACENT_NETWORK", L: "LOCAL", P: "PHYSICAL" };
const LHN_WORD: Record<string, string> = { H: "HIGH", L: "LOW", N: "NONE" };
const AC_WORD: Record<string, string> = { L: "LOW", H: "HIGH" };

export interface CirclNormalized {
  referential: string;
  fields: Record<string, string | number>;
  summary: string;
  kev: boolean;
  cvssVector: string | null;
}

async function circlGet(path: string, timeoutMs = 15000): Promise<any> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${CIRCL_API}${path}`, { headers: { Accept: "application/json" }, signal: ctrl.signal });
    if (r.status === 404) throw new Error("Introuvable dans CIRCL");
    if (!r.ok) throw new Error(`CIRCL ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

export function isCve(id: string): boolean {
  return CVE_RE.test(id);
}

function parseVector(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v && k !== "CVSS") out[k] = v;
  }
  return out;
}

/** Looks up a CVSS v3.x metric in the cna + adp containers. */
function findCvss(record: any): { base: number | null; vector: string | null } {
  const containers = record.containers || {};
  const metricSets = [containers.cna, ...(containers.adp || [])].filter(Boolean);
  for (const c of metricSets) {
    for (const m of c.metrics || []) {
      const cv = m.cvssV3_1 || m.cvssV3_0;
      if (cv && cv.vectorString) {
        return { base: typeof cv.baseScore === "number" ? cv.baseScore : null, vector: cv.vectorString };
      }
    }
  }
  return { base: null, vector: null };
}

/** KEV = active exploitation reported by the CISA-ADP SSVC. */
function detectKev(record: any): boolean {
  for (const a of record.containers?.adp || []) {
    for (const m of a.metrics || []) {
      if (m.other?.type === "ssvc") {
        for (const opt of m.other.content?.options || []) {
          if (String(opt.Exploitation || "").toLowerCase() === "active") return true;
        }
      }
    }
  }
  return false;
}

/** Normalizes a CVE 5.x record (CIRCL) into the XVULNERABILITY columns. */
export function normalizeCircl(record: any): CirclNormalized {
  const id = String(record.cveMetadata?.cveId || "");
  const cna = record.containers?.cna || {};
  const fields: Record<string, string | number> = {};
  for (const col of ["VULReferential", "VULReferentialID", "VULGUID", "VULName", "VULShortName"]) fields[col] = id;

  const desc = ((cna.descriptions || []).find((d: any) => d.lang?.startsWith("en")) || (cna.descriptions || [])[0] || {}).value;
  if (desc) fields.VULDescription = String(desc).trim();
  if (record.cveMetadata?.datePublished) {
    fields.VULPublishedDate = String(record.cveMetadata.datePublished);
    fields.ValidFromDate = String(record.cveMetadata.datePublished);
  }
  if (record.cveMetadata?.dateUpdated) fields.VULModifiedDate = String(record.cveMetadata.dateUpdated);
  fields.VULType = "CIRCL";

  const { base, vector } = findCvss(record);
  if (vector) {
    const m = parseVector(vector);
    if (m.AV && AV_WORD[m.AV]) fields.CVSSMetricAccessVector = AV_WORD[m.AV];
    if (m.AC && AC_WORD[m.AC]) fields.CVSSMetricAccessComplexity = AC_WORD[m.AC];
    if (m.PR && LHN_WORD[m.PR]) fields.CVSSMetricAuthentication = LHN_WORD[m.PR];
    if (m.C && LHN_WORD[m.C]) fields.CVSSMetricConfImpact = LHN_WORD[m.C];
    if (m.I && LHN_WORD[m.I]) fields.CVSSMetricIntegImpact = LHN_WORD[m.I];
    if (m.A && LHN_WORD[m.A]) fields.CVSSMetricAvailImpact = LHN_WORD[m.A];
  }
  if (base != null) fields.CVSSBaseScore = base;

  const refs: any[] = cna.references || [];
  if (refs[0]?.url) fields.VULURL = String(refs[0].url);

  const kev = detectKev(record);
  if (kev) {
    fields.KEV = 1;
    fields.Exploited = 1;
  }
  const detail: string[] = [];
  detail.push(kev ? "KEV : exploitation active (CISA SSVC)." : "KEV : non signalé comme activement exploité.");
  if (refs.length) {
    detail.push("References:");
    for (const r of refs.slice(0, 10)) if (r?.url) detail.push(`- ${r.url}`);
  }
  fields.VULDetailedInformation = detail.join("\n");

  return { referential: id, fields, summary: desc ? String(desc).slice(0, 120) : id, kev, cvssVector: vector };
}

/** Fetches + normalizes a CVE from CIRCL (without writing). */
export async function lookupCircl(id: string): Promise<CirclNormalized> {
  if (!isCve(id)) throw new Error("Identifiant CVE invalide (ex. CVE-2021-44228)");
  return normalizeCircl(await circlGet(`/api/vulnerability/${encodeURIComponent(id)}`));
}

export interface CirclSearchHit { id: string; summary: string }

/**
 * Search: a CVE id → direct lookup; otherwise "vendor" or "vendor/product"
 * via /api/search. Returns at most `limit` matches.
 */
export async function searchCircl(query: string, limit = 25): Promise<CirclSearchHit[]> {
  const q = query.trim();
  if (isCve(q)) {
    const n = await lookupCircl(q);
    return [{ id: n.referential, summary: (n.kev ? "[KEV] " : "") + n.summary }];
  }
  const parts = q.split(/[\s/]+/).filter(Boolean).slice(0, 2);
  for (const p of parts) if (!SAFE_TERM.test(p)) throw new Error("Terme de recherche invalide");
  const path = "/api/search/" + parts.map(encodeURIComponent).join("/");
  const data = await circlGet(path);
  const hits: CirclSearchHit[] = [];
  const results = data?.results || {};
  for (const src of Object.keys(results)) {
    for (const entry of results[src] || []) {
      const rec = Array.isArray(entry) ? entry[1] : entry;
      const id = rec?.cveMetadata?.cveId;
      if (!id) continue;
      const cna = rec.containers?.cna || {};
      const d = ((cna.descriptions || []).find((x: any) => x.lang?.startsWith("en")) || {}).value || "";
      hits.push({ id, summary: String(d).slice(0, 140) });
      if (hits.length >= limit) return hits;
    }
  }
  return hits;
}

/** Imports (or updates) a CVE from CIRCL into XVULNERABILITY (with KEV). */
export async function importCircl(id: string): Promise<OsvImportResult & { kev: boolean }> {
  const norm = await lookupCircl(id);
  const r = upsertVulnerability(norm.referential, norm.fields);
  return { ...r, kev: norm.kev };
}
