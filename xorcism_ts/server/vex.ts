/**
 * vex.ts — OpenVEX export. Emits a VEX (Vulnerability Exploitability eXchange) document
 * from the asset↔vulnerability links so downstream consumers know which CVEs actually
 * affect your products and which are false-positives/fixed. Format: OpenVEX v0.2.0.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";

const CVE_RX = /CVE-\d{4}-\d{3,7}/i;

export function generateVex(tenant: number | null): unknown {
  const xo = getDb("XORCISM");
  const aCols = new Set((xo.prepare('PRAGMA table_info("ASSET")').all() as { name: string }[]).map((c) => c.name));
  const tcl = tenant != null && aCols.has("TenantID") ? 'AND (a."TenantID"=? OR a."TenantID" IS NULL)' : "";
  const targs = tenant != null && aCols.has("TenantID") ? [tenant] : [];
  const rows = xo.prepare(
    `SELECT av.VulnerabilityID vid, a.AssetName name, av.Status status, COALESCE(av.FalsePositive,0) fp
     FROM ASSETVULNERABILITY av JOIN ASSET a ON a.AssetID=av.AssetID WHERE 1=1 ${tcl}`
  ).all(...targs) as { vid: number; name: string; status: string | null; fp: number }[];

  const refByVid = new Map<number, string>();
  try {
    const xv = getDb("XVULNERABILITY");
    const ids = [...new Set(rows.map((r) => r.vid))];
    for (let i = 0; i < ids.length; i += 800) {
      const chunk = ids.slice(i, i + 800); const ph = chunk.map(() => "?").join(",");
      for (const m of xv.prepare(`SELECT VulnerabilityID id, COALESCE(VULReferential,VULName) ref FROM VULNERABILITY WHERE VulnerabilityID IN (${ph})`).all(...chunk) as { id: number; ref: string }[]) refByVid.set(m.id, m.ref);
    }
  } catch { /* */ }

  // group by CVE → { products, statuses }
  const byCve = new Map<string, { products: Set<string>; statuses: Set<string> }>();
  for (const r of rows) {
    const cve = (String(refByVid.get(r.vid) || "").toUpperCase().match(CVE_RX) || [])[0];
    if (!cve) continue;
    const e = byCve.get(cve) ?? byCve.set(cve, { products: new Set(), statuses: new Set() }).get(cve)!;
    e.products.add(r.name);
    e.statuses.add(r.fp ? "not_affected" : /fixed|resolved|remediated|closed/i.test(r.status || "") ? "fixed" : "affected");
  }

  const ts = new Date().toISOString();
  const statements = [...byCve.entries()].map(([cve, e]) => {
    // status precedence: affected > under_investigation > fixed > not_affected
    const status = e.statuses.has("affected") ? "affected" : e.statuses.has("fixed") ? "fixed" : "not_affected";
    const st: Record<string, unknown> = {
      vulnerability: { name: cve },
      products: [...e.products].slice(0, 200).map((p) => ({ "@id": `pkg:xorcism/asset/${encodeURIComponent(p)}` })),
      status,
    };
    if (status === "affected") st.action_statement = "Remediate per the prioritized exposure worklist (see /exposure).";
    if (status === "not_affected") st.justification = "component_not_present";
    return st;
  });

  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `https://xorcism.ai/vex/${randomUUID()}`,
    author: "XORCISM",
    role: "Asset Owner",
    timestamp: ts,
    version: 1,
    statements,
  };
}
