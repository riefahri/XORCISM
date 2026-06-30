/**
 * aisbom.ts — AI SBOM minimum-elements conformance (CISA / G7 "SBOM for AI — Minimum Elements").
 *
 * The 7 clusters / 50 supplemental minimum elements are a reference catalogue (AISBOMELEMENT, seeded
 * at boot). Each AI system being documented is an AISBOM instance whose coverage of every element is
 * tracked (Present / Partial / Missing / Not applicable) in AISBOMCOVERAGE; this rolls up to a per-
 * cluster and overall completeness score + a gap worklist — i.e. "how transparent is the SBOM for this
 * AI system against the G7 minimum?". Supplements [[sca-sbom]] (software components) and [[cbom]].
 */
import { allocId, getDb } from "./db";
import { randomUUID } from "crypto";
import { AI_SBOM_CLUSTERS } from "./data/aiSbomElements";

const STATUSES = ["Present", "Partial", "Missing", "Not applicable"];
const WEIGHT: Record<string, number> = { Present: 1, Partial: 0.5, Missing: 0 };
const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const r0 = (x: number): number => Math.round(x);

export interface AiSbomElementRow { id: number; cluster: string; clusterName: string; element: string; description: string; example: string; }

export function aiSbomCatalog(): AiSbomElementRow[] {
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return []; }
  if (!has(cc, "AISBOMELEMENT")) return [];
  return (cc.prepare("SELECT ElementID, ClusterCode, ClusterName, Element, Description, Example FROM AISBOMELEMENT ORDER BY SortOrder").all() as any[])
    .map((e) => ({ id: Number(e.ElementID), cluster: String(e.ClusterCode), clusterName: String(e.ClusterName), element: String(e.Element), description: String(e.Description ?? ""), example: String(e.Example ?? "") }));
}

/** Completeness over a coverage map (status by elementId) against the full catalogue. */
function score(catalog: AiSbomElementRow[], cov: Map<number, { status: string }>): { byCluster: any[]; overall: number; present: number; partial: number; missing: number; na: number; applicable: number } {
  const byClusterMap = new Map<string, { code: string; name: string; total: number; applicable: number; weighted: number; present: number }>();
  let present = 0, partial = 0, missing = 0, na = 0;
  for (const e of catalog) {
    const st = cov.get(e.id)?.status || "Missing";
    let cl = byClusterMap.get(e.cluster);
    if (!cl) { cl = { code: e.cluster, name: e.clusterName, total: 0, applicable: 0, weighted: 0, present: 0 }; byClusterMap.set(e.cluster, cl); }
    cl.total++;
    if (st === "Not applicable") { na++; continue; }
    cl.applicable++;
    const w = WEIGHT[st] ?? 0;
    cl.weighted += w;
    if (st === "Present") { present++; cl.present++; }
    else if (st === "Partial") partial++;
    else missing++;
  }
  const order = AI_SBOM_CLUSTERS.map((c) => c.code);
  const byCluster = [...byClusterMap.values()].sort((a, b) => order.indexOf(a.code) - order.indexOf(b.code))
    .map((c) => ({ code: c.code, name: c.name, total: c.total, applicable: c.applicable, present: c.present, completeness: c.applicable ? r0((c.weighted / c.applicable) * 100) : 100 }));
  const applicable = present + partial + missing;
  const weighted = present + partial * 0.5;
  return { byCluster, overall: applicable ? r0((weighted / applicable) * 100) : 0, present, partial, missing, na, applicable };
}

/** List every AI-SBOM instance for a tenant with its overall completeness. */
export function listAiSboms(tenant: number | null): any {
  const catalog = aiSbomCatalog();
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return { clusters: AI_SBOM_CLUSTERS, catalogSize: 0, sboms: [] }; }
  if (!has(cc, "AISBOM")) return { clusters: AI_SBOM_CLUSTERS, catalogSize: catalog.length, sboms: [] };
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = (tenant != null ? cc.prepare(`SELECT * FROM AISBOM ${tw} ORDER BY AiSbomID DESC`).all(tenant) : cc.prepare("SELECT * FROM AISBOM ORDER BY AiSbomID DESC").all()) as any[];
  const sboms = rows.map((r) => {
    const cov = new Map<number, { status: string }>();
    for (const c of cc!.prepare("SELECT ElementID, Status FROM AISBOMCOVERAGE WHERE AiSbomID = ?").all(r.AiSbomID) as any[]) cov.set(Number(c.ElementID), { status: String(c.Status) });
    const s = score(catalog, cov);
    return { id: Number(r.AiSbomID), name: String(r.Name ?? ""), producer: String(r.Producer ?? ""), version: String(r.Version ?? ""), format: String(r.Format ?? ""), status: String(r.Status ?? "Draft"), completeness: s.overall, present: s.present, missing: s.missing, applicable: s.applicable };
  });
  return { clusters: AI_SBOM_CLUSTERS, catalogSize: catalog.length, sboms };
}

/** Full detail for one AI-SBOM instance: per-cluster + per-element coverage + worklist. */
export function aiSbomDetail(id: number, tenant: number | null): any {
  const catalog = aiSbomCatalog();
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return null; }
  if (!has(cc, "AISBOM")) return null;
  const r = cc.prepare("SELECT * FROM AISBOM WHERE AiSbomID = ?").get(id) as any;
  if (!r) return null;
  if (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant) return null;
  const cov = new Map<number, { status: string; value: string; notes: string }>();
  for (const c of cc.prepare("SELECT ElementID, Status, Value, Notes FROM AISBOMCOVERAGE WHERE AiSbomID = ?").all(id) as any[])
    cov.set(Number(c.ElementID), { status: String(c.Status), value: String(c.Value ?? ""), notes: String(c.Notes ?? "") });
  const s = score(catalog, cov);
  const elements = catalog.map((e) => {
    const c = cov.get(e.id);
    return { ...e, status: c?.status || "Missing", value: c?.value || "", notes: c?.notes || "" };
  });
  const worklist = elements.filter((e) => e.status === "Missing")
    .map((e) => ({ id: e.id, cluster: e.cluster, element: e.element, severity: ["MODEL", "DATA", "SEC"].includes(e.cluster) ? "High" : "Medium" }))
    .slice(0, 60);
  return {
    statuses: STATUSES,
    sbom: { id: Number(r.AiSbomID), name: String(r.Name ?? ""), producer: String(r.Producer ?? ""), version: String(r.Version ?? ""), format: String(r.Format ?? ""), status: String(r.Status ?? "Draft"), notes: String(r.Notes ?? "") },
    elements, byCluster: s.byCluster,
    summary: { overall: s.overall, present: s.present, partial: s.partial, missing: s.missing, na: s.na, applicable: s.applicable, total: catalog.length },
    worklist,
  };
}

export function createAiSbom(p: { name: string; producer?: string; version?: string; format?: string; notes?: string }, tenant: number | null): { id: number } {
  const cc = getDb("XCOMPLIANCE");
  const id = allocId(cc, "AISBOM", "AiSbomID");
  cc.prepare("INSERT INTO AISBOM (AiSbomID, AiSbomGUID, Name, Producer, Version, Format, Status, Notes, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), (p.name || "AI system").slice(0, 200), (p.producer || "").slice(0, 200), (p.version || "").slice(0, 60), (p.format || "CycloneDX").slice(0, 60), "Draft", (p.notes || "").slice(0, 1000), tenant, new Date().toISOString());
  return { id };
}

export function setCoverage(aiSbomId: number, elementId: number, p: { status?: string; value?: string; notes?: string }, tenant: number | null): boolean {
  const cc = getDb("XCOMPLIANCE");
  const r = cc.prepare("SELECT TenantID FROM AISBOM WHERE AiSbomID = ?").get(aiSbomId) as { TenantID: number | null } | undefined;
  if (!r) return false;
  if (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant) return false;
  if (!cc.prepare("SELECT 1 FROM AISBOMELEMENT WHERE ElementID = ?").get(elementId)) return false;
  const status = p.status && STATUSES.includes(p.status) ? p.status : undefined;
  const now = new Date().toISOString();
  const ex = cc.prepare("SELECT CoverageID FROM AISBOMCOVERAGE WHERE AiSbomID = ? AND ElementID = ?").get(aiSbomId, elementId) as { CoverageID: number } | undefined;
  if (ex) {
    const sets: string[] = ["UpdatedDate = ?"]; const vals: unknown[] = [now];
    if (status) { sets.push("Status = ?"); vals.push(status); }
    if (p.value != null) { sets.push("Value = ?"); vals.push(String(p.value).slice(0, 1000)); }
    if (p.notes != null) { sets.push("Notes = ?"); vals.push(String(p.notes).slice(0, 1000)); }
    vals.push(ex.CoverageID);
    cc.prepare(`UPDATE AISBOMCOVERAGE SET ${sets.join(", ")} WHERE CoverageID = ?`).run(...vals);
  } else {
    const id = allocId(cc, "AISBOMCOVERAGE", "CoverageID");
    cc.prepare("INSERT INTO AISBOMCOVERAGE (CoverageID, AiSbomID, ElementID, Status, Value, Notes, UpdatedDate) VALUES (?,?,?,?,?,?,?)")
      .run(id, aiSbomId, elementId, status ?? "Present", String(p.value ?? "").slice(0, 1000), String(p.notes ?? "").slice(0, 1000), now);
  }
  return true;
}

export function deleteAiSbom(id: number, tenant: number | null): boolean {
  const cc = getDb("XCOMPLIANCE");
  const r = cc.prepare("SELECT TenantID FROM AISBOM WHERE AiSbomID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!r || (tenant != null && r.TenantID != null && Number(r.TenantID) !== tenant)) return false;
  cc.prepare("DELETE FROM AISBOMCOVERAGE WHERE AiSbomID = ?").run(id);
  cc.prepare("DELETE FROM AISBOM WHERE AiSbomID = ?").run(id);
  return true;
}

/** Seed a realistic demo AI-SBOM (idempotent: skips if any instance exists for the tenant). */
export function seedAiSbom(tenant: number): { created: number } {
  const cc = getDb("XCOMPLIANCE");
  if (!has(cc, "AISBOM")) return { created: 0 };
  if ((cc.prepare("SELECT COUNT(*) n FROM AISBOM WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { created: 0 };
  const { id } = createAiSbom({ name: "Customer-support RAG assistant", producer: "Acme AI", version: "2.1", format: "CycloneDX 1.6", notes: "Demo AI SBOM against the CISA/G7 minimum elements." }, tenant);
  const catalog = aiSbomCatalog();
  // a believable mid-coverage: metadata/system/model mostly present, datasets/security partial/missing
  for (const e of catalog) {
    let st = "Present";
    if (e.cluster === "DATA") st = e.element.includes("statistical") || e.element.includes("provenance") ? "Missing" : "Partial";
    else if (e.cluster === "SEC") st = e.element.includes("policy") ? "Missing" : "Partial";
    else if (e.cluster === "KPI") st = "Partial";
    else if (e.element === "SBOM author signature") st = "Missing";
    else if ((Number(e.id) * 7) % 9 === 0) st = "Partial";
    setCoverage(id, e.id, { status: st }, tenant);
  }
  return { created: 1 };
}
