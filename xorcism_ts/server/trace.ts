/**
 * trace.ts — TRACE threat-modeling methodology (Oak Security, CC BY 4.0).
 *
 * TRACE turns heterogeneous sources into a structured model of five first-class objects —
 * Threat actors, Roles, Assets, Critical invariants, Edges — then runs STRIDE, builds attack trees,
 * inspects collusion/coordination surfaces, and produces a mitigation roadmap, through a deliberately
 * sequential 6-phase workflow with human approval gates. It is evidence-driven: every model object
 * records its source or is flagged as an inferred assumption, and every threat should trace back to an
 * asset/invariant/role/edge.
 *
 * This module layers TRACE onto the existing THREATMODEL (Methodology="TRACE", TracePillar):
 *   TRACEACTOR/ROLE/ASSET/INVARIANT/EDGE  — the 5 model objects (evidence vs assumption)
 *   TRACECOLLUSION                        — coordination/collusion surfaces (phase 5)
 *   TRACEPHASE                            — the 6-phase workflow + approval gates
 *   THREATMODELTHREAT.TraceObjectType/ID  — STRIDE threats traced to a model object (coverage)
 *   ATTACKTREE                            — attack trees for top threats (phase 4, reused)
 *
 * Ref: https://github.com/oak-security/TRACE — TRACE™ is a trademark of Oak Security.
 */
import { randomUUID } from "crypto";
import { allocId, getDb } from "./db";

export const TRACE_PHASES = [
  { phase: 0, name: "Scope & source inventory" },
  { phase: 1, name: "Ingest sources" },
  { phase: 2, name: "Construct TRACE model" },
  { phase: 3, name: "STRIDE identification & ranking" },
  { phase: 4, name: "Build attack trees" },
  { phase: 5, name: "Collusion & coordination inspection" },
  { phase: 6, name: "Roadmap & report" },
];
export const TRACE_PILLARS = ["Protocol", "System", "Organisation"];
export const STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service", "Elevation of privilege"];

// object-type → table metadata (the 5 TRACE objects). `cols` are the type-specific text columns.
const OBJ: Record<string, { table: string; pk: string; cols: string[] }> = {
  actor: { table: "TRACEACTOR", pk: "TraceActorID", cols: ["Name", "Kind", "Capability", "Incentive"] },
  role: { table: "TRACEROLE", pk: "TraceRoleID", cols: ["Name", "Privilege"] },
  asset: { table: "TRACEASSET", pk: "TraceAssetID", cols: ["Name", "Kind", "Value"] },
  invariant: { table: "TRACEINVARIANT", pk: "TraceInvariantID", cols: ["Name", "Statement", "Category"] },
  edge: { table: "TRACEEDGE", pk: "TraceEdgeID", cols: ["Name", "FromDomain", "ToDomain", "Kind"] },
};

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const pct = (a: number, b: number): number => (b ? Math.round((a / b) * 100) : 0);
const tw = (tenant: number | null): string => (tenant != null ? " AND (TenantID = ? OR TenantID IS NULL)" : "");

function tmInScope(db: ReturnType<typeof getDb>, id: number, tenant: number | null): boolean {
  const r = db.prepare("SELECT TenantID FROM THREATMODEL WHERE ThreatModelID = ?").get(id) as { TenantID: number | null } | undefined;
  if (!r) return false;
  return tenant == null || r.TenantID == null || Number(r.TenantID) === tenant;
}

/** List TRACE threat models (Methodology = TRACE) for a tenant. */
export function listTraceModels(tenant: number | null): any {
  const db = getDb("XORCISM");
  if (!has(db, "THREATMODEL")) return { phases: TRACE_PHASES, pillars: TRACE_PILLARS, models: [] };
  const rows = (tenant != null
    ? db.prepare("SELECT * FROM THREATMODEL WHERE Methodology = 'TRACE' AND (TenantID = ? OR TenantID IS NULL) ORDER BY ThreatModelID DESC").all(tenant)
    : db.prepare("SELECT * FROM THREATMODEL WHERE Methodology = 'TRACE' ORDER BY ThreatModelID DESC").all()) as any[];
  const models = rows.map((m) => {
    const id = Number(m.ThreatModelID);
    const objs = (Object.values(OBJ).reduce((s, o) => s + num((db.prepare(`SELECT COUNT(*) n FROM ${o.table} WHERE ThreatModelID = ?`).get(id) as { n: number }).n), 0));
    const approved = has(db, "TRACEPHASE") ? num((db.prepare("SELECT COUNT(*) n FROM TRACEPHASE WHERE ThreatModelID = ? AND Status='approved'").get(id) as { n: number }).n) : 0;
    return { id, name: String(m.ThreatModelName ?? ""), pillar: String(m.TracePillar ?? ""), status: String(m.Status ?? "Draft"), objects: objs, phasesApproved: approved, phasesTotal: TRACE_PHASES.length };
  });
  return { phases: TRACE_PHASES, pillars: TRACE_PILLARS, stride: STRIDE, models };
}

/** Full TRACE model: header, 5 object lists, collusion, STRIDE threats, attack trees, phases, coverage. */
export function traceModel(threatModelId: number, tenant: number | null): any {
  const db = getDb("XORCISM");
  if (!has(db, "THREATMODEL")) return null;
  const m = db.prepare("SELECT * FROM THREATMODEL WHERE ThreatModelID = ?").get(threatModelId) as any;
  if (!m || !tmInScope(db, threatModelId, tenant)) return null;

  const objects: Record<string, any[]> = {};
  for (const [type, o] of Object.entries(OBJ)) {
    objects[type] = (db.prepare(`SELECT * FROM ${o.table} WHERE ThreatModelID = ? ORDER BY ${o.pk}`).all(threatModelId) as any[])
      .map((r) => ({ id: Number(r[o.pk]), assumption: Number(r.Assumption) === 1, evidence: String(r.Evidence ?? ""), notes: String(r.Notes ?? ""), ...Object.fromEntries(o.cols.map((c) => [c.toLowerCase(), String(r[c] ?? "")])) }));
  }
  const collusion = has(db, "TRACECOLLUSION")
    ? (db.prepare("SELECT * FROM TRACECOLLUSION WHERE ThreatModelID = ? ORDER BY TraceCollusionID").all(threatModelId) as any[])
      .map((r) => ({ id: Number(r.TraceCollusionID), actors: String(r.Actors ?? ""), quorum: String(r.QuorumAssumption ?? ""), credible: Number(r.Credible) === 1, notes: String(r.Notes ?? "") })) : [];

  const threats = has(db, "THREATMODELTHREAT")
    ? (db.prepare("SELECT ThreatModelThreatID, Title, STRIDECategory, Likelihood, Impact, Status, TraceObjectType, TraceObjectID FROM THREATMODELTHREAT WHERE ThreatModelID = ? ORDER BY ThreatModelThreatID").all(threatModelId) as any[])
      .map((r) => ({ id: Number(r.ThreatModelThreatID), title: String(r.Title ?? ""), stride: String(r.STRIDECategory ?? ""), likelihood: String(r.Likelihood ?? ""), impact: String(r.Impact ?? ""), status: String(r.Status ?? ""), traceType: r.TraceObjectType ? String(r.TraceObjectType) : null, traceId: r.TraceObjectID != null ? Number(r.TraceObjectID) : null })) : [];
  const attackTrees = has(db, "ATTACKTREE")
    ? (db.prepare("SELECT AttackTreeID, Name, Goal FROM ATTACKTREE WHERE ThreatModelID = ? ORDER BY AttackTreeID").all(threatModelId) as any[])
      .map((r) => ({ id: Number(r.AttackTreeID), name: String(r.Name ?? ""), goal: String(r.Goal ?? "") })) : [];

  let phases = has(db, "TRACEPHASE") ? (db.prepare("SELECT Phase, Name, Status, ApprovedBy, ApprovedAt FROM TRACEPHASE WHERE ThreatModelID = ? ORDER BY Phase").all(threatModelId) as any[])
    .map((r) => ({ phase: Number(r.Phase), name: String(r.Name ?? ""), status: String(r.Status ?? "pending"), approvedBy: String(r.ApprovedBy ?? ""), approvedAt: String(r.ApprovedAt ?? "") })) : [];
  if (!phases.length) phases = TRACE_PHASES.map((p) => ({ ...p, status: "pending", approvedBy: "", approvedAt: "" }));

  return {
    model: { id: Number(m.ThreatModelID), name: String(m.ThreatModelName ?? ""), description: String(m.Description ?? ""), pillar: String(m.TracePillar ?? ""), status: String(m.Status ?? "Draft"), scope: String(m.Scope ?? "") },
    pillars: TRACE_PILLARS, stride: STRIDE,
    objects, collusion, threats, attackTrees, phases,
    coverage: traceCoverage(threatModelId, { objects, threats, attackTrees, phases, collusion }),
  };
}

/** Output-quality / coverage scorecard (TRACE's "Output Quality Criteria"). */
export function traceCoverage(threatModelId: number, pre?: any): any {
  const db = getDb("XORCISM");
  const objects = pre?.objects ?? Object.fromEntries(Object.entries(OBJ).map(([t, o]) => [t, db.prepare(`SELECT ${o.pk} id FROM ${o.table} WHERE ThreatModelID = ?`).all(threatModelId).map((r: any) => ({ id: Number(r.id) }))]));
  const threats = pre?.threats ?? (db.prepare("SELECT ThreatModelThreatID id, TraceObjectType t, TraceObjectID oid FROM THREATMODELTHREAT WHERE ThreatModelID = ?").all(threatModelId) as any[]).map((r) => ({ id: Number(r.id), traceType: r.t || null, traceId: r.oid != null ? Number(r.oid) : null }));
  const attackTrees = pre?.attackTrees ?? (db.prepare("SELECT AttackTreeID id FROM ATTACKTREE WHERE ThreatModelID = ?").all(threatModelId) as any[]);
  const phases = pre?.phases ?? [];

  const linked = (type: string) => new Set(threats.filter((t: any) => t.traceType === type && t.traceId != null).map((t: any) => t.traceId));
  const assetLinks = linked("asset"), invLinks = linked("invariant"), edgeLinks = linked("edge");
  const assetsTotal = objects.asset.length, invTotal = objects.invariant.length, edgeTotal = objects.edge.length;
  const assetsCovered = objects.asset.filter((a: any) => assetLinks.has(a.id)).length;
  const invCovered = objects.invariant.filter((a: any) => invLinks.has(a.id)).length;
  const edgesReviewed = objects.edge.filter((a: any) => edgeLinks.has(a.id)).length;
  const traceable = threats.filter((t: any) => !!t.traceType).length;
  const approved = phases.filter((p: any) => p.status === "approved").length;

  const parts = [
    pct(assetsCovered, assetsTotal || 1),
    pct(invCovered, invTotal || 1),
    pct(edgesReviewed, edgeTotal || 1),
    pct(traceable, threats.length || 1),
    attackTrees.length ? 100 : 0,
    pct(approved, TRACE_PHASES.length),
  ];
  const quality = Math.round(parts.reduce((a, b) => a + b, 0) / parts.length);
  return {
    actors: objects.actor.length, roles: objects.role.length, assets: assetsTotal, invariants: invTotal, edges: edgeTotal,
    threats: threats.length, traceable, traceabilityPct: pct(traceable, threats.length || 1),
    assetsCovered, assetCoveragePct: pct(assetsCovered, assetsTotal || 1),
    invariantsCovered: invCovered, edgesReviewed, edgeReviewPct: pct(edgesReviewed, edgeTotal || 1),
    attackTrees: attackTrees.length, collusion: pre?.collusion?.length ?? 0,
    phasesApproved: approved, phasesTotal: TRACE_PHASES.length, qualityScore: quality,
  };
}

// ── mutations ────────────────────────────────────────────────────────────────
/** Create a TRACE threat model (THREATMODEL Methodology=TRACE) + seed the 6-phase workflow. */
export function createTraceModel(p: { name: string; pillar?: string; description?: string; scope?: string }, tenant: number | null): { id: number } {
  const db = getDb("XORCISM");
  const id = allocId(db, "THREATMODEL", "ThreatModelID");
  const pillar = TRACE_PILLARS.includes(String(p.pillar)) ? String(p.pillar) : "System";
  db.prepare("INSERT INTO THREATMODEL (ThreatModelID, ThreatModelGUID, ThreatModelName, Description, Methodology, Status, Scope, TracePillar, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, randomUUID(), (p.name || "TRACE model").slice(0, 200), (p.description || "").slice(0, 2000), "TRACE", "Draft", (p.scope || "").slice(0, 2000), pillar, new Date().toISOString(), tenant);
  let pid = allocId(db, "TRACEPHASE", "TracePhaseID");
  const ins = db.prepare("INSERT INTO TRACEPHASE (TracePhaseID, ThreatModelID, Phase, Name, Status, TenantID) VALUES (?,?,?,?,?,?)");
  for (const ph of TRACE_PHASES) ins.run(pid++, id, ph.phase, ph.name, "pending", tenant);
  return { id };
}

/** Add a TRACE model object (actor/role/asset/invariant/edge). */
export function addTraceObject(threatModelId: number, type: string, fields: Record<string, unknown>, tenant: number | null): { id: number } | null {
  const o = OBJ[type];
  const db = getDb("XORCISM");
  if (!o || !tmInScope(db, threatModelId, tenant)) return null;
  const id = allocId(db, o.table, o.pk);
  const cols = [o.pk, "ThreatModelID", ...o.cols, "Evidence", "Assumption", "Notes", "CreatedDate", "TenantID"];
  const vals: unknown[] = [id, threatModelId,
    ...o.cols.map((c) => String(fields[c.toLowerCase()] ?? fields[c] ?? "").slice(0, 1000)),
    String(fields.evidence ?? "").slice(0, 2000), fields.assumption ? 1 : 0, String(fields.notes ?? "").slice(0, 2000),
    new Date().toISOString(), tenant];
  db.prepare(`INSERT INTO ${o.table} (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`).run(...vals);
  return { id };
}

export function deleteTraceObject(type: string, id: number, tenant: number | null): boolean {
  const o = OBJ[type]; const db = getDb("XORCISM");
  if (!o) return false;
  const row = db.prepare(`SELECT ThreatModelID FROM ${o.table} WHERE ${o.pk} = ?`).get(id) as { ThreatModelID: number } | undefined;
  if (!row || !tmInScope(db, Number(row.ThreatModelID), tenant)) return false;
  db.prepare(`DELETE FROM ${o.table} WHERE ${o.pk} = ?`).run(id);
  // drop any STRIDE-threat links pointing at it
  db.prepare("UPDATE THREATMODELTHREAT SET TraceObjectType = NULL, TraceObjectID = NULL WHERE TraceObjectType = ? AND TraceObjectID = ?").run(type, id);
  return true;
}

export function addCollusion(threatModelId: number, p: { actors: string; quorum?: string; credible?: boolean; notes?: string }, tenant: number | null): { id: number } | null {
  const db = getDb("XORCISM");
  if (!tmInScope(db, threatModelId, tenant)) return null;
  const id = allocId(db, "TRACECOLLUSION", "TraceCollusionID");
  db.prepare("INSERT INTO TRACECOLLUSION (TraceCollusionID, ThreatModelID, Actors, QuorumAssumption, Credible, Notes, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?)")
    .run(id, threatModelId, (p.actors || "").slice(0, 500), (p.quorum || "").slice(0, 500), p.credible ? 1 : 0, (p.notes || "").slice(0, 2000), new Date().toISOString(), tenant);
  return { id };
}
export function deleteCollusion(id: number, tenant: number | null): boolean {
  const db = getDb("XORCISM");
  const row = db.prepare("SELECT ThreatModelID FROM TRACECOLLUSION WHERE TraceCollusionID = ?").get(id) as { ThreatModelID: number } | undefined;
  if (!row || !tmInScope(db, Number(row.ThreatModelID), tenant)) return false;
  db.prepare("DELETE FROM TRACECOLLUSION WHERE TraceCollusionID = ?").run(id);
  return true;
}

/** Add a STRIDE threat to the model, optionally traced to a model object (phase 3). */
export function addTraceThreat(threatModelId: number, p: { title: string; stride?: string; description?: string; likelihood?: string; impact?: string; traceType?: string; traceId?: number }, tenant: number | null): { id: number } | null {
  const db = getDb("XORCISM");
  if (!tmInScope(db, threatModelId, tenant)) return null;
  const id = allocId(db, "THREATMODELTHREAT", "ThreatModelThreatID");
  const stride = STRIDE.includes(String(p.stride)) ? String(p.stride) : "";
  db.prepare("INSERT INTO THREATMODELTHREAT (ThreatModelThreatID, ThreatModelID, Title, STRIDECategory, Description, Likelihood, Impact, Status, TraceObjectType, TraceObjectID, CreatedDate, TenantID) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, threatModelId, (p.title || "Threat").slice(0, 300), stride, (p.description || "").slice(0, 2000), (p.likelihood || "").slice(0, 30), (p.impact || "").slice(0, 30), "Open",
      p.traceType && OBJ[p.traceType] ? p.traceType : null, p.traceId != null ? Number(p.traceId) : null, new Date().toISOString(), tenant);
  return { id };
}

/** Trace an existing STRIDE threat to a model object (for coverage). */
export function setThreatTraceLink(threatId: number, objType: string | null, objId: number | null, tenant: number | null): boolean {
  const db = getDb("XORCISM");
  const row = db.prepare("SELECT ThreatModelID FROM THREATMODELTHREAT WHERE ThreatModelThreatID = ?").get(threatId) as { ThreatModelID: number } | undefined;
  if (!row || !tmInScope(db, Number(row.ThreatModelID), tenant)) return false;
  const t = objType && OBJ[objType] ? objType : null;
  db.prepare("UPDATE THREATMODELTHREAT SET TraceObjectType = ?, TraceObjectID = ? WHERE ThreatModelThreatID = ?").run(t, t ? (objId ?? null) : null, threatId);
  return true;
}

/** Advance/approve a workflow phase. Approval is gated: a phase can only be approved once the
 *  previous phase is approved (the sequential, reviewable TRACE workflow). */
export function advancePhase(threatModelId: number, phase: number, status: string, by: string, tenant: number | null): { ok: boolean; error?: string } {
  const db = getDb("XORCISM");
  if (!tmInScope(db, threatModelId, tenant)) return { ok: false, error: "not found" };
  const st = ["pending", "in-progress", "approved"].includes(status) ? status : "in-progress";
  if (st === "approved" && phase > 0) {
    const prev = db.prepare("SELECT Status FROM TRACEPHASE WHERE ThreatModelID = ? AND Phase = ?").get(threatModelId, phase - 1) as { Status: string } | undefined;
    if (!prev || prev.Status !== "approved") return { ok: false, error: `phase ${phase - 1} must be approved first (sequential gate)` };
  }
  const now = new Date().toISOString();
  db.prepare("UPDATE TRACEPHASE SET Status = ?, ApprovedBy = ?, ApprovedAt = ? WHERE ThreatModelID = ? AND Phase = ?")
    .run(st, st === "approved" ? by : null, st === "approved" ? now : null, threatModelId, phase);
  return { ok: true };
}

/** Seed a small demo TRACE model (idempotent: skips if a TRACE model already exists for the tenant). */
export function seedTraceDemo(tenant: number): { created: number } {
  const db = getDb("XORCISM");
  if (db.prepare("SELECT 1 FROM THREATMODEL WHERE Methodology='TRACE' AND IFNULL(TenantID,-1)=IFNULL(?,-1) LIMIT 1").get(tenant)) return { created: 0 };
  const { id } = createTraceModel({ name: "Treasury multisig & deploy pipeline", pillar: "System", description: "Demo TRACE model over a Web3 treasury + CI/CD deploy path.", scope: "Multisig custody, signer devices, CI/CD to mainnet deploy." }, tenant);
  addTraceObject(id, "actor", { name: "Compromised signer device", kind: "Insider/compromised", capability: "Holds a signing key", incentive: "Theft", evidence: "Signer laptops in scope", assumption: false }, tenant);
  addTraceObject(id, "actor", { name: "Malicious CI maintainer", kind: "Insider", capability: "Can alter the deploy workflow", incentive: "Backdoor a release", assumption: true }, tenant);
  addTraceObject(id, "role", { name: "Multisig signer (3-of-5)", privilege: "Approves treasury transfers" }, tenant);
  addTraceObject(id, "role", { name: "Deployer", privilege: "Pushes contracts to mainnet" }, tenant);
  const aFunds = addTraceObject(id, "asset", { name: "Treasury funds", kind: "Funds", value: "High", evidence: "On-chain treasury" }, tenant);
  const aKeys = addTraceObject(id, "asset", { name: "Signing keys", kind: "Keys", value: "Critical" }, tenant);
  const iSod = addTraceObject(id, "invariant", { name: "Segregation of duties", statement: "No single actor can both approve and execute a transfer.", category: "Bounded authority" }, tenant);
  addTraceObject(id, "invariant", { name: "Deployment integrity", statement: "Only reviewed, signed artifacts reach mainnet.", category: "Deployment integrity" }, tenant);
  const eCi = addTraceObject(id, "edge", { name: "CI/CD → mainnet deploy", fromDomain: "CI/CD", toDomain: "Blockchain", kind: "Deploy authority" }, tenant);
  addTraceObject(id, "edge", { name: "Signer device → multisig", fromDomain: "Endpoint", toDomain: "Multisig", kind: "Signer path" }, tenant);
  // a couple of STRIDE threats traced to objects
  addTraceThreat(id, { title: "Quorum capture: collusion of 3 signers drains treasury", stride: "Elevation of privilege", likelihood: "Low", impact: "Critical", traceType: "asset", traceId: aFunds?.id }, tenant);
  addTraceThreat(id, { title: "Tampered CI artifact deployed to mainnet", stride: "Tampering", likelihood: "Medium", impact: "Critical", traceType: "edge", traceId: eCi?.id }, tenant);
  addTraceThreat(id, { title: "Signer key exfiltration from compromised device", stride: "Information disclosure", likelihood: "Medium", impact: "High", traceType: "asset", traceId: aKeys?.id }, tenant);
  addCollusion(id, { actors: "3 of 5 multisig signers", quorum: "3-of-5 threshold", credible: true, notes: "Threshold equals collusion size — accountable-fault assumption weak." }, tenant);
  void iSod;
  return { created: 1 };
}
