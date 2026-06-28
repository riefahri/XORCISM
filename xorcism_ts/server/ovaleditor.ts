/**
 * ovaleditor.ts — author/edit OVAL Definitions in XORCISM (the /oval-editor page).
 *
 * The legacy XOVAL database holds a fully-relational OVAL repository (35k+ definitions, 140k+ tests)
 * but objects/states/variables were not imported. So this editor authors the part that IS reusable:
 * a DEFINITION (metadata) + its CRITERIA TREE, whose leaves reference EXISTING imported OVAL tests
 * (criterion → OVALTEST) and definitions (extend_definition → OVALDEFINITION). It persists the tree
 * relationally (exactly like the imported definitions) AND stores a generated, OVAL-5.11-compliant
 * <oval_definitions> document in OVALDEFINITION.BLOB.
 *
 * Relational model (confirmed against the live data):
 *   OVALDEFINITION.OVALCriteriaID            -> root OVALCRITERIA node
 *   OVALCRITERIA (operator/negate/comment/applicabilitycheck) = a criteria node
 *   OVALCRITERIACRITERION (OVALCriteriaID -> OVALTestID)         = criterion leaf (test_ref)
 *   OVALCRITERIAEXTENDDEFINITION (OVALCriteriaID -> OVALDefinitionID) = extend_definition leaf
 *   OVALCRITERIAFOROVALCRITERIA (Ref=parent, Subject=child, CriteriaRank) = nested criteria
 *
 * Authored definitions use the namespace oval:ai.xorcism:def:N and RepositoryID = AUTHORED_REPO so
 * they stay separable from the imported CIS/MITRE reference content.
 */
import { getDb, allocId } from "./db";
import { randomUUID } from "crypto";

export const OVAL_NS = "ai.xorcism";              // authored-definition namespace
// OVAL-Community (github.com/OVAL-Community/OVAL) schema versions. 5.12.x is the current SCAP-1.4-aligned
// line; 5.11.2 is kept for OpenSCAP (still 5.11.x) interoperability. Default = latest stable.
export const OVAL_SCHEMA_VERSIONS = ["5.12.3", "5.12.1", "5.11.2"];
export const OVAL_SCHEMA_VERSION = OVAL_SCHEMA_VERSIONS[0];
const AUTHORED_REPO = 9001;                        // RepositoryID marker for XORCISM-authored defs
// oval-common-5 FamilyEnumeration (the `affected family` attribute).
const FAMILIES = ["windows", "unix", "linux", "macos", "ios", "ios_xe", "android", "apache", "asa",
  "catos", "esx", "freebsd", "hpux", "junos", "pixos", "sharepoint", "solaris", "vmware_infrastructure", "undefined"];

function cols(table: string): Set<string> {
  try { return new Set((getDb("XOVAL").prepare(`PRAGMA table_info("${table}")`).all() as { name: string }[]).map((c) => c.name)); }
  catch { return new Set(); }
}
function ins(db: ReturnType<typeof getDb>, table: string, rec: Record<string, unknown>, present: Set<string>): void {
  const keys = Object.keys(rec).filter((k) => present.has(k));
  db.prepare(`INSERT INTO "${table}" (${keys.map((k) => `"${k}"`).join(",")}) VALUES (${keys.map(() => "?").join(",")})`).run(...keys.map((k) => rec[k]));
}
const xe = (s: unknown): string => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c]!));

// ── enums / reference data for the editor comboboxes ───────────────────────────
/** Ensure the four OVAL set-operators exist (the import only seeded AND/OR; the spec also has ONE/XOR). */
function ensureOperators(): Map<string, number> {
  const xv = getDb("XOVAL");
  const want = ["AND", "OR", "ONE", "XOR"];
  const have = new Map<string, number>();
  for (const r of xv.prepare(`SELECT OperatorEnumerationID id, OperatorValue v FROM OPERATORENUMERATION`).all() as { id: number; v: string }[]) have.set(String(r.v).toUpperCase(), Number(r.id));
  const oc = cols("OPERATORENUMERATION");
  for (const v of want) {
    if (!have.has(v)) {
      const id = allocId(xv, "OPERATORENUMERATION", "OperatorEnumerationID");
      ins(xv, "OPERATORENUMERATION", { OperatorEnumerationID: id, OperatorValue: v, OperatorDescription: `OVAL ${v} operator`, CreatedDate: new Date().toISOString() }, oc);
      have.set(v, id);
    }
  }
  return have;
}

export function ovalEditorMeta(): {
  classes: { id: number; value: string }[]; operators: string[]; families: string[];
  schemaVersion: string; schemaVersions: string[]; namespace: string;
} {
  const xv = getDb("XOVAL");
  ensureOperators();
  const classes = xv.prepare(`SELECT OVALClassEnumerationID id, ClassValue value FROM OVALCLASSENUMERATION ORDER BY OVALClassEnumerationID`).all() as { id: number; value: string }[];
  return { classes, operators: ["AND", "OR", "ONE", "XOR"], families: FAMILIES, schemaVersion: OVAL_SCHEMA_VERSION, schemaVersions: OVAL_SCHEMA_VERSIONS, namespace: OVAL_NS };
}

/** Search imported OVAL tests for the criterion combobox (by id pattern or comment). */
export function searchOvalTests(q: string, limit = 40): { id: number; idPattern: string; comment: string; hasContent: boolean }[] {
  const term = `%${q}%`;
  return (getDb("XOVAL").prepare(
    `SELECT OVALTestID id, OVALTestIDPattern idPattern, comment,
            CASE WHEN BLOB IS NOT NULL AND length(BLOB) > 0 THEN 1 ELSE 0 END hasContent FROM OVALTEST
     WHERE OVALTestIDPattern LIKE ? OR comment LIKE ? ORDER BY OVALTestID LIMIT ?`
  ).all(term, term, Math.min(limit, 100)) as { id: number; idPattern: string; comment: string; hasContent: number }[])
    .map((r) => ({ ...r, hasContent: !!r.hasContent }));
}

/** Search imported OVAL definitions for the extend_definition combobox. */
export function searchOvalDefsForExtend(q: string, limit = 40): { id: number; idPattern: string; title: string }[] {
  const term = `%${q}%`;
  return getDb("XOVAL").prepare(
    `SELECT OVALDefinitionID id, OVALDefinitionIDPattern idPattern, OVALDefinitionTitle title FROM OVALDEFINITION
     WHERE OVALDefinitionIDPattern LIKE ? OR OVALDefinitionTitle LIKE ? ORDER BY OVALDefinitionID LIMIT ?`
  ).all(term, term, Math.min(limit, 100)) as { id: number; idPattern: string; title: string }[];
}

// ── OVAL test content (objects / states / variables) — import & inspect ─────────
// XOVAL imported only the definition→criteria→test skeleton: OVALOBJECT/OVALSTATE are empty and
// OVALTEST.BLOB is NULL, so a criterion's test shows only an id + comment. To let the editor SHOW
// what a test actually checks, an admin uploads a full OVAL document; per <*_test> we extract a
// self-contained bundle (the test element + its referenced object / states / variables, verbatim with
// their original namespace prefixes) into OVALTEST.BLOB. Same dependency-free, namespace-tolerant,
// match-by-local-name approach as arf.ts (the repo has no XML-parser dependency).

export interface OvalEntity { name: string; operation?: string; datatype?: string; varRef?: string; value?: string; }
export interface OvalTestBundle {
  id: string; type: string; family?: string; check?: string; checkExistence?: string; comment?: string;
  object?: { id: string; comment?: string; entities: OvalEntity[]; xml: string };
  states: { id: string; comment?: string; entities: OvalEntity[]; xml: string }[];
  variables: { id: string; type: string; xml: string }[];
  xml: string;
}

// <prefix:foo_<suffix> …>…</…> OR self-closing — match by local-name suffix (_test/_object/_state/_variable).
const reLocalSuffix = (suffix: string, g = ""): RegExp =>
  new RegExp(`<((?:[\\w.\\-]+:)?[\\w.\\-]*${suffix})\\b([^>]*?)(?:/>|>([\\s\\S]*?)</(?:[\\w.\\-]+:)?[\\w.\\-]*${suffix}\\s*>)`, g);
const attrOf = (attrs: string, name: string): string | undefined => {
  const m = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`).exec(attrs || "");
  return m ? m[1] : undefined;
};
const openAttrs = (elXml: string): string => { const m = /^<[^>]*?>/.exec(elXml || ""); return m ? m[0] : ""; };
const localName = (tag: string): string => tag.replace(/^[\w.\-]+:/, "");
const nsPrefix = (tag: string): string | undefined => (tag.includes(":") ? tag.split(":")[0] : undefined);

/** Extract an object/state element's direct child entities (name/operation/datatype/value or var_ref). */
function entitiesOf(elementXml: string): OvalEntity[] {
  const inner = elementXml.replace(/^<[^>]*?>/, "").replace(/<\/[^>]*?>\s*$/, "");
  const out: OvalEntity[] = [];
  const re = /<((?:[\w.\-]+:)?[\w.\-]+)\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[\w.\-]+:)?[\w.\-]+\s*>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) {
    out.push({ name: localName(m[1]), operation: attrOf(m[2], "operation"), datatype: attrOf(m[2], "datatype"),
      varRef: attrOf(m[2], "var_ref"), value: (m[3] ?? "").trim() || undefined });
    if (out.length > 60) break;
  }
  return out;
}

/** Parse an OVAL document (or a stored bundle) → one OvalTestBundle per <*_test>, with object/states/variables resolved by ref. */
export function parseOvalTests(xml: string): OvalTestBundle[] {
  const objById = new Map<string, string>(), stById = new Map<string, string>(), varById = new Map<string, { xml: string; type: string }>();
  for (const suffix of ["_object", "_state", "_variable"] as const) {
    const re = reLocalSuffix(suffix, "g"); let m: RegExpExecArray | null;
    while ((m = re.exec(xml)) !== null) {
      const id = attrOf(m[2], "id"); if (!id) continue;
      if (suffix === "_object") objById.set(id, m[0]);
      else if (suffix === "_state") stById.set(id, m[0]);
      else varById.set(id, { xml: m[0], type: localName(m[1]) });
    }
  }
  const bundles: OvalTestBundle[] = [];
  const reTest = reLocalSuffix("_test", "g"); let tm: RegExpExecArray | null;
  while ((tm = reTest.exec(xml)) !== null) {
    const tag = tm[1], attrs = tm[2], body = tm[3] || "", full = tm[0];
    const id = attrOf(attrs, "id"); if (!id) continue;
    const objRef = /<(?:[\w.\-]+:)?object\b[^>]*?\bobject_ref="([^"]+)"/.exec(body)?.[1];
    const stRefs = [...body.matchAll(/<(?:[\w.\-]+:)?state\b[^>]*?\bstate_ref="([^"]+)"/g)].map((x) => x[1]);
    const objXml = objRef ? objById.get(objRef) : undefined;
    const stXmls = stRefs.map((r) => stById.get(r)).filter((x): x is string => !!x);
    const varRefs = new Set<string>();
    for (const x of [objXml, ...stXmls]) if (x) for (const vm of x.matchAll(/\bvar_ref="([^"]+)"/g)) varRefs.add(vm[1]);
    const variables = [...varRefs].map((v) => varById.get(v)).filter((x): x is { xml: string; type: string } => !!x)
      .map((v) => ({ id: attrOf(openAttrs(v.xml), "id") || "", type: v.type, xml: v.xml }));
    bundles.push({
      id, type: localName(tag), family: nsPrefix(tag), check: attrOf(attrs, "check"),
      checkExistence: attrOf(attrs, "check_existence"), comment: attrOf(attrs, "comment"),
      object: objXml ? { id: objRef!, comment: attrOf(openAttrs(objXml), "comment"), entities: entitiesOf(objXml), xml: objXml } : undefined,
      states: stXmls.map((x, i) => ({ id: stRefs[i], comment: attrOf(openAttrs(x), "comment"), entities: entitiesOf(x), xml: x })),
      variables, xml: full,
    });
    if (bundles.length > 200000) break;
  }
  return bundles;
}

const nsDeclsFrom = (xml: string, skipBase = true): string[] => {
  const decls = xml.match(/xmlns(?::[\w.\-]+)?="[^"]*"/g) || [];
  const base = new Set(["", "oval", "xsi"]);
  return [...new Set(decls)].filter((d) => {
    if (!skipBase) return true;
    const pm = /xmlns(?::([\w.\-]+))?=/.exec(d); return !base.has(pm?.[1] || "");
  });
};
function bundleXml(b: OvalTestBundle, nsdecls: string[], schemaVersion: string): string {
  return `<oval-test-bundle${nsdecls.length ? " " + nsdecls.join(" ") : ""} schema_version="${schemaVersion}">` +
    `<tests>${b.xml}</tests>` +
    `<objects>${b.object?.xml || ""}</objects>` +
    `<states>${b.states.map((s) => s.xml).join("")}</states>` +
    `<variables>${b.variables.map((v) => v.xml).join("")}</variables>` +
    `</oval-test-bundle>`;
}

export interface OvalTestImportResult { parsed: number; created: number; updated: number; skipped: number; }
/** Import OVAL test content from a full OVAL document into OVALTEST.BLOB (upsert by test id). */
export function importOvalTestContent(xml: string): OvalTestImportResult {
  const xv = getDb("XOVAL");
  const tc = cols("OVALTEST");
  if (!tc.size) throw new Error("OVALTEST not available");
  const nsdecls = nsDeclsFrom(xml);
  const sv = /schema_version\s*>\s*([\d.]+)/.exec(xml)?.[1] || OVAL_SCHEMA_VERSION;
  const bundles = parseOvalTests(xml);
  const out: OvalTestImportResult = { parsed: bundles.length, created: 0, updated: 0, skipped: 0 };
  const find = xv.prepare("SELECT OVALTestID id FROM OVALTEST WHERE OVALTestIDPattern = ? LIMIT 1");
  const hasComment = tc.has("comment");
  const tx = xv.transaction(() => {
    for (const b of bundles) {
      if (!b.id) { out.skipped++; continue; }
      const blob = bundleXml(b, nsdecls, sv);
      const ex = find.get(b.id) as { id: number } | undefined;
      if (ex) {
        if (b.comment && hasComment) xv.prepare("UPDATE OVALTEST SET BLOB=?, comment=COALESCE(NULLIF(comment,''),?) WHERE OVALTestID=?").run(blob, b.comment, ex.id);
        else xv.prepare("UPDATE OVALTEST SET BLOB=? WHERE OVALTestID=?").run(blob, ex.id);
        out.updated++;
      } else {
        // OVALTestVersion + comment are NOT NULL on the legacy table (no default).
        ins(xv, "OVALTEST", { OVALTestID: allocId(xv, "OVALTEST", "OVALTestID"), OVALTestIDPattern: b.id, OVALTestVersion: 1, comment: b.comment || "", BLOB: blob, CreatedDate: new Date().toISOString() }, tc);
        out.created++;
      }
    }
  });
  tx();
  return out;
}

export interface OvalTestView {
  id: number; idPattern: string; comment: string | null; hasContent: boolean;
  type?: string; family?: string; check?: string; checkExistence?: string;
  object?: { id: string; comment?: string; entities: OvalEntity[]; xml: string };
  states?: { id: string; comment?: string; entities: OvalEntity[]; xml: string }[];
  variables?: { id: string; type: string; xml: string }[];
  xml?: string;
}
/** Inspect a single OVAL test: relational id/comment + parsed content from OVALTEST.BLOB if imported. */
export function getOvalTest(idPattern: string): OvalTestView | null {
  const xv = getDb("XOVAL");
  const r = xv.prepare("SELECT OVALTestID id, OVALTestIDPattern idPattern, comment, BLOB FROM OVALTEST WHERE OVALTestIDPattern = ? LIMIT 1").get(idPattern) as
    { id: number; idPattern: string; comment: string | null; BLOB: string | null } | undefined;
  if (!r) return null;
  const blob = r.BLOB ? String(r.BLOB) : "";
  if (!blob) return { id: r.id, idPattern: r.idPattern, comment: r.comment, hasContent: false };
  const b = parseOvalTests(blob)[0];
  return {
    id: r.id, idPattern: r.idPattern, comment: r.comment || b?.comment || null, hasContent: true,
    type: b?.type, family: b?.family, check: b?.check, checkExistence: b?.checkExistence,
    object: b?.object, states: b?.states || [], variables: b?.variables || [], xml: blob,
  };
}

// ── self-contained generation: inline referenced tests' objects/states from stored bundles ─────
function collectTestPatterns(n: OvalNode, out: Set<string>): void {
  if (n.kind === "criterion") { if (n.testIdPattern) out.add(n.testIdPattern); }
  else if (n.kind === "criteria") for (const c of n.children || []) collectTestPatterns(c, out);
}
function buildSelfContained(tree: OvalNode): { tests: string; objects: string; states: string; variables: string; nsdecls: string; resolved: number; missing: number } {
  const xv = getDb("XOVAL");
  const pats = new Set<string>(); collectTestPatterns(tree, pats);
  const tests: string[] = []; const objs = new Map<string, string>(); const sts = new Map<string, string>(); const vars = new Map<string, string>();
  const nsset = new Set<string>();
  let resolved = 0, missing = 0;
  const get = xv.prepare("SELECT BLOB FROM OVALTEST WHERE OVALTestIDPattern = ? AND BLOB IS NOT NULL LIMIT 1");
  for (const p of pats) {
    const row = get.get(p) as { BLOB: string } | undefined;
    if (!row?.BLOB) { missing++; continue; }
    const blob = String(row.BLOB);
    for (const d of nsDeclsFrom(blob)) nsset.add(d);
    const b = parseOvalTests(blob)[0]; if (!b) { missing++; continue; }
    resolved++;
    tests.push("    " + b.xml);
    if (b.object) objs.set(b.object.id, "    " + b.object.xml);
    for (const s of b.states) sts.set(s.id, "    " + s.xml);
    for (const v of b.variables) vars.set(v.id || v.xml.slice(0, 40), "    " + v.xml);
  }
  return {
    tests: tests.join("\n"), objects: [...objs.values()].join("\n"), states: [...sts.values()].join("\n"),
    variables: [...vars.values()].join("\n"), nsdecls: [...nsset].join(" "), resolved, missing,
  };
}

// ── tree types (client ↔ server) ───────────────────────────────────────────────
export type OvalNode =
  | { kind: "criteria"; operator: string; negate?: boolean; applicabilityCheck?: boolean; comment?: string; children: OvalNode[] }
  | { kind: "criterion"; testId: number; testIdPattern?: string; testComment?: string; negate?: boolean; comment?: string }
  | { kind: "extend"; defId: number; defIdPattern?: string; defTitle?: string; negate?: boolean; comment?: string };

export interface OvalDefMeta {
  id?: number; idPattern?: string; version: number; classId: number | null; className: string;
  title: string; description: string; deprecated: boolean; family: string; platform: string;
  references: { source: string; refId: string; refUrl: string }[]; authored?: boolean;
  schemaVersion?: string; selfContained?: boolean;
}

// ── load an existing definition (metadata + criteria tree) for editing/cloning ──
const opNameById = (): Map<number, string> => {
  const m = new Map<number, string>();
  for (const r of getDb("XOVAL").prepare(`SELECT OperatorEnumerationID id, OperatorValue v FROM OPERATORENUMERATION`).all() as { id: number; v: string }[]) m.set(Number(r.id), String(r.v).toUpperCase());
  return m;
};

export function loadOvalDefinition(idPattern: string): { meta: OvalDefMeta; tree: OvalNode } | null {
  const xv = getDb("XOVAL");
  const d = xv.prepare(
    `SELECT OVALDefinitionID, OVALDefinitionIDPattern, OVALDefinitionVersion, OVALClassEnumerationID,
            OVALDefinitionTitle, OVALDefinitionDescription, deprecated, OVALCriteriaID, RepositoryID
     FROM OVALDEFINITION WHERE OVALDefinitionIDPattern = ? LIMIT 1`
  ).get(idPattern) as Record<string, unknown> | undefined;
  if (!d) return null;
  const classValue = d.OVALClassEnumerationID != null
    ? (xv.prepare(`SELECT ClassValue v FROM OVALCLASSENUMERATION WHERE OVALClassEnumerationID=?`).get(d.OVALClassEnumerationID) as { v: string } | undefined)?.v || ""
    : "";
  const ops = opNameById();
  let nodeCount = 0;
  const visited = new Set<number>();
  const build = (criteriaId: number): OvalNode => {
    if (nodeCount++ > 4000 || visited.has(criteriaId)) return { kind: "criteria", operator: "AND", children: [] };
    visited.add(criteriaId);
    const c = xv.prepare(`SELECT OperatorEnumerationID, negate, comment, applicabilitycheck FROM OVALCRITERIA WHERE OVALCriteriaID=?`).get(criteriaId) as Record<string, unknown> | undefined;
    const node: OvalNode = {
      kind: "criteria", operator: c ? (ops.get(Number(c.OperatorEnumerationID)) || "AND") : "AND",
      negate: !!(c && c.negate), applicabilityCheck: !!(c && c.applicabilitycheck), comment: (c?.comment as string) || "", children: [],
    };
    for (const cr of xv.prepare(`SELECT OVALTestID, negate, comment FROM OVALCRITERIACRITERION WHERE OVALCriteriaID=?`).all(criteriaId) as Record<string, unknown>[]) {
      const t = xv.prepare(`SELECT OVALTestIDPattern p, comment c FROM OVALTEST WHERE OVALTestID=?`).get(cr.OVALTestID) as { p: string; c: string } | undefined;
      node.children.push({ kind: "criterion", testId: Number(cr.OVALTestID), testIdPattern: t?.p, testComment: t?.c, negate: !!cr.negate, comment: (cr.comment as string) || "" });
    }
    for (const ex of xv.prepare(`SELECT OVALDefinitionID, negate, comment FROM OVALCRITERIAEXTENDDEFINITION WHERE OVALCriteriaID=?`).all(criteriaId) as Record<string, unknown>[]) {
      const ed = xv.prepare(`SELECT OVALDefinitionIDPattern p, OVALDefinitionTitle t FROM OVALDEFINITION WHERE OVALDefinitionID=?`).get(ex.OVALDefinitionID) as { p: string; t: string } | undefined;
      node.children.push({ kind: "extend", defId: Number(ex.OVALDefinitionID), defIdPattern: ed?.p, defTitle: ed?.t, negate: !!ex.negate, comment: (ex.comment as string) || "" });
    }
    for (const sub of xv.prepare(`SELECT OVALCriteriaSubjectID FROM OVALCRITERIAFOROVALCRITERIA WHERE OVALCriteriaRefID=? ORDER BY CriteriaRank`).all(criteriaId) as { OVALCriteriaSubjectID: number }[]) {
      node.children.push(build(Number(sub.OVALCriteriaSubjectID)));
    }
    return node;
  };
  const tree = d.OVALCriteriaID != null ? build(Number(d.OVALCriteriaID)) : { kind: "criteria" as const, operator: "AND", children: [] };
  const meta: OvalDefMeta = {
    id: Number(d.OVALDefinitionID), idPattern: String(d.OVALDefinitionIDPattern), version: Number(d.OVALDefinitionVersion) || 1,
    classId: d.OVALClassEnumerationID != null ? Number(d.OVALClassEnumerationID) : null, className: classValue,
    title: String(d.OVALDefinitionTitle || ""), description: String(d.OVALDefinitionDescription || ""),
    deprecated: !!d.deprecated, family: "", platform: "", references: [],
    authored: Number(d.RepositoryID) === AUTHORED_REPO || String(d.OVALDefinitionIDPattern).includes(`:${OVAL_NS}:`),
  };
  return { meta, tree };
}

// ── OVAL XML generation (schema version selectable; optional self-contained tests) ──────────────
export function generateOvalXml(meta: OvalDefMeta, tree: OvalNode, idPattern: string): string {
  const sv = meta.schemaVersion && OVAL_SCHEMA_VERSIONS.includes(meta.schemaVersion) ? meta.schemaVersion : OVAL_SCHEMA_VERSION;
  const cls = (meta.className || "compliance").toLowerCase();
  const refs = (meta.references || []).filter((r) => r.refId || r.source)
    .map((r) => `        <reference source="${xe(r.source || "")}" ref_id="${xe(r.refId || "")}"${r.refUrl ? ` ref_url="${xe(r.refUrl)}"` : ""}/>`).join("\n");
  const affected = meta.family
    ? `        <affected family="${xe(meta.family)}">${meta.platform ? `\n          <platform>${xe(meta.platform)}</platform>\n        ` : ""}</affected>\n`
    : "";
  const crit = (n: OvalNode, ind: string): string => {
    if (n.kind === "criterion")
      return `${ind}<criterion test_ref="${xe(n.testIdPattern || "")}"${n.negate ? ` negate="true"` : ""}${n.comment ? ` comment="${xe(n.comment)}"` : ""}/>`;
    if (n.kind === "extend")
      return `${ind}<extend_definition definition_ref="${xe(n.defIdPattern || "")}"${n.negate ? ` negate="true"` : ""}${n.comment ? ` comment="${xe(n.comment)}"` : ""}/>`;
    const inner = (n.children || []).map((c) => crit(c, ind + "  ")).join("\n");
    return `${ind}<criteria operator="${xe((n.operator || "AND").toUpperCase())}"${n.negate ? ` negate="true"` : ""}${n.applicabilityCheck ? ` applicability_check="true"` : ""}${n.comment ? ` comment="${xe(n.comment)}"` : ""}>\n${inner}\n${ind}</criteria>`;
  };
  // Optional self-contained sections: inline the referenced tests' objects/states from OVALTEST.BLOB.
  let extraNs = ""; let sections = "";
  if (meta.selfContained) {
    const sc = buildSelfContained(tree);
    extraNs = sc.nsdecls ? `\n  ${sc.nsdecls}` : "";
    sections =
      (sc.tests ? `  <tests>\n${sc.tests}\n  </tests>\n` : "  <tests/>\n") +
      (sc.objects ? `  <objects>\n${sc.objects}\n  </objects>\n` : "") +
      (sc.states ? `  <states>\n${sc.states}\n  </states>\n` : "") +
      (sc.variables ? `  <variables>\n${sc.variables}\n  </variables>\n` : "");
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"${extraNs}
  xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd">
  <generator>
    <oval:product_name>XORCISM OVAL Editor</oval:product_name>
    <oval:schema_version>${sv}</oval:schema_version>
    <oval:timestamp>${new Date().toISOString().replace(/\.\d+Z$/, "")}</oval:timestamp>
  </generator>
  <definitions>
    <definition id="${xe(idPattern)}" version="${Number(meta.version) || 1}" class="${xe(cls)}"${meta.deprecated ? ` deprecated="true"` : ""}>
      <metadata>
        <title>${xe(meta.title)}</title>
${affected}        <reference source="XORCISM" ref_id="${xe(idPattern)}"/>
${refs ? refs + "\n" : ""}        <description>${xe(meta.description)}</description>
      </metadata>
${crit(tree, "      ")}
    </definition>
  </definitions>
${sections}</oval_definitions>
`;
}

// ── persistence ────────────────────────────────────────────────────────────────
/** Collect all criteria ids reachable from a root (for clean subtree deletion on edit). */
function collectCriteria(rootId: number): number[] {
  const xv = getDb("XOVAL");
  const out: number[] = []; const seen = new Set<number>(); const stack = [rootId];
  while (stack.length && out.length < 5000) {
    const id = stack.pop()!;
    if (seen.has(id)) continue; seen.add(id); out.push(id);
    for (const s of xv.prepare(`SELECT OVALCriteriaSubjectID s FROM OVALCRITERIAFOROVALCRITERIA WHERE OVALCriteriaRefID=?`).all(id) as { s: number }[]) stack.push(Number(s.s));
  }
  return out;
}

export interface SaveResult { id: number; idPattern: string; xml: string; nodes: number; created: boolean; }

export function saveOvalDefinition(meta: OvalDefMeta, tree: OvalNode, tenant: number | null): SaveResult {
  const xv = getDb("XOVAL");
  const now = new Date().toISOString();
  const opIds = ensureOperators();
  const dc = cols("OVALDEFINITION"), cc = cols("OVALCRITERIA"), crc = cols("OVALCRITERIACRITERION"),
    exc = cols("OVALCRITERIAEXTENDDEFINITION"), fc = cols("OVALCRITERIAFOROVALCRITERIA");
  if (!dc.size || !cc.size) throw new Error("XOVAL OVAL tables not available");
  const hasTenant = dc.has("TenantID");

  let nodes = 0;
  // Recursively write a criteria node + its children; returns the new OVALCriteriaID.
  const writeNode = (n: OvalNode): number => {
    nodes++;
    const cid = allocId(xv, "OVALCRITERIA", "OVALCriteriaID");
    const criteriaNode = n.kind === "criteria" ? n : { operator: "AND", children: [] as OvalNode[] } as Extract<OvalNode, { kind: "criteria" }>;
    ins(xv, "OVALCRITERIA", {
      OVALCriteriaID: cid, OperatorEnumerationID: opIds.get((criteriaNode.operator || "AND").toUpperCase()) ?? opIds.get("AND"),
      negate: criteriaNode.negate ? 1 : 0, comment: criteriaNode.comment || null,
      applicabilitycheck: criteriaNode.applicabilityCheck ? 1 : 0, CreatedDate: now, RepositoryID: AUTHORED_REPO,
    }, cc);
    let rank = 0;
    for (const ch of criteriaNode.children || []) {
      if (ch.kind === "criterion") {
        if (!ch.testId) continue;
        ins(xv, "OVALCRITERIACRITERION", {
          OVALCriteriaCriterionID: allocId(xv, "OVALCRITERIACRITERION", "OVALCriteriaCriterionID"),
          OVALCriteriaID: cid, OVALTestID: ch.testId, negate: ch.negate ? 1 : 0, comment: ch.comment || null,
          CreatedDate: now, RepositoryID: AUTHORED_REPO,
        }, crc);
        nodes++;
      } else if (ch.kind === "extend") {
        if (!ch.defId) continue;
        ins(xv, "OVALCRITERIAEXTENDDEFINITION", {
          OVALCriteriaExtendDefinitionID: allocId(xv, "OVALCRITERIAEXTENDDEFINITION", "OVALCriteriaExtendDefinitionID"),
          OVALCriteriaID: cid, OVALDefinitionID: ch.defId, negate: ch.negate ? 1 : 0, comment: ch.comment || null, CreatedDate: now,
        }, exc);
        nodes++;
      } else if (ch.kind === "criteria") {
        const childId = writeNode(ch);
        ins(xv, "OVALCRITERIAFOROVALCRITERIA", {
          OVALCriteriaRelationshipID: allocId(xv, "OVALCRITERIAFOROVALCRITERIA", "OVALCriteriaRelationshipID"),
          OVALCriteriaRefID: cid, OVALCriteriaSubjectID: childId, RelationshipName: "HasMember",
          CriteriaRank: ++rank, CreatedDate: now,
        }, fc);
      }
    }
    return cid;
  };

  const tx = xv.transaction((): SaveResult => {
    // editing an existing authored def?
    let defId: number | null = null; let idPattern = ""; let created = true;
    const existing = meta.idPattern
      ? xv.prepare(`SELECT OVALDefinitionID, RepositoryID, OVALCriteriaID FROM OVALDEFINITION WHERE OVALDefinitionIDPattern=? LIMIT 1`).get(meta.idPattern) as { OVALDefinitionID: number; RepositoryID: number; OVALCriteriaID: number } | undefined
      : undefined;
    if (existing && (Number(existing.RepositoryID) === AUTHORED_REPO || String(meta.idPattern).includes(`:${OVAL_NS}:`))) {
      defId = Number(existing.OVALDefinitionID); idPattern = meta.idPattern!; created = false;
      // delete the old criteria subtree (clean rebuild)
      if (existing.OVALCriteriaID != null) {
        const ids = collectCriteria(Number(existing.OVALCriteriaID));
        const ph = ids.map(() => "?").join(",");
        if (ids.length) {
          xv.prepare(`DELETE FROM OVALCRITERIACRITERION WHERE OVALCriteriaID IN (${ph})`).run(...ids);
          xv.prepare(`DELETE FROM OVALCRITERIAEXTENDDEFINITION WHERE OVALCriteriaID IN (${ph})`).run(...ids);
          xv.prepare(`DELETE FROM OVALCRITERIAFOROVALCRITERIA WHERE OVALCriteriaRefID IN (${ph}) OR OVALCriteriaSubjectID IN (${ph})`).run(...ids, ...ids);
          xv.prepare(`DELETE FROM OVALCRITERIA WHERE OVALCriteriaID IN (${ph})`).run(...ids);
        }
      }
    } else {
      defId = allocId(xv, "OVALDEFINITION", "OVALDefinitionID");
      // mint the next id in the authored namespace
      const maxSuf = (xv.prepare(
        `SELECT COALESCE(MAX(CAST(REPLACE(OVALDefinitionIDPattern,'oval:${OVAL_NS}:def:','') AS INTEGER)),0) m
         FROM OVALDEFINITION WHERE OVALDefinitionIDPattern LIKE 'oval:${OVAL_NS}:def:%'`).get() as { m: number }).m;
      idPattern = `oval:${OVAL_NS}:def:${maxSuf + 1}`;
    }

    const rootId = writeNode(tree.kind === "criteria" ? tree : { kind: "criteria", operator: "AND", children: [tree] });
    const xml = generateOvalXml({ ...meta, idPattern }, tree, idPattern);
    const rec: Record<string, unknown> = {
      OVALDefinitionID: defId, OVALDefinitionIDPattern: idPattern, OVALDefinitionVersion: Number(meta.version) || 1,
      OVALClassEnumerationID: meta.classId ?? null, deprecated: meta.deprecated ? 1 : 0,
      OVALDefinitionTitle: (meta.title || "").slice(0, 1000), OVALDefinitionDescription: (meta.description || "").slice(0, 8000),
      OVALCriteriaID: rootId, StatusName: "DRAFT", CreatedDate: now, RepositoryID: AUTHORED_REPO, BLOB: xml,
    };
    if (hasTenant) rec.TenantID = tenant;
    if (dc.has("OVALDefinitionGUID")) rec.OVALDefinitionGUID = randomUUID();
    if (created) ins(xv, "OVALDEFINITION", rec, dc);
    else {
      const setKeys = Object.keys(rec).filter((k) => dc.has(k) && k !== "OVALDefinitionID" && k !== "CreatedDate");
      xv.prepare(`UPDATE OVALDEFINITION SET ${setKeys.map((k) => `"${k}"=?`).join(",")} WHERE OVALDefinitionID=?`).run(...setKeys.map((k) => rec[k]), defId);
    }
    return { id: defId!, idPattern, xml, nodes, created };
  });
  return tx();
}
