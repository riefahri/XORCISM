/**
 * ovaleditor.ts (routes) — author/edit OVAL Definitions (/oval-editor page).
 * Read endpoints guarded by read on XOVAL.OVALDEFINITION; save by create/update.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import {
  ovalEditorMeta, searchOvalTests, searchOvalDefsForExtend, loadOvalDefinition,
  generateOvalXml, saveOvalDefinition, getOvalTest, importOvalTestContent, OvalDefMeta, OvalNode,
} from "../ovaleditor";
import * as xid from "../xid";

const router = Router();
const ID_RX = /^oval:[A-Za-z0-9_.\-]+:def:[0-9]+$/i;

// GET /api/oval/meta — enums (classes/operators/families) for the editor comboboxes
router.get("/oval/meta", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(ovalEditorMeta()); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/oval/test-search?q= — imported OVAL tests for the criterion combobox
router.get("/oval/test-search", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const q = String(req.query.q || "").trim();
  if (q.length < 2) return void res.json([]);
  try { res.json(searchOvalTests(q, Number(req.query.limit) || 40)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/oval/def-search?q= — imported OVAL definitions for the extend_definition combobox
router.get("/oval/def-search", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const q = String(req.query.q || "").trim();
  if (q.length < 2) return void res.json([]);
  try { res.json(searchOvalDefsForExtend(q, Number(req.query.limit) || 40)); } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/oval/definition?id=oval:...:def:N — load a definition's metadata + criteria tree
router.get("/oval/definition", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const id = String(req.query.id || "").trim();
  if (!ID_RX.test(id)) return void res.status(400).json({ error: "invalid OVAL definition id" });
  try {
    const out = loadOvalDefinition(id);
    if (!out) return void res.status(404).json({ error: "definition not found" });
    res.json(out);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// GET /api/oval/test?id=oval:...:tst:N — inspect a test's content (id/comment + object/states from BLOB)
const TST_RX = /^oval:[A-Za-z0-9_.\-]+:tst:[0-9]+$/i;
router.get("/oval/test", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const id = String(req.query.id || "").trim();
  if (!TST_RX.test(id)) return void res.status(400).json({ error: "invalid OVAL test id" });
  try {
    const out = getOvalTest(id);
    if (!out) return void res.status(404).json({ error: "test not found" });
    res.json(out);
  } catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/oval/import-tests { xml } — import OVAL test content (objects/states/variables) from a full
// OVAL document into OVALTEST.BLOB so the editor can show what each criterion's test checks.
router.post("/oval/import-tests", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { xml?: unknown };
  const xml = typeof b.xml === "string" ? b.xml : "";
  if (!xml.trim()) return void res.status(400).json({ error: "xml required" });
  if (xml.length > 24 * 1024 * 1024) return void res.status(400).json({ error: "OVAL document too large (max 24 MB)" });
  if (!/<(?:[\w.\-]+:)?oval_definitions\b|<(?:[\w.\-]+:)?[\w.\-]*_test\b/i.test(xml)) {
    return void res.status(400).json({ error: "not a recognisable OVAL document (no <oval_definitions> / *_test elements)" });
  }
  try {
    const out = importOvalTestContent(xml);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "oval_test_import", resourceType: "XOVAL.OVALTEST",
      detail: `parsed=${out.parsed} created=${out.created} updated=${out.updated} skipped=${out.skipped}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/oval/preview { meta, tree } — generate OVAL XML without persisting
router.post("/oval/preview", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { meta?: OvalDefMeta; tree?: OvalNode };
  if (!b.meta || !b.tree) return void res.status(400).json({ error: "meta and tree required" });
  try {
    const idp = b.meta.idPattern && ID_RX.test(b.meta.idPattern) ? b.meta.idPattern : "oval:ai.xorcism:def:NEW";
    res.json({ xml: generateOvalXml(b.meta, b.tree, idp) });
  } catch (e) { res.status(400).json({ error: (e as Error).message }); }
});

// POST /api/oval/definition { meta, tree } — create/update an authored OVAL definition
router.post("/oval/definition", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XOVAL", "OVALDEFINITION")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as { meta?: OvalDefMeta; tree?: OvalNode };
  if (!b.meta || !b.tree) return void res.status(400).json({ error: "meta and tree required" });
  if (!String(b.meta.title || "").trim()) return void res.status(400).json({ error: "title required" });
  if (b.tree.kind !== "criteria") return void res.status(400).json({ error: "root must be a criteria node" });
  const tenant = req.user.isSuperAdmin ? null : (req.user.tenantId ?? null);
  try {
    const out = saveOvalDefinition(b.meta, b.tree, tenant);
    xid.addAudit({ userId: req.user.UserID ?? null, action: out.created ? "oval_def_create" : "oval_def_update",
      resourceType: "XOVAL.OVALDEFINITION", resourceKey: out.idPattern,
      detail: `title="${String(b.meta.title).slice(0, 80)}" nodes=${out.nodes}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
