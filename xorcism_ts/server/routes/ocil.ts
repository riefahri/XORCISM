/**
 * ocil.ts (routes) — OCIL 2.0 import/export of XCOMPLIANCE questionnaires.
 * Mounted AFTER the auth gate. RBAC: read for export, create for
 * import (on XCOMPLIANCE.QUESTIONNAIRE).
 *
 *   GET  /api/ocil/export?ids=1,2   → OCIL 2.0 XML (download)
 *   POST /api/ocil/import { xml }   → creates/updates questionnaires/questions/answers
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import * as xid from "../xid";
import { getDb } from "../db";
import { exportOcil, importOcil, validateOcil } from "../ocil";

const router = Router();
const DB = "XCOMPLIANCE", TBL = "QUESTIONNAIRE";

// GET /api/ocil/questionnaires — list for the export selector
router.get("/ocil/questionnaires", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  try {
    const rows = getDb(DB).prepare(
      "SELECT QuestionnaireID, QuestionnaireName, OcilId FROM QUESTIONNAIRE ORDER BY QuestionnaireID"
    ).all();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

// POST /api/ocil/validate { xml } — OCIL 2.0 validation (without writing)
router.post("/ocil/validate", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const xml = String((req.body as { xml?: string })?.xml || "");
  if (!xml.trim()) return void res.status(400).json({ error: "XML OCIL requis" });
  res.json(validateOcil(xml));
});

router.get("/ocil/export", (req: Request, res: Response) => {
  if (!userCan(req.user, "read", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const ids = String(req.query.ids || "")
    .split(",").map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0);
  try {
    const xml = exportOcil(ids.length ? ids : undefined);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "ocil_export", resourceType: "table",
      resourceKey: `${DB}.${TBL}`, detail: ids.length ? `ids=${ids.join(",")}` : "all", ip: clientIp(req) });
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="ocil-export.xml"');
    res.send(xml);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

router.post("/ocil/import", (req: Request, res: Response) => {
  if (!userCan(req.user, "create", DB, TBL)) return void res.status(403).json({ error: "Accès refusé" });
  const xml = String((req.body as { xml?: string })?.xml || "");
  if (!xml.trim()) return void res.status(400).json({ error: "XML OCIL requis" });
  try {
    const r = importOcil(xml);
    xid.addAudit({ userId: req.user?.UserID ?? null, action: "ocil_import", resourceType: "table",
      resourceKey: `${DB}.${TBL}`, detail: JSON.stringify(r), ip: clientIp(req) });
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

export default router;
