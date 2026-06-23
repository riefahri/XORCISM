/**
 * frameworks.ts (routes) — Frameworks management (Compliance).
 * Global FRAMEWORK catalogue + framework→VOCABULARY mapping. Read guarded by read on
 * XORCISM.FRAMEWORK; create/map guarded by create/update on FRAMEWORK.
 */
import { Router, Request, Response } from "express";
import { userCan, clientIp } from "../auth";
import { frameworksInventory, createFramework, setFrameworkVocabulary } from "../frameworks";
import * as xid from "../xid";

const router = Router();

// GET /api/frameworks — framework catalogue + vocabulary mapping + control counts
router.get("/frameworks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XORCISM", "FRAMEWORK")) return void res.status(403).json({ error: "forbidden" });
  try { res.json(frameworksInventory()); }
  catch (e) { res.status(500).json({ error: (e as Error).message }); }
});

// POST /api/frameworks — create a framework (optionally pre-mapped to a vocabulary)
router.post("/frameworks", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "create", "XORCISM", "FRAMEWORK")) return void res.status(403).json({ error: "forbidden" });
  const b = (req.body || {}) as Record<string, unknown>;
  const name = String(b.name ?? "").trim();
  if (!name) return void res.status(400).json({ error: "name required" });
  try {
    const out = createFramework({
      name,
      version: b.version ? String(b.version) : undefined,
      description: b.description ? String(b.description) : undefined,
      vocabularyId: b.vocabularyId != null && String(b.vocabularyId) !== "" ? Number(b.vocabularyId) : null,
    });
    xid.addAudit({ userId: req.user.UserID ?? null, action: "framework_create", resourceType: "FRAMEWORK",
      resourceKey: String(out.id), detail: `name="${name}" vocab=${b.vocabularyId ?? ""}`, ip: clientIp(req) });
    res.json({ ok: true, ...out });
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

// POST /api/frameworks/:id/map { vocabularyId|null } — map (or unmap) to a VOCABULARY
router.post("/frameworks/:id/map", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "update", "XORCISM", "FRAMEWORK")) return void res.status(403).json({ error: "forbidden" });
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return void res.status(400).json({ error: "bad framework id" });
  const raw = (req.body as { vocabularyId?: unknown })?.vocabularyId;
  const vocabularyId = raw != null && String(raw) !== "" ? Number(raw) : null;
  try {
    const out = setFrameworkVocabulary(id, vocabularyId);
    xid.addAudit({ userId: req.user.UserID ?? null, action: "framework_map", resourceType: "FRAMEWORK",
      resourceKey: String(id), detail: `vocab=${vocabularyId ?? "none"}`, ip: clientIp(req) });
    res.json(out);
  } catch (e) { res.status(400).json({ error: String((e as Error).message || e) }); }
});

export default router;
