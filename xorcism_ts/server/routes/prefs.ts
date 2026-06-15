/**
 * prefs.ts (routes) — user preferences (key → JSON), e.g. CTI feeds and
 * display options of the Threat Feeds page. Mounted AFTER the auth gate.
 */
import { Router, Request, Response } from "express";
import * as xid from "../xid";

const router = Router();

const KEY_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const MAX_VALUE_BYTES = 64 * 1024; // guard: a preferences JSON stays small

// GET /api/prefs/:key → { value: <JSON|null> }
router.get("/prefs/:key", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const key = String(req.params.key);
  if (!KEY_RE.test(key)) return void res.status(400).json({ error: "bad key" });
  const raw = xid.getUserPref(req.user.UserID, key);
  if (raw == null) return void res.json({ value: null });
  try { res.json({ value: JSON.parse(raw) }); }
  catch { res.json({ value: null }); }
});

// PUT /api/prefs/:key  { value: <JSON> } → { ok: true }
router.put("/prefs/:key", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const key = String(req.params.key);
  if (!KEY_RE.test(key)) return void res.status(400).json({ error: "bad key" });
  const value = (req.body as { value?: unknown })?.value;
  if (value === undefined) return void res.status(400).json({ error: "value required" });
  const raw = JSON.stringify(value);
  if (Buffer.byteLength(raw, "utf8") > MAX_VALUE_BYTES)
    return void res.status(413).json({ error: "value too large" });
  xid.setUserPref(req.user.UserID, key, raw);
  res.json({ ok: true });
});

export default router;
