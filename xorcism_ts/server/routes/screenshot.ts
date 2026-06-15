/**
 * screenshot.ts (routes) — Screenshot of a URL → image file served by /uploads.
 * Used by the ASSET form (websiteurl → AssetImage) in creation mode.
 * Runs tools/screenshot.py (Playwright/Chromium). Basic SSRF guard.
 */
import { Router, Request, Response } from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { execFile } from "child_process";
import { UPLOAD_DIR } from "./upload";
import * as xid from "../xid";
import { clientIp } from "../auth";

const router = Router();
const SCRIPT = path.resolve(__dirname, "../../../../tools/screenshot.py");

/** Rejects non-http(s) schemes and internal/private hosts (basic anti-SSRF). */
function isSafeUrl(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (!/^https?:$/.test(u.protocol)) return false;
  const h = u.hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h === "::1") return false;
  if (/^(127\.|10\.|169\.254\.|0\.)/.test(h)) return false;
  if (/^192\.168\./.test(h)) return false;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
  if (/^(fc|fd|fe80)/.test(h)) return false; // IPv6 ULA / link-local
  return true;
}

// POST /api/asset/screenshot { url } → { url: "/uploads/screenshots/<file>.png" }
router.post("/asset/screenshot", (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const url = String((req.body as { url?: string })?.url || "").trim();
  if (!isSafeUrl(url)) return void res.status(400).json({ error: "URL invalide ou hôte non autorisé" });

  const dir = path.join(UPLOAD_DIR, "screenshots");
  fs.mkdirSync(dir, { recursive: true });
  const file = crypto.randomUUID() + ".png";
  const out = path.join(dir, file);

  execFile("python", [SCRIPT, url, out], { timeout: 40000 }, (err) => {
    if (err || !fs.existsSync(out)) {
      return void res.status(502).json({ error: "Capture impossible : " + (err?.message || "échec") });
    }
    xid.addAudit({
      userId: req.user!.UserID, action: "asset_screenshot", resourceType: "asset",
      detail: url, ip: clientIp(req),
    });
    res.json({ url: `/uploads/screenshots/${file}` });
  });
});

export default router;
