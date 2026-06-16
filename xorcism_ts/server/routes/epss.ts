/**
 * epss.ts (routes) — FIRST.org EPSS lookup proxy for the VULNERABILITY form.
 *   GET /api/epss?cve=CVE-…  → { cve, epss, percentile, date }
 * Proxies https://api.first.org/data/v1/epss?cve=… (avoids browser CORS / leaking
 * the client). Mounted AFTER the auth gate; guarded by read rights on
 * XVULNERABILITY.VULNERABILITY.
 */
import { Router, Request, Response } from "express";
import { userCan } from "../auth";

const router = Router();
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

router.get("/epss", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  if (!userCan(req.user, "read", "XVULNERABILITY", "VULNERABILITY"))
    return void res.status(403).json({ error: "forbidden" });
  const cve = String(req.query.cve || "").trim().toUpperCase();
  if (!CVE_RE.test(cve)) return void res.status(400).json({ error: "Invalid CVE id" });

  try {
    const r = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`, {
      headers: { Accept: "application/json", "User-Agent": "XORCISM" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return void res.status(502).json({ error: `FIRST.org EPSS HTTP ${r.status}` });
    const j = (await r.json()) as { data?: { cve: string; epss?: string; percentile?: string; date?: string }[] };
    const row = j.data && j.data[0];
    if (!row) return void res.json({ cve, epss: null });
    res.json({
      cve,
      epss: row.epss != null ? Number(row.epss) : null,
      percentile: row.percentile != null ? Number(row.percentile) : null,
      date: row.date ?? null,
    });
  } catch (e) {
    res.status(502).json({ error: e instanceof Error ? e.message : String(e) });
  }
});

export default router;
