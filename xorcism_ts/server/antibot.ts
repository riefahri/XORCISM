/**
 * antibot.ts — Anti-bot / anti-scraping protection (Express).
 *
 *  1) Per-IP rate limiting (sliding window) — two levels:
 *       - global (all API routes),
 *       - reinforced "scraping" level on the DATA endpoints (bulk read/export).
 *  2) Blocking of known scraping/harvesting tool User-Agents (and empty UA).
 *  3) Detection of extraction bursts → 429 + temporary IP block.
 *  4) Honeypot for public forms (filled hidden field = bot).
 *
 *  Everything is in memory (no dependency) and tunable via environment variables.
 *  Thresholds are deliberately generous so as not to hinder the UI or agents/workers.
 */
import { Request, Response, NextFunction } from "express";

const num = (v: string | undefined, d: number) => (v && Number.isFinite(+v) ? +v : d);

// Thresholds (per IP, per minute) — overridable via env.
const WINDOW_MS = 60_000;
const GLOBAL_MAX = num(process.env.XORCISM_RL_GLOBAL, 600); // all /api routes
const SCRAPE_MAX = num(process.env.XORCISM_RL_SCRAPE, 90); // data endpoints
const BLOCK_MS = num(process.env.XORCISM_RL_BLOCK_MS, 5 * 60_000); // temporary block after abuse

// Common harvesting tools / scrapers / automated clients (UA).
const BAD_UA = /(?:scrapy|httrack|wget|libwww|python-requests|python-urllib|go-http-client|node-fetch|axios\/|java\/|okhttp|curl\/|httpie|harvest|crawler|spider|masscan|nikto|sqlmap|nmap|zgrab|semrush|ahrefsbot|mj12bot|dotbot|petalbot|bytespider|gptbot|ccbot)/i;

// Bulk DATA endpoints (scraping target) — reinforced limit.
// (UI POLLING endpoints — jobs, agents, events — stay under the
//  global limit only, so as not to hinder the interface.)
const DATA_RE = /^\/api\/(rows|export|schema|lookup|tables|databases|vuln-search|asset-(cpes|vulnerabilities)|threatmodel-|threat-controls|feedback\/all)/;

interface Bucket { hits: number[]; blockedUntil: number }
const buckets = new Map<string, Bucket>();

function ipOf(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress ?? "?";
}

// blockOnExceed=true → temporary block after gross abuse (global limit).
// blockOnExceed=false → plain windowed throttle (429 until the window slides).
function take(key: string, max: number, blockOnExceed: boolean): { ok: boolean; retryAfter: number } {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b) { b = { hits: [], blockedUntil: 0 }; buckets.set(key, b); }
  if (b.blockedUntil > now) return { ok: false, retryAfter: Math.ceil((b.blockedUntil - now) / 1000) };
  b.hits = b.hits.filter((t) => now - t < WINDOW_MS);
  if (b.hits.length >= max) {
    if (blockOnExceed) b.blockedUntil = now + BLOCK_MS;
    return { ok: false, retryAfter: blockOnExceed ? Math.ceil(BLOCK_MS / 1000) : Math.ceil(WINDOW_MS / 1000) };
  }
  b.hits.push(now);
  return { ok: true, retryAfter: 0 };
}

// Periodic purge (avoids memory growth).
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) {
    if (b.blockedUntil < now && (b.hits.length === 0 || now - b.hits[b.hits.length - 1] > WINDOW_MS)) {
      buckets.delete(k);
    }
  }
}, WINDOW_MS).unref?.();

let blockedUaCount = 0;
let rateLimited = 0;
export function antibotStats() { return { trackedIps: buckets.size, blockedUaCount, rateLimited }; }

export function antibot(req: Request, res: Response, next: NextFunction): void {
  // Static resources: not concerned.
  const p = req.path;
  if (p.startsWith("/css/") || p.startsWith("/js/") || p.startsWith("/vendor/") || p === "/favicon.ico") {
    return next();
  }
  const ip = ipOf(req);
  const ua = String(req.headers["user-agent"] ?? "");

  // 1) Block harvesting UAs on HTML PAGES (where content scraping happens).
  //    The API is protected by authentication + rate limiting; we don't block
  //    by UA there, so as not to hinder legitimate API/agent clients.
  if (!p.startsWith("/api/") && (ua === "" || BAD_UA.test(ua))) {
    blockedUaCount++;
    res.setHeader("X-Robots-Tag", "noindex, nofollow");
    return void res.status(403).type("text/plain").send("Automated access blocked.");
  }

  // 2) Rate limiting (only /api; the HTML pages are few).
  if (p.startsWith("/api/")) {
    const g = take(ip, GLOBAL_MAX, true); // gross abuse → temporary block
    if (!g.ok) { rateLimited++; res.setHeader("Retry-After", String(g.retryAfter)); return void res.status(429).json({ error: "Rate limit exceeded" }); }
    // 3) Reinforced limit on data endpoints (anti-scraping) — windowed throttle.
    if (DATA_RE.test(p)) {
      const s = take("scrape:" + ip, SCRAPE_MAX, false);
      if (!s.ok) { rateLimited++; res.setHeader("Retry-After", String(s.retryAfter)); return void res.status(429).json({ error: "Scraping rate limit exceeded" }); }
    }
  }
  next();
}

/** Honeypot for public forms: filled hidden field ⇒ bot. */
export function honeypotTriggered(req: Request, field = "website"): boolean {
  const v = (req.body as Record<string, unknown>)?.[field];
  return typeof v === "string" && v.trim() !== "";
}
