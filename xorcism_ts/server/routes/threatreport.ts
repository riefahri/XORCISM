/**
 * threatreport.ts (routes) — THREATREPORT PDF ingestion.
 *
 * POST /api/threatreport/parse { filename, dataBase64 }
 *   → extracts the PDF text (pdf-parse), then:
 *      • IOCs (regex, defang-aware) → XTHREAT.IOC      (idempotent by IOCName)
 *      • known threat actors (dictionary built from ATTACKGROUP/THREATACTOR
 *        names + aliases) → XTHREAT.THREATACTOR        (idempotent by name)
 *   → stores the PDF under UPLOAD_DIR and returns the stored file name + a summary.
 * The client writes the file name into THREATREPORT.ThreatReportFileName.
 *
 * Mounted AFTER the auth gate (req.user required). No multipart dependency:
 * the client sends a base64 data URL (reusing the /api/upload convention).
 */
import { Router, Request, Response } from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { getDb } from "../db";
import { clamScan } from "./upload";

// Use the inner lib to avoid pdf-parse's debug wrapper (which reads a test PDF).
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pdfParse = require("pdf-parse/lib/pdf-parse.js") as (b: Buffer) => Promise<{ text: string; numpages: number }>;

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const UPLOAD_DIR = path.join(DB_DIR, "uploads");
const MAX_BYTES = 15 * 1024 * 1024;
const MAX_IOCS = 1000;
// "1": refuse the upload when the ClamAV scan could not run (scanner missing).
const AV_REQUIRED = (process.env.XORCISM_UPLOAD_AV_REQUIRED ?? "0") === "1";

function nowTs(): string {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}
function sanitizeName(name: string): string {
  const base = path.basename(name || "report.pdf").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^\.+/, "");
  return (base || "report.pdf").slice(0, 120);
}

// ── IOC extraction (defang-aware) ─────────────────────────────────────────────
function refang(s: string): string {
  return s
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/h[xX]{2}p(s?)(:\/\/|\[:\]\/\/)/gi, "http$1://")
    .replace(/\[@\]|\(at\)|\[at\]/gi, "@");
}
interface Ioc { type: string; value: string }
export function extractIocs(text: string): Ioc[] {
  let t = refang(text);
  const out = new Map<string, Ioc>(); // lowercased value → ioc (dedupe)
  const add = (type: string, raw: string): void => {
    const v = raw.trim().replace(/[.,;)\]>"']+$/, "");
    if (v && !out.has(v.toLowerCase())) out.set(v.toLowerCase(), { type, value: v });
  };
  // Hashes (longest first, then remove from the working text).
  for (const m of t.match(/\b[a-fA-F0-9]{64}\b/g) || []) add("file:hashes.SHA-256", m);
  for (const m of t.match(/\b[a-fA-F0-9]{40}\b/g) || []) add("file:hashes.SHA-1", m);
  for (const m of t.match(/\b[a-fA-F0-9]{32}\b/g) || []) add("file:hashes.MD5", m);
  for (const m of t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []) add("vulnerability", m.toUpperCase());
  // URLs and emails, then strip them so their hosts aren't re-matched as bare domains.
  for (const m of t.match(/\bhttps?:\/\/[^\s<>"')\]]+/gi) || []) add("url", m);
  t = t.replace(/\bhttps?:\/\/[^\s<>"')\]]+/gi, " ");
  for (const m of t.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []) add("email-addr", m);
  t = t.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, " ");
  for (const m of t.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || []) add("ipv4-addr", m);
  // Bare domains (skip file-name-looking tokens).
  for (const m of t.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi) || []) {
    const d = m.toLowerCase();
    if (/\.(?:exe|dll|sys|bat|ps1|vbs|js|jar|pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|svg|txt|csv|zip|rar|7z|tar|gz|bin|dat|tmp|log|htm|html|php|aspx?)$/.test(d)) continue;
    add("domain-name", d);
  }
  return [...out.values()].slice(0, MAX_IOCS);
}

// ── Threat-actor dictionary (known names + aliases from the DB) ───────────────
function splitAliases(v: unknown): string[] {
  if (v == null) return [];
  const s = String(v).trim();
  if (!s) return [];
  try {
    const j = JSON.parse(s);
    if (Array.isArray(j)) return j.map((x) => String(x));
  } catch { /* not JSON */ }
  return s.split(/[,;|]/).map((x) => x.trim()).filter(Boolean);
}
function tableExists(db: ReturnType<typeof getDb>, name: string): boolean {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name);
}
export function buildActorDictionary(db: ReturnType<typeof getDb>): Map<string, string> {
  const dict = new Map<string, string>(); // lowercased alias → canonical actor name
  const add = (alias: string, canon: string): void => {
    const a = (alias || "").trim();
    if (a.length >= 3 && !/^\d+$/.test(a)) dict.set(a.toLowerCase(), canon);
  };
  const hasAliases = (tbl: string): boolean =>
    (db.prepare(`PRAGMA table_info("${tbl}")`).all() as { name: string }[]).some((c) => c.name === "Aliases");
  if (tableExists(db, "ATTACKGROUP")) {
    const cols = hasAliases("ATTACKGROUP") ? "Name, Aliases" : "Name, NULL AS Aliases";
    for (const r of db.prepare(`SELECT ${cols} FROM ATTACKGROUP`).all() as Record<string, any>[]) {
      if (r.Name) { add(r.Name, r.Name); for (const a of splitAliases(r.Aliases)) add(a, r.Name); }
    }
  }
  if (tableExists(db, "THREATACTOR")) {
    const cols = hasAliases("THREATACTOR") ? "ThreatActorName, Aliases" : "ThreatActorName, NULL AS Aliases";
    for (const r of db.prepare(`SELECT ${cols} FROM THREATACTOR`).all() as Record<string, any>[]) {
      if (r.ThreatActorName) { add(r.ThreatActorName, r.ThreatActorName); for (const a of splitAliases(r.Aliases)) add(a, r.ThreatActorName); }
    }
  }
  return dict;
}
export function extractActors(text: string, dict: Map<string, string>): string[] {
  const lower = text.toLowerCase();
  const found = new Set<string>();
  for (const [alias, canon] of dict) {
    let i = lower.indexOf(alias);
    while (i !== -1) {
      const before = i === 0 ? " " : lower[i - 1];
      const after = i + alias.length >= lower.length ? " " : lower[i + alias.length];
      if (!/[a-z0-9]/i.test(before) && !/[a-z0-9]/i.test(after)) { found.add(canon); break; }
      i = lower.indexOf(alias, i + 1);
    }
  }
  return [...found];
}

// ── Inserts (idempotent) ──────────────────────────────────────────────────────
function upsertIocs(db: ReturnType<typeof getDb>, iocs: Ioc[], source: string): number {
  let n = 0;
  const insert = db.prepare(
    `INSERT INTO IOC (IOCGUID, IOCName, IOCDescription, CreatedDate, IOCtype, Pattern, PatternType)
     VALUES (?, ?, ?, ?, ?, ?, 'stix')`
  );
  const exists = db.prepare("SELECT 1 FROM IOC WHERE IOCName = ? LIMIT 1");
  const tx = db.transaction(() => {
    for (const ioc of iocs) {
      if (exists.get(ioc.value)) continue;
      const pattern = `[${ioc.type.split(":")[0]}:value = '${ioc.value.replace(/'/g, "''")}']`;
      insert.run(crypto.randomUUID(), ioc.value, `Extracted from threat report: ${source}`, nowTs(), ioc.type, pattern);
      n++;
    }
  });
  tx();
  return n;
}
function upsertActors(db: ReturnType<typeof getDb>, names: string[], source: string): number {
  let n = 0;
  let nextId = ((db.prepare("SELECT COALESCE(MAX(ThreatActorID),0) AS m FROM THREATACTOR").get() as { m: number }).m) + 1;
  const exists = db.prepare("SELECT 1 FROM THREATACTOR WHERE ThreatActorName = ? COLLATE NOCASE LIMIT 1");
  const insert = db.prepare(
    `INSERT INTO THREATACTOR (ThreatActorID, ThreatActorGUID, ThreatActorName, ThreatActorDescription, CreatedDate)
     VALUES (?, ?, ?, ?, ?)`
  );
  const tx = db.transaction(() => {
    for (const name of names) {
      if (exists.get(name)) continue;
      insert.run(nextId++, crypto.randomUUID(), name, `Mentioned in threat report: ${source}`, nowTs());
      n++;
    }
  });
  tx();
  return n;
}

const router = Router();

router.post("/threatreport/parse", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = req.body as { filename?: string; dataBase64?: string };
  if (!b.dataBase64) return void res.status(400).json({ error: "Missing file." });

  const comma = b.dataBase64.indexOf(",");
  const raw = b.dataBase64.startsWith("data:") && comma >= 0 ? b.dataBase64.slice(comma + 1) : b.dataBase64;
  let buf: Buffer;
  try { buf = Buffer.from(raw, "base64"); } catch { return void res.status(400).json({ error: "Invalid encoding." }); }
  if (buf.length === 0) return void res.status(400).json({ error: "Empty file." });
  if (buf.length > MAX_BYTES) return void res.status(413).json({ error: "File too large (max 15 MB)." });
  if (buf.slice(0, 5).toString("latin1") !== "%PDF-") return void res.status(415).json({ error: "Not a PDF file." });

  const fileName = sanitizeName(b.filename ?? "report.pdf");

  // Store the PDF, then AV-scan it with ClamAV BEFORE parsing / ingesting.
  let full: string | null = null;
  try {
    const sub = new Date().toISOString().slice(0, 7);
    const dir = path.join(UPLOAD_DIR, sub);
    fs.mkdirSync(dir, { recursive: true });
    full = path.join(dir, `${crypto.randomUUID()}__${fileName}`);
    fs.writeFileSync(full, buf);
  } catch { full = null; /* storage is best-effort */ }

  if (full) {
    const av = await clamScan(full);
    if (av.status === "infected") {
      try { fs.unlinkSync(full); } catch { /* already gone */ }
      console.warn(`[threatreport] PDF REFUSED (infected: ${av.signature}) — ${fileName}`);
      return void res.status(422).json({ error: `File refused — threat detected by ClamAV (${av.signature}).`, av: av.status });
    }
    if (av.status === "unavailable" && AV_REQUIRED) {
      try { fs.unlinkSync(full); } catch { /* already gone */ }
      return void res.status(503).json({ error: "Antivirus scan unavailable (ClamAV) — upload refused.", av: av.status });
    }
  }

  // Extract text (only after the AV gate).
  let text = "";
  try { text = (await pdfParse(buf)).text || ""; } catch (e) { return void res.status(422).json({ error: "Unreadable PDF: " + String(e) }); }

  const db = getDb("XTHREAT");
  const iocs = extractIocs(text);
  const actors = extractActors(text, buildActorDictionary(db));
  const newIocs = upsertIocs(db, iocs, fileName);
  const newActors = upsertActors(db, actors, fileName);

  res.json({
    fileName,
    source: fileName.replace(/\.pdf$/i, ""),
    chars: text.length,
    iocsFound: iocs.length, newIocs,
    actorsFound: actors.length, newActors,
    actorNames: actors.slice(0, 50),
    iocSample: iocs.slice(0, 50),
  });
});

export default router;
