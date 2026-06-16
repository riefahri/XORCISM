/**
 * upload.ts (routes) — File upload (compliance evidence, etc.).
 * Mounted AFTER the auth gate (req.user required). The client reads the file via
 * FileReader and sends a JSON { filename, contentType, dataBase64 }. The file
 * is written OUTSIDE OneDrive (UPLOAD_DIR, next to the databases) and the /uploads/... URL is
 * returned to be stored in the relevant column (e.g. EVIDENCE.EvidenceFile).
 *
 * No multipart dependency: we reuse express.json (25 MB limit). The decoded
 * size is capped at 15 MB to stay under this limit (base64 ≈ +33 %).
 */
import { Router, Request, Response } from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { execFile } from "child_process";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
export const UPLOAD_DIR = path.join(DB_DIR, "uploads");
const MAX_BYTES = 15 * 1024 * 1024;

// If "1": an upload is REFUSED when the antivirus scan could not run
// (ClamAV missing / daemon stopped). By default (0): the upload is allowed but
// marked "not scanned" — we don't block the app if ClamAV is not installed.
const AV_REQUIRED = (process.env.XORCISM_UPLOAD_AV_REQUIRED ?? "0") === "1";

export type AvStatus = "clean" | "infected" | "unavailable";
export interface AvResult { status: AvStatus; signature?: string; scanner?: string }

/**
 * Antivirus scan of the uploaded file with ClamAV (clamdscan via the daemon,
 * otherwise clamscan). Asynchronous (doesn't block the event loop).
 * ClamAV exit codes: 0 = clean, 1 = infected, 2 = error.
 */
export function clamScan(filePath: string): Promise<AvResult> {
  const candidates: [string, string[]][] = [
    ["clamdscan", ["--no-summary", "--fdpass", filePath]],
    ["clamscan", ["--no-summary", filePath]],
  ];
  return new Promise((resolve) => {
    let i = 0;
    const tryNext = (): void => {
      if (i >= candidates.length) return void resolve({ status: "unavailable" });
      const [bin, args] = candidates[i++];
      execFile(bin, args, { timeout: 120000, windowsHide: true }, (err, stdout) => {
        if (!err) return void resolve({ status: "clean", scanner: bin }); // exit 0
        // execFile: code = exit code (number) if exit ≠ 0, or 'ENOENT' (string) if the binary is absent.
        const code = (err as { code?: number | string }).code;
        if (code === 1) {
          // "<file>: <Signature> FOUND"
          const m = /:\s*(.+?)\s+FOUND/i.exec(String(stdout || ""));
          return void resolve({ status: "infected", signature: m ? m[1].trim() : "unknown", scanner: bin });
        }
        // ENOENT (binary absent), 2 (error), timeout → next candidate then "unavailable"
        tryNext();
      });
    };
    tryNext();
  });
}

/** Cleans a file name (anti-traversal, safe characters, bounded length). */
function sanitizeName(name: string): string {
  const base = path
    .basename(name || "fichier")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .replace(/^\.+/, ""); // no hidden file / extension only
  return (base || "fichier").slice(0, 120);
}

const router = Router();

// POST /api/upload  { filename, contentType?, dataBase64 }  ->  { url, name, size, av }
// The file is scanned by ClamAV: an infected file is DELETED and refused.
router.post("/upload", async (req: Request, res: Response) => {
  if (!req.user) return void res.status(401).json({ error: "auth" });
  const b = req.body as { filename?: string; dataBase64?: string };
  if (!b.dataBase64) return void res.status(400).json({ error: "Fichier manquant." });

  // Accepts a data URL (data:...;base64,XXXX) or raw base64.
  const comma = b.dataBase64.indexOf(",");
  const raw =
    b.dataBase64.startsWith("data:") && comma >= 0 ? b.dataBase64.slice(comma + 1) : b.dataBase64;

  let buf: Buffer;
  try {
    buf = Buffer.from(raw, "base64");
  } catch {
    return void res.status(400).json({ error: "Encodage invalide." });
  }
  if (buf.length === 0) return void res.status(400).json({ error: "Fichier vide." });
  if (buf.length > MAX_BYTES)
    return void res.status(413).json({ error: "Fichier trop volumineux (max 15 Mo)." });

  const safe = sanitizeName(b.filename ?? "fichier");
  const sub = new Date().toISOString().slice(0, 7); // YYYY-MM subfolder
  const dir = path.join(UPLOAD_DIR, sub);
  fs.mkdirSync(dir, { recursive: true });
  const stored = `${crypto.randomUUID()}__${safe}`; // unique name + original name
  const full = path.join(dir, stored);
  fs.writeFileSync(full, buf);

  // ── Antivirus scan (ClamAV) of the uploaded file ──
  const av = await clamScan(full);
  if (av.status === "infected") {
    try { fs.unlinkSync(full); } catch { /* already deleted */ }
    console.warn(`[upload] fichier REFUSÉ (infecté : ${av.signature}) — ${safe}`);
    return void res.status(422).json({
      error: `Fichier refusé — menace détectée par ClamAV (${av.signature}).`,
      av: av.status,
    });
  }
  if (av.status === "unavailable" && AV_REQUIRED) {
    try { fs.unlinkSync(full); } catch { /* already deleted */ }
    return void res.status(503).json({
      error: "Analyse antivirus indisponible (ClamAV) — upload refusé.",
      av: av.status,
    });
  }

  res.json({ url: `/uploads/${sub}/${stored}`, name: safe, size: buf.length, av: av.status });
});

export default router;
