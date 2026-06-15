/**
 * vault.ts — Robust data encryption (sensitive fields) in the manner of
 * ProtonMail: zero-access "envelope encryption" (the server cannot read anything
 * without the key).
 *
 *   DEK (Data Encryption Key)  : random AES-256 key that encrypts field VALUES (AES-256-GCM).
 *   KEK (Key Encryption Key)   : derived from the admin's SECRET PASSPHRASE (scrypt + salt).
 *   Vault (XVAULT.json)        : stores only the DEK *wrapped* by the KEK — never the passphrase or the DEK in clear.
 *   Recovery key               : the DEK in base64, shown ONCE to the admin at creation (to be saved offline).
 *                                Lets the secret passphrase be reset if forgotten.
 *
 * The unlocked DEK lives only in server MEMORY (never persisted).
 * Locked: encrypted fields display as "🔒", and writing sensitive
 * fields is refused (to avoid storing cleartext by mistake).
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";

const DB_DIR = process.env.DB_DIR ?? "C:/Users/jerom/XORCISM_databases";
const VAULT_PATH = path.join(DB_DIR, "XVAULT.json");
const TAG = "xenc1:"; // prefix of encrypted values
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 };

interface VaultFile {
  v: number; kdf: "scrypt"; salt: string; N: number; r: number; p: number;
  wrapIv: string; wrapped: string; createdAt: string;
}

let dek: Buffer | null = null; // unlocked DEK (memory only)

// ── Persistent vault ──────────────────────────────────────────────────────────
function readVault(): VaultFile | null {
  try { return JSON.parse(fs.readFileSync(VAULT_PATH, "utf-8")) as VaultFile; }
  catch { return null; }
}
function writeVault(v: VaultFile): void {
  fs.writeFileSync(VAULT_PATH, JSON.stringify(v, null, 2), { mode: 0o600 });
}
export function isConfigured(): boolean { return readVault() !== null; }
export function isUnlocked(): boolean { return dek !== null; }

function deriveKek(passphrase: string, salt: Buffer): Buffer {
  return crypto.scryptSync(passphrase, salt, SCRYPT.keylen,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
}

function wrapDek(passphrase: string, key: Buffer): VaultFile {
  const salt = crypto.randomBytes(16);
  const kek = deriveKek(passphrase, salt);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", kek, iv);
  const ct = Buffer.concat([c.update(key), c.final()]);
  const tag = c.getAuthTag();
  return {
    v: 1, kdf: "scrypt", salt: salt.toString("base64"), N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
    wrapIv: iv.toString("base64"), wrapped: Buffer.concat([ct, tag]).toString("base64"),
    createdAt: new Date().toISOString(),
  };
}

function unwrapDek(passphrase: string, vf: VaultFile): Buffer {
  const kek = crypto.scryptSync(passphrase, Buffer.from(vf.salt, "base64"), 32,
    { N: vf.N, r: vf.r, p: vf.p, maxmem: SCRYPT.maxmem });
  const blob = Buffer.from(vf.wrapped, "base64");
  const ct = blob.subarray(0, blob.length - 16);
  const tag = blob.subarray(blob.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", kek, Buffer.from(vf.wrapIv, "base64"));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]); // throws if wrong passphrase (GCM tag)
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

/** First-time setup: creates the DEK, wraps it with the passphrase, returns the recovery key. */
export function setup(passphrase: string): { recoveryKey: string } {
  if (isConfigured()) throw new Error("Le coffre est déjà configuré.");
  if (!passphrase || passphrase.length < 8) throw new Error("Phrase secrète trop courte (8 caractères min).");
  const key = crypto.randomBytes(32);
  writeVault(wrapDek(passphrase, key));
  dek = key; // unlocked immediately
  return { recoveryKey: key.toString("base64") };
}

export function unlock(passphrase: string): void {
  const vf = readVault();
  if (!vf) throw new Error("Coffre non configuré.");
  try { dek = unwrapDek(passphrase, vf); }
  catch { throw new Error("Phrase secrète incorrecte."); }
}

export function lock(): void { dek = null; }

/** Restores access with the recovery key (DEK base64) and resets the passphrase. */
export function recover(recoveryKey: string, newPassphrase: string): void {
  if (!isConfigured()) throw new Error("Coffre non configuré.");
  if (!newPassphrase || newPassphrase.length < 8) throw new Error("Nouvelle phrase trop courte (8 caractères min).");
  let key: Buffer;
  try { key = Buffer.from(recoveryKey.trim(), "base64"); }
  catch { throw new Error("Clé de récupération invalide."); }
  if (key.length !== 32) throw new Error("Clé de récupération invalide (longueur).");
  writeVault(wrapDek(newPassphrase, key));
  dek = key;
}

// ── Field value encryption ──────────────────────────────────────────────

export function isEncryptedValue(v: unknown): boolean {
  return typeof v === "string" && v.startsWith(TAG);
}

export function encryptValue(plain: string): string {
  if (!dek) throw new Error("Coffre verrouillé.");
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", dek, iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  const tag = c.getAuthTag();
  return TAG + Buffer.concat([iv, ct, tag]).toString("base64");
}

export function decryptValue(tagged: string): string {
  if (!dek) throw new Error("Coffre verrouillé.");
  const blob = Buffer.from(tagged.slice(TAG.length), "base64");
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", dek, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

// ── Columns designated as "sensitive" (encrypted) ───────────────────────────
// By name pattern (all tables) + explicit "TABLE.Column" list.
const ENC_NAME_PATTERNS = [
  /password/i, /passwd/i, /secret/i, /token/i, /credential/i, /privatekey/i,
  /private_key/i, /passphrase/i, /api_?key/i,
];
const ENC_COLUMNS = new Set<string>([
  // explicit examples — extensible
  "ACCOUNT.AccountPassword", "CREDENTIAL.CredentialValue",
]);

export function isEncryptableColumn(table: string, col: string): boolean {
  if (col === "isEncrypted" || /id$/i.test(col)) return false;
  if (ENC_COLUMNS.has(`${table}.${col}`)) return true;
  return ENC_NAME_PATTERNS.some((re) => re.test(col));
}

export function status(): {
  configured: boolean; unlocked: boolean; patterns: string[]; columns: string[];
} {
  return {
    configured: isConfigured(), unlocked: isUnlocked(),
    patterns: ENC_NAME_PATTERNS.map((r) => r.source),
    columns: [...ENC_COLUMNS],
  };
}

/**
 * Encrypts in place the sensitive columns of a row to be written.
 * - not configured → no-op (cleartext, legacy behavior).
 * - configured + unlocked → encrypts + sets isEncrypted=1 if the column exists.
 * - configured + locked → refuses to write a sensitive field in clear.
 */
export function encryptRowForWrite(
  table: string, row: Record<string, unknown>, schemaCols: Set<string>
): void {
  if (!isConfigured()) return;
  let touched = false;
  for (const [k, v] of Object.entries(row)) {
    if (!isEncryptableColumn(table, k)) continue;
    if (v === null || v === undefined || v === "") continue;
    if (isEncryptedValue(v)) { touched = true; continue; } // already encrypted
    if (!isUnlocked()) throw new Error(`Coffre verrouillé : impossible d'écrire le champ sensible « ${k} » en clair.`);
    row[k] = encryptValue(String(v));
    touched = true;
  }
  if (touched && schemaCols.has("isEncrypted")) row.isEncrypted = 1;
}

/** Decrypts (or masks) the encrypted values of a batch of read rows. */
export function decryptRows(rows: Record<string, unknown>[]): void {
  if (!rows.length) return;
  for (const row of rows) {
    for (const [k, v] of Object.entries(row)) {
      if (!isEncryptedValue(v)) continue;
      if (isUnlocked()) {
        try { row[k] = decryptValue(v as string); } catch { row[k] = "🔒 [erreur déchiffrement]"; }
      } else {
        row[k] = "🔒 [chiffré]";
      }
    }
  }
}
