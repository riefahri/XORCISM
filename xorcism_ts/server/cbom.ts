/**
 * cbom.ts — Cryptographic Bill of Materials (CBOM).
 *
 * A first-class inventory of cryptographic assets (algorithms, certificates, protocols, keys) across
 * the estate, with each asset classified quantum-safe vs quantum-vulnerable. Imports a CycloneDX 1.6
 * CBOM (component.type = "cryptographic-asset" + cryptoProperties) or a plain list, stores rows in
 * XORCISM.CRYPTOASSET, and rolls up the quantum-readiness picture that feeds PQCMM ([[pqcmm]]).
 *
 * Quantum classification (deterministic): Shor breaks classical public-key crypto (RSA, ECC/ECDSA/ECDH,
 * DH, DSA, ElGamal) → quantum-vulnerable. NIST PQC standards (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/
 * SPHINCS+, FN-DSA/Falcon) and hash-based sigs (XMSS/LMS) → quantum-safe. Symmetric/hashes are safe at
 * adequate sizes (AES-256, SHA-384/512/3); AES-128 / SHA-256 are weakened by Grover but not broken.
 */
import { allocId, getDb } from "./db";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

const QUANTUM_VULNERABLE = /\b(rsa|ecdsa|ecdh|ecc|ecies|ed25519|ed448|x25519|x448|curve25519|secp\d|prime256|nistp|brainpool|\bdh\b|diffie|dsa|elgamal|dss)\b/i;
const QUANTUM_SAFE = /\b(ml-?kem|kyber|ml-?dsa|dilithium|slh-?dsa|sphincs|fn-?dsa|falcon|mceliece|bike|hqc|frodo|ntru|saber|xmss|\blms\b|hss)\b/i;
const SYMMETRIC = /\b(aes|chacha|salsa|camellia|aria|seed|sm4|3des|des|blowfish|twofish|rc4)\b/i;
const HASH = /\b(sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha-?3|sha3|shake|blake|md5|md4|ripemd|sm3|whirlpool)\b/i;
const WEAK = /\b(md5|md4|sha-?1|\bdes\b|3des|rc4|blowfish)\b/i;

/** Quantum-safety verdict for an algorithm. Returns 1 safe / 0 vulnerable / null unknown. */
export function quantumSafe(algorithm: string, primitive?: string, nistLevel?: number | null): number | null {
  const a = `${algorithm || ""} ${primitive || ""}`;
  if (nistLevel != null && Number(nistLevel) >= 1) return 1; // declared NIST PQC level
  if (QUANTUM_SAFE.test(a)) return 1;
  if (QUANTUM_VULNERABLE.test(a)) return 0;
  if (SYMMETRIC.test(a)) {
    const m = a.match(/(\d{3,4})/);
    const bits = m ? Number(m[1]) : 0;
    if (/3des|\bdes\b|rc4|blowfish/i.test(a)) return 0;            // broken regardless of quantum
    return bits >= 256 ? 1 : 0;                                    // AES-256 safe; AES-128 Grover-weakened
  }
  if (HASH.test(a)) {
    if (/md5|md4|sha-?1/i.test(a)) return 0;
    const m = a.match(/(\d{3,4})/);
    return (m && Number(m[1]) >= 384) || /sha-?3|sha3|shake/i.test(a) ? 1 : 0; // SHA-384+/SHA-3 safe
  }
  return null;
}

const num = (v: unknown): number | null => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const str = (v: unknown): string => (v == null ? "" : String(v)).slice(0, 300);

/** Normalize one crypto asset (from CycloneDX cryptoProperties or a plain object) into a CRYPTOASSET row. */
function normalizeCryptoAsset(c: any): any {
  const cp = c.cryptoProperties || c.crypto || {};
  const alg = cp.algorithmProperties || {};
  const cert = cp.certificateProperties || {};
  const proto = cp.protocolProperties || {};
  const assetType = str(cp.assetType || c.assetType || (cert.subjectName ? "certificate" : proto.type ? "protocol" : "algorithm")).toLowerCase();
  // algorithm name: prefer explicit, else component name
  const algorithm = str(c.algorithm || alg.primitive && c.name || c.name || cp.oid || "");
  const primitive = str(alg.primitive || c.primitive || (assetType === "certificate" ? "certificate" : assetType === "protocol" ? "protocol" : ""));
  const keySize = num(alg.parameterSetIdentifier) ?? num(c.keySize) ?? num(alg.keySize);
  const curve = str(alg.curve || c.curve);
  const classicalBits = num(alg.classicalSecurityLevel);
  const nistLevel = num(alg.nistQuantumSecurityLevel) ?? num(c.nistQuantumSecurityLevel);
  const protocol = str(proto.type ? `${proto.type}${proto.version ? " " + proto.version : ""}` : c.protocol);
  const qs = quantumSafe(`${algorithm} ${curve}`, primitive, nistLevel);
  return {
    name: str(c.name || algorithm || cp.oid || "crypto-asset"), bomRef: str(c["bom-ref"] || c.bomRef),
    assetType, primitive, algorithm: algorithm || str(c.name), keySize, curve,
    classicalBits, nistLevel, quantumSafe: qs, deprecated: WEAK.test(`${algorithm} ${curve}`) ? 1 : 0,
    protocol, certSubject: str(cert.subjectName), certIssuer: str(cert.issuerName), certNotAfter: str(cert.notValidAfter),
    oid: str(cp.oid || c.oid),
  };
}

/** Import a CBOM (CycloneDX 1.6 JSON, a plain {cryptoAssets:[]} / array). Returns counts. */
export function importCbom(input: any, opts: { assetId?: number | null; source?: string; tenant: number | null; sbomId?: number | null }): { imported: number; quantumVulnerable: number } {
  const db = getDb("XORCISM");
  if (!has(db, "CRYPTOASSET")) return { imported: 0, quantumVulnerable: 0 };
  let doc = input;
  if (typeof input === "string") { try { doc = JSON.parse(input); } catch { throw new Error("CBOM is not valid JSON"); } }
  // collect candidate crypto components
  let comps: any[] = [];
  if (Array.isArray(doc)) comps = doc;
  else if (Array.isArray(doc.cryptoAssets)) comps = doc.cryptoAssets;
  else if (Array.isArray(doc.components)) comps = doc.components.filter((c: any) => String(c.type || "").toLowerCase() === "cryptographic-asset" || c.cryptoProperties);
  if (!comps.length) throw new Error("No cryptographic assets found (expected CycloneDX components[type=cryptographic-asset] or cryptoAssets[])");

  const now = new Date().toISOString();
  const ins = db.prepare(`INSERT INTO CRYPTOASSET (CryptoAssetID, CryptoAssetGUID, Name, BomRef, AssetType, Primitive, Algorithm,
    KeySize, Curve, ClassicalBits, NistQuantumLevel, QuantumSafe, Deprecated, Protocol, CertSubject, CertIssuer, CertNotAfter, Oid,
    AssetID, SbomID, Source, TenantID, CreatedDate) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  let n = 0, qv = 0;
  const tx = db.transaction(() => {
    for (const c of comps) {
      const r = normalizeCryptoAsset(c);
      const id = allocId(db, "CRYPTOASSET", "CryptoAssetID");
      ins.run(id, (globalThis as any).crypto?.randomUUID?.() ?? String(id), r.name, r.bomRef, r.assetType, r.primitive, r.algorithm,
        r.keySize, r.curve, r.classicalBits, r.nistLevel, r.quantumSafe, r.deprecated, r.protocol, r.certSubject, r.certIssuer, r.certNotAfter, r.oid,
        opts.assetId ?? null, opts.sbomId ?? null, (opts.source || "CBOM import").slice(0, 120), opts.tenant, now);
      n++; if (r.quantumSafe === 0) qv++;
    }
  });
  tx();
  return { imported: n, quantumVulnerable: qv };
}

/** Full CBOM inventory + quantum-readiness rollup + worklist (quantum-vulnerable / deprecated first). */
export function cbomInventory(tenant: number | null): any {
  const db = getDb("XORCISM");
  const empty = { rows: [], summary: { total: 0, quantumSafe: 0, quantumVulnerable: 0, unknown: 0, deprecated: 0, certificates: 0, protocols: 0, withAsset: 0, quantumReadiness: 0, byPrimitive: [], byAlgorithm: [] }, worklist: [] };
  if (!has(db, "CRYPTOASSET")) return empty;
  const tw = tenant != null ? "WHERE (TenantID = ? OR TenantID IS NULL)" : "";
  const rows = (tenant != null ? db.prepare(`SELECT * FROM CRYPTOASSET ${tw} ORDER BY QuantumSafe ASC, Algorithm`).all(tenant) : db.prepare("SELECT * FROM CRYPTOASSET ORDER BY QuantumSafe ASC, Algorithm").all()) as any[];
  // resolve asset names
  const assetName = new Map<number, string>();
  try {
    const ids = [...new Set(rows.map((r) => Number(r.AssetID)).filter(Boolean))];
    if (ids.length) for (const a of db.prepare(`SELECT AssetID, AssetName FROM ASSET WHERE AssetID IN (${ids.map(() => "?").join(",")})`).all(...ids) as any[]) assetName.set(Number(a.AssetID), a.AssetName);
  } catch { /* */ }

  const out = rows.map((r) => ({
    id: Number(r.CryptoAssetID), name: String(r.Name ?? ""), assetType: String(r.AssetType ?? ""), primitive: String(r.Primitive ?? ""),
    algorithm: String(r.Algorithm ?? ""), keySize: r.KeySize != null ? Number(r.KeySize) : null, curve: String(r.Curve ?? ""),
    nistLevel: r.NistQuantumLevel != null ? Number(r.NistQuantumLevel) : null,
    quantumSafe: r.QuantumSafe == null ? null : Number(r.QuantumSafe) === 1, deprecated: Number(r.Deprecated) === 1,
    protocol: String(r.Protocol ?? ""), certSubject: String(r.CertSubject ?? ""), certNotAfter: String(r.CertNotAfter ?? ""),
    asset: r.AssetID != null ? (assetName.get(Number(r.AssetID)) ?? `Asset #${r.AssetID}`) : null, assetId: r.AssetID != null ? Number(r.AssetID) : null,
    source: String(r.Source ?? ""),
  }));

  const tally = (key: (x: any) => string) => {
    const m = new Map<string, number>();
    for (const r of out) { const k = key(r) || "—"; m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].map(([k, n]) => ({ key: k, n })).sort((a, b) => b.n - a.n).slice(0, 12);
  };
  const qSafe = out.filter((r) => r.quantumSafe === true).length;
  const qVuln = out.filter((r) => r.quantumSafe === false).length;
  const classified = qSafe + qVuln;
  const worklist = out.filter((r) => r.quantumSafe === false || r.deprecated)
    .map((r) => ({ id: r.id, name: r.name, algorithm: r.algorithm, asset: r.asset, severity: r.deprecated ? "High" : "Medium", reason: r.deprecated ? "Deprecated/broken algorithm" : "Quantum-vulnerable (classical public-key)" }))
    .slice(0, 50);

  return {
    rows: out,
    summary: {
      total: out.length, quantumSafe: qSafe, quantumVulnerable: qVuln, unknown: out.filter((r) => r.quantumSafe === null).length,
      deprecated: out.filter((r) => r.deprecated).length, certificates: out.filter((r) => r.assetType === "certificate").length,
      protocols: out.filter((r) => r.assetType === "protocol").length, withAsset: out.filter((r) => r.assetId != null).length,
      quantumReadiness: classified ? Math.round((qSafe / classified) * 100) : 0,
      byPrimitive: tally((r) => r.primitive), byAlgorithm: tally((r) => r.algorithm),
    },
    worklist,
  };
}

/** Seed a small demo CBOM for a tenant (idempotent: skips if any crypto assets exist). */
export function seedCbom(tenant: number): { imported: number } {
  const db = getDb("XORCISM");
  if (!has(db, "CRYPTOASSET")) return { imported: 0 };
  if ((db.prepare("SELECT COUNT(*) n FROM CRYPTOASSET WHERE IFNULL(TenantID,-1)=IFNULL(?,-1)").get(tenant) as { n: number }).n) return { imported: 0 };
  const sample = { components: [
    { type: "cryptographic-asset", name: "RSA-2048", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "pke", parameterSetIdentifier: 2048, classicalSecurityLevel: 112, nistQuantumSecurityLevel: 0 } } },
    { type: "cryptographic-asset", name: "ECDSA-P256", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "signature", curve: "secp256r1", classicalSecurityLevel: 128, nistQuantumSecurityLevel: 0 } } },
    { type: "cryptographic-asset", name: "AES-256-GCM", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "ae", parameterSetIdentifier: 256, classicalSecurityLevel: 256 } } },
    { type: "cryptographic-asset", name: "SHA-256", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "hash", parameterSetIdentifier: 256 } } },
    { type: "cryptographic-asset", name: "ML-KEM-768", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "kem", parameterSetIdentifier: 768, nistQuantumSecurityLevel: 3 } } },
    { type: "cryptographic-asset", name: "ML-DSA-65", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "signature", nistQuantumSecurityLevel: 3 } } },
    { type: "cryptographic-asset", name: "TLS 1.2", cryptoProperties: { assetType: "protocol", protocolProperties: { type: "tls", version: "1.2" } } },
    { type: "cryptographic-asset", name: "edge01.example.com", cryptoProperties: { assetType: "certificate", certificateProperties: { subjectName: "CN=edge01.example.com", issuerName: "CN=Lets Encrypt", notValidAfter: "2026-09-01" } } },
  ] };
  return { imported: importCbom(sample, { tenant, source: "CBOM demo seed" }).imported };
}
