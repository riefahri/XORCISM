/**
 * slsa.ts — SLSA supply-chain level tracker (/slsa).
 *
 * SLSA (Supply-chain Levels for Software Artifacts, slsa.dev) grades the build integrity of a software
 * artifact on Build Levels L0–L3 (provenance → hosted+signed → hardened/isolated). This module tracks
 * each artifact/project's SLSA Build level from its build-integrity attributes (provenance generated /
 * signed, hosted build platform, isolated & hermetic builds) — the supply-chain companion to the
 * Xygeni connector (which surfaces the CI/CD / build-integrity findings that gate these levels).
 *
 * Compute-only posture over SLSAARTIFACT (schema-driven CRUD via the explorer feeds it). Mirrors the
 * other XORCISM cockpits.
 */
import { getDb, allocId } from "./db";
import { randomUUID } from "crypto";

export function ensureSlsaTables(): void {
  getDb("XORCISM").exec(`
    CREATE TABLE IF NOT EXISTS SLSAARTIFACT (
      ArtifactID INTEGER PRIMARY KEY, ArtifactGUID TEXT, ProjectName TEXT, Repo TEXT, BuildPlatform TEXT,
      ProvenanceGenerated INTEGER DEFAULT 0, ProvenanceSigned INTEGER DEFAULT 0, BuildHosted INTEGER DEFAULT 0,
      Isolated INTEGER DEFAULT 0, Hermetic INTEGER DEFAULT 0, TwoPersonReviewed INTEGER DEFAULT 0,
      ProvenanceVerified INTEGER DEFAULT 0, Notes TEXT, TenantID INTEGER, CreatedDate TEXT);
    CREATE INDEX IF NOT EXISTS ix_slsa_tenant ON SLSAARTIFACT(TenantID);
  `);
}

function slsaLevel(a: any): number {
  const prov = !!a.ProvenanceGenerated, signed = !!a.ProvenanceSigned, hosted = !!a.BuildHosted;
  const iso = !!a.Isolated, herm = !!a.Hermetic;
  if (prov && signed && hosted && iso && herm) return 3;
  if (prov && signed && hosted) return 2;
  if (prov) return 1;
  return 0;
}
const nextGap = (lvl: number): string =>
  lvl === 0 ? "Generate build provenance from a scripted build (→ L1)"
  : lvl === 1 ? "Move to a hosted build platform and sign the provenance (→ L2)"
  : lvl === 2 ? "Harden: isolated + hermetic builds with non-falsifiable provenance (→ L3)"
  : "At SLSA Build L3 — maintain.";

export function slsaTracker(tenant: number | null): any {
  ensureSlsaTables();
  const db = getDb("XORCISM");
  const rows = db.prepare("SELECT * FROM SLSAARTIFACT WHERE (TenantID = ? OR TenantID IS NULL) ORDER BY ProjectName").all(tenant) as any[];
  const arts = rows.map((a) => {
    const level = slsaLevel(a);
    return {
      id: a.ArtifactID, project: a.ProjectName || `#${a.ArtifactID}`, repo: a.Repo || "", platform: a.BuildPlatform || "",
      level, gap: nextGap(level),
      provenance: !!a.ProvenanceGenerated, signed: !!a.ProvenanceSigned, hosted: !!a.BuildHosted,
      isolated: !!a.Isolated, hermetic: !!a.Hermetic, verified: !!a.ProvenanceVerified,
    };
  });
  const dist: Record<string, number> = { L0: 0, L1: 0, L2: 0, L3: 0 };
  for (const a of arts) dist[`L${a.level}`]++;
  const summary = {
    artifacts: arts.length,
    avgLevel: arts.length ? Math.round((arts.reduce((s, a) => s + a.level, 0) / arts.length) * 10) / 10 : 0,
    atL2plus: arts.filter((a) => a.level >= 2).length,
    atL0: arts.filter((a) => a.level === 0).length,
    unsigned: arts.filter((a) => !a.signed).length,
  };
  const worklist = arts.filter((a) => a.level < 3).sort((a, b) => a.level - b.level);
  return { summary, dist, artifacts: arts, worklist };
}

/** Demo (tenant-scoped): a few artifacts at varying SLSA levels. Idempotent. */
export function seedSlsaDemo(tenant: number): { artifacts: number } {
  ensureSlsaTables();
  const db = getDb("XORCISM");
  if ((db.prepare("SELECT COUNT(*) n FROM SLSAARTIFACT WHERE TenantID=?").get(tenant) as { n: number }).n > 0) return { artifacts: 0 };
  const seed = [
    { ProjectName: "payments-api", Repo: "github.com/acme/payments-api", BuildPlatform: "GitHub Actions", ProvenanceGenerated: 1, ProvenanceSigned: 1, BuildHosted: 1, Isolated: 1, Hermetic: 1, ProvenanceVerified: 1 },
    { ProjectName: "web-frontend", Repo: "github.com/acme/web", BuildPlatform: "GitHub Actions", ProvenanceGenerated: 1, ProvenanceSigned: 1, BuildHosted: 1, Isolated: 0, Hermetic: 0 },
    { ProjectName: "data-pipeline", Repo: "gitlab.com/acme/etl", BuildPlatform: "GitLab CI", ProvenanceGenerated: 1, ProvenanceSigned: 0, BuildHosted: 0 },
    { ProjectName: "legacy-billing", Repo: "internal/billing", BuildPlatform: "Jenkins (dev laptop)", ProvenanceGenerated: 0 },
  ];
  const now = new Date().toISOString();
  for (const a of seed) {
    const id = allocId(db, "SLSAARTIFACT", "ArtifactID");
    db.prepare(`INSERT INTO SLSAARTIFACT (ArtifactID,ArtifactGUID,ProjectName,Repo,BuildPlatform,ProvenanceGenerated,ProvenanceSigned,BuildHosted,Isolated,Hermetic,ProvenanceVerified,TenantID,CreatedDate)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, randomUUID(), a.ProjectName, a.Repo, a.BuildPlatform,
      a.ProvenanceGenerated || 0, a.ProvenanceSigned || 0, a.BuildHosted || 0, a.Isolated || 0, a.Hermetic || 0, a.ProvenanceVerified || 0, tenant, now);
  }
  return { artifacts: seed.length };
}
