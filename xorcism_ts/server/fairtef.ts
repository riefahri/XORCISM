/**
 * fairtef.ts — FAIR frequency side: Threat / Loss Event Frequency estimation by Monte Carlo.
 *
 * The FAIR ontology's left branch, complementing FAIR-MAM (the loss-magnitude branch, fairmam.ts):
 *
 *   Loss Event Frequency (LEF) = Threat Event Frequency (TEF) × Vulnerability
 *   TEF          = Contact Frequency (CF) × Probability of Action (PoA)
 *   Vulnerability = P(Threat Capability (TCap) > Resistance Strength (RS))
 *   Annualized Loss Expectancy (ALE) = LEF × Loss Magnitude (LM)
 *
 * Each factor is a PERT estimate (min / most-likely / max); we sample them with a Beta-PERT
 * distribution and run a Monte Carlo simulation to produce distributions for TEF / Vulnerability /
 * LEF (and ALE when a loss magnitude — a single SLE, or a FAIR-MAM assessment total — is supplied),
 * plus a loss-exceedance curve. Persisted assessments write LEF + ALE back onto the linked
 * XCOMPLIANCE.RISKREGISTERENTRY (LossEventFrequency / AnnualizedLossExpectancy). Surfaced at /fair-tef.
 */
import { randomUUID } from "crypto";
import { getDb } from "./db";
import { linkableRisks, fairMamInventory } from "./fairmam";

const has = (db: ReturnType<typeof getDb>, t: string): boolean => {
  try { return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t); } catch { return false; }
};

// ── PERT / Monte-Carlo primitives ────────────────────────────────────────────────────
function gaussian(): number { let u = 0, v = 0; while (u === 0) u = Math.random(); while (v === 0) v = Math.random(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
/** Marsaglia–Tsang gamma sampler (shape k>0, scale 1). */
function gammaSample(k: number): number {
  if (k < 1) return gammaSample(1 + k) * Math.pow(Math.random() || 1e-12, 1 / k);
  const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d);
  for (;;) {
    let x = 0, v = 0;
    do { x = gaussian(); v = 1 + c * x; } while (v <= 0);
    v = v * v * v; const u = Math.random();
    if (u < 1 - 0.0331 * x * x * x * x) return d * v;
    if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
}
function betaSample(a: number, b: number): number { const x = gammaSample(a), y = gammaSample(b); return x + y > 0 ? x / (x + y) : 0; }
/** Sample a Beta-PERT(min, mostLikely, max) value (λ=4 — the classic PERT smoothing). */
function pertSample(min: number, ml: number, max: number, lambda = 4): number {
  min = Number(min); ml = Number(ml); max = Number(max);
  if (!Number.isFinite(min)) min = 0;
  if (!Number.isFinite(max) || max <= min) return min;
  ml = Math.min(Math.max(Number.isFinite(ml) ? ml : (min + max) / 2, min), max);
  const a = 1 + lambda * (ml - min) / (max - min);
  const b = 1 + lambda * (max - ml) / (max - min);
  return min + betaSample(a, b) * (max - min);
}
const clamp01 = (x: number): number => Math.max(0, Math.min(1, x));

interface Dist { min: number; p10: number; p50: number; mean: number; p90: number; max: number }
function stats(arr: number[]): Dist {
  const s = [...arr].sort((x, y) => x - y); const n = s.length || 1;
  const pct = (p: number): number => s[Math.min(n - 1, Math.max(0, Math.round(p * (n - 1))))] ?? 0;
  const mean = arr.reduce((a, b) => a + b, 0) / n;
  return { min: s[0] ?? 0, p10: pct(0.10), p50: pct(0.50), mean, p90: pct(0.90), max: s[n - 1] ?? 0 };
}
const r4 = (d: Dist): Dist => ({ min: round(d.min, 4), p10: round(d.p10, 4), p50: round(d.p50, 4), mean: round(d.mean, 4), p90: round(d.p90, 4), max: round(d.max, 4) });
const r0 = (d: Dist): Dist => ({ min: Math.round(d.min), p10: Math.round(d.p10), p50: Math.round(d.p50), mean: Math.round(d.mean), p90: Math.round(d.p90), max: Math.round(d.max) });
function round(n: number, dp: number): number { const f = 10 ** dp; return Math.round(n * f) / f; }

export interface TefInput { cf: [number, number, number]; poa: [number, number, number]; tcap: [number, number, number]; rs: [number, number, number]; lossMagnitude?: number | null; iterations?: number }

/** Run the FAIR frequency Monte Carlo. Returns TEF / Vulnerability / LEF distributions, ALE (if a loss
 *  magnitude is given) and a loss-exceedance curve (annual-loss, else annual-frequency). */
export function runFairTef(inp: TefInput): any {
  const N = Math.min(50000, Math.max(1000, Math.round(inp.iterations || 10000)));
  const lm = Number(inp.lossMagnitude) || 0;
  const tef: number[] = new Array(N), lef: number[] = new Array(N); const ale: number[] = lm > 0 ? new Array(N) : [];
  let vulnSum = 0;
  for (let i = 0; i < N; i++) {
    const cf = Math.max(0, pertSample(inp.cf[0], inp.cf[1], inp.cf[2]));
    const poa = clamp01(pertSample(inp.poa[0], inp.poa[1], inp.poa[2]));
    const t = cf * poa;
    const tcap = pertSample(inp.tcap[0], inp.tcap[1], inp.tcap[2]);
    const rs = pertSample(inp.rs[0], inp.rs[1], inp.rs[2]);
    const v = tcap > rs ? 1 : 0;
    const l = t * v;
    tef[i] = t; lef[i] = l; vulnSum += v;
    if (lm > 0) ale[i] = l * lm;
  }
  const lefS = stats(lef);
  const aleArr = lm > 0 ? ale : null;
  // loss-exceedance curve: P(annual ≥ x) over 21 points (annual $ when LM given, else annual frequency)
  const curveSrc = [...(aleArr ?? lef)].sort((a, b) => a - b);
  const lec: { x: number; prob: number }[] = [];
  for (let k = 0; k <= 20; k++) {
    const idx = Math.min(curveSrc.length - 1, Math.round((k / 20) * (curveSrc.length - 1)));
    lec.push({ x: lm > 0 ? Math.round(curveSrc[idx]) : round(curveSrc[idx], 4), prob: round(1 - idx / (curveSrc.length - 1), 3) });
  }
  return {
    iterations: N,
    tef: r4(stats(tef)),
    vulnerability: round(vulnSum / N, 4),
    lef: r4(lefS),
    ale: aleArr ? r0(stats(aleArr)) : null,
    lossMagnitude: lm || null,
    lec,
    annualizedRiskExposure: aleArr ? Math.round(stats(aleArr).mean) : null,
  };
}

// ── inventory / list ─────────────────────────────────────────────────────────────────
export function fairTefInventory(tenant: number | null): any {
  const risks = linkableRisks(tenant);
  const fairmam = fairMamInventory(tenant).assessments.map((a) => ({ id: a.id, name: a.name, total: a.total, currency: a.currency }));
  let cc; try { cc = getDb("XCOMPLIANCE"); } catch { return { assessments: [], risks, fairmam, summary: empty() }; }
  if (!has(cc, "FAIRTEFASSESSMENT")) return { assessments: [], risks, fairmam, summary: empty() };
  const tw = tenant != null ? `WHERE TenantID = ${tenant}` : "";
  const rows = cc.prepare(`SELECT * FROM FAIRTEFASSESSMENT ${tw} ORDER BY AssessmentID DESC`).all() as Record<string, any>[];
  const assessments = rows.map((r) => ({
    id: Number(r.AssessmentID), name: String(r.Name ?? `TEF #${r.AssessmentID}`), scenarioRef: r.ScenarioRef ?? null,
    riskRegisterEntryId: r.RiskRegisterEntryID ?? null, threatCommunity: r.ThreatCommunity ?? null, currency: String(r.Currency ?? "EUR"),
    tef: num(r.TefMean), vuln: num(r.VulnMean), lef: num(r.LefMean), lefP90: num(r.LefP90),
    lossMagnitude: r.LossMagnitude != null ? num(r.LossMagnitude) : null, ale: r.AleMean != null ? num(r.AleMean) : null, aleP90: r.AleP90 != null ? num(r.AleP90) : null,
    iterations: Number(r.Iterations ?? 0), createdDate: r.CreatedDate ? String(r.CreatedDate).slice(0, 10) : null,
  }));
  const ales = assessments.map((a) => a.ale ?? 0).filter((x) => x > 0);
  return {
    assessments, risks, fairmam,
    summary: {
      assessments: assessments.length,
      totalAle: ales.reduce((a, b) => a + b, 0), largestAle: ales.length ? Math.max(...ales) : 0,
      avgLef: assessments.length ? round(assessments.reduce((s, a) => s + a.lef, 0) / assessments.length, 3) : 0,
      currency: assessments[0]?.currency ?? "EUR",
    },
  };
}
const empty = () => ({ assessments: 0, totalAle: 0, largestAle: 0, avgLef: 0, currency: "EUR" });
const num = (v: unknown): number => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

// ── persist + risk write-back ──────────────────────────────────────────────────────────
export interface TefPayload {
  name?: string; scenarioRef?: string; threatCommunity?: string; riskRegisterEntryId?: number; fairMamAssessmentId?: number;
  currency?: string; iterations?: number;
  cf?: [number, number, number]; poa?: [number, number, number]; tcap?: [number, number, number]; rs?: [number, number, number];
  lossMagnitude?: number;
}

/** Resolve the loss magnitude: an explicit value, else the total of a linked FAIR-MAM assessment. */
function resolveLossMagnitude(payload: TefPayload, tenant: number | null): number {
  if (payload.lossMagnitude != null && Number.isFinite(Number(payload.lossMagnitude))) return Number(payload.lossMagnitude);
  if (payload.fairMamAssessmentId) {
    const a = fairMamInventory(tenant).assessments.find((x) => x.id === Number(payload.fairMamAssessmentId));
    if (a) return a.total;
  }
  return 0;
}

export function computeFairTef(payload: TefPayload, tenant: number | null): any {
  const lm = resolveLossMagnitude(payload, tenant);
  return runFairTef({ cf: payload.cf || [0, 0, 0], poa: payload.poa || [0, 0, 0], tcap: payload.tcap || [0, 0, 0], rs: payload.rs || [0, 0, 0], lossMagnitude: lm, iterations: payload.iterations });
}

export function saveFairTefAssessment(payload: TefPayload, tenant: number | null, userId: number | null): { assessmentId: number; result: any; riskWriteback: { id: number; ref: string; lef: number; ale: number | null } | null } {
  const cc = getDb("XCOMPLIANCE");
  const lm = resolveLossMagnitude(payload, tenant);
  const result = runFairTef({ cf: payload.cf || [0, 0, 0], poa: payload.poa || [0, 0, 0], tcap: payload.tcap || [0, 0, 0], rs: payload.rs || [0, 0, 0], lossMagnitude: lm, iterations: payload.iterations });
  const now = new Date().toISOString();
  const cf = payload.cf || [0, 0, 0], poa = payload.poa || [0, 0, 0], tcap = payload.tcap || [0, 0, 0], rs = payload.rs || [0, 0, 0];
  const r = cc.prepare(
    `INSERT INTO FAIRTEFASSESSMENT (AssessmentGUID, Name, ScenarioRef, RiskRegisterEntryID, FairMamAssessmentID, ThreatCommunity, Iterations, Currency,
       CfMin,CfMl,CfMax, PoaMin,PoaMl,PoaMax, TcapMin,TcapMl,TcapMax, RsMin,RsMl,RsMax,
       LossMagnitude, TefMean, VulnMean, LefMean, LefP10, LefP50, LefP90, AleMean, AleP90, Status, PersonID, CreatedDate, TenantID)
     VALUES (?,?,?,?,?,?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(randomUUID(), (payload.name || `FAIR TEF ${now.slice(0, 10)}`).slice(0, 300), payload.scenarioRef ? String(payload.scenarioRef).slice(0, 300) : null,
    payload.riskRegisterEntryId ?? null, payload.fairMamAssessmentId ?? null, payload.threatCommunity ? String(payload.threatCommunity).slice(0, 200) : null,
    result.iterations, (payload.currency || "EUR").slice(0, 8),
    cf[0], cf[1], cf[2], poa[0], poa[1], poa[2], tcap[0], tcap[1], tcap[2], rs[0], rs[1], rs[2],
    lm || null, result.tef.mean, result.vulnerability, result.lef.mean, result.lef.p10, result.lef.p50, result.lef.p90,
    result.ale ? result.ale.mean : null, result.ale ? result.ale.p90 : null, "Final", userId, now, tenant);
  const assessmentId = Number(r.lastInsertRowid);

  // Write LEF (and ALE when a magnitude is present) back onto the linked risk-register entry.
  let riskWriteback: { id: number; ref: string; lef: number; ale: number | null } | null = null;
  const rid = Number(payload.riskRegisterEntryId) || 0;
  if (rid && has(cc, "RISKREGISTERENTRY")) {
    try {
      const rcols = new Set((cc.prepare(`PRAGMA table_info("RISKREGISTERENTRY")`).all() as { name: string }[]).map((c) => c.name));
      const tg = tenant != null && rcols.has("TenantID") ? " AND TenantID = ?" : "";
      const entry = cc.prepare(`SELECT Ref, SingleLossExpectancy FROM RISKREGISTERENTRY WHERE RiskRegisterEntryID = ?${tg}`).get(...(tg ? [rid, tenant] : [rid])) as { Ref?: string; SingleLossExpectancy?: unknown } | undefined;
      if (entry) {
        const lef = round(result.lef.mean, 4);
        // ALE: prefer the simulated ALE; else LEF × the risk's existing SLE
        const sle = Number(entry.SingleLossExpectancy);
        const ale = result.ale ? result.ale.mean : (Number.isFinite(sle) && sle > 0 ? Math.round(lef * sle) : null);
        cc.prepare(`UPDATE RISKREGISTERENTRY SET LossEventFrequency = ?, AnnualizedLossExpectancy = COALESCE(?, AnnualizedLossExpectancy) WHERE RiskRegisterEntryID = ?${tg}`)
          .run(...[lef, ale, rid, ...(tg ? [tenant] : [])]);
        riskWriteback = { id: rid, ref: String(entry.Ref ?? `R-${rid}`), lef, ale };
      }
    } catch { /* best-effort */ }
  }
  return { assessmentId, result, riskWriteback };
}
