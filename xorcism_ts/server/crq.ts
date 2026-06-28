/**
 * crq.ts — Cyber Risk Quantification (CRQ) decision support.
 *
 * Inspired by Gartner's "Innovation Insight for Cyber Risk Quantification" (FAIR Institute analysis):
 * the value of CRQ is no longer producing a number but *operationalizing* it for decisions. This module
 * turns XORCISM's already-quantified risk register (FAIR/CRQ ALE per risk, residual level, treatment,
 * risk appetite) into answers to the four decision questions Gartner says a mature CRQ program must
 * answer continuously:
 *   1. Which exposures should we remediate first?           → remediateFirst (ranked by annualized loss)
 *   2. Which investments maximize risk reduction?           → investments (expected ALE reduction / ROSI)
 *   3. Which risks are outside our risk appetite?           → appetite (over-appetite register)
 *   4. How do we optimize limited resources?                → scenarios (current vs treated ALE) + portfolio
 *
 * Everything is derived live from riskRegisterInventory() (driven by FAIR-MAM/TEF write-back), so it is
 * "continuous" rather than a periodic exercise, and expressed in financial / board terms with an explicit
 * uncertainty band. The one modelling assumption (control effectiveness by treatment state) is transparent.
 */
import { riskRegisterInventory } from "./riskregister";

// Transparent control-effectiveness assumptions (fraction of ALE a treatment is expected to remove).
const EFFECTIVENESS = { untreated: 0.7, planned: 0.4, treated: 0.15 };

export interface CrqAction {
  id: number; ref: string; title: string; level: string; ale: number; aleLow: number; aleHigh: number;
  treatment: string; hasPlan: boolean; overAppetite: boolean; expectedReduction: number; effectiveness: number;
  reason: string;
}
export interface CrqResult {
  currency: string;
  portfolio: { totalALE: number; aleLow: number; aleHigh: number; quantifiedRisks: number; openRisks: number; overAppetite: number; untreated: number; aboveAppetiteALE: number };
  remediateFirst: CrqAction[];
  investments: CrqAction[];
  appetite: { overCount: number; withinCount: number; overALE: number; items: CrqAction[] };
  scenarios: { name: string; ale: number; reductionPct: number; note: string }[];
  questions: { q: string; a: string }[];
  generated: string;
}

const band = (ale: number): { low: number; high: number } => ({ low: Math.round(ale * 0.5), high: Math.round(ale * 2) });

function effOf(r: { hasPlan: boolean; treatment: string }): number {
  const t = String(r.treatment || "").toLowerCase();
  if (/accept|avoid|transfer/.test(t)) return EFFECTIVENESS.treated;
  if (r.hasPlan || /mitigat|treat|reduce/.test(t)) return EFFECTIVENESS.planned;
  return EFFECTIVENESS.untreated;
}

export function crqDecisionSupport(tenant: number | null): CrqResult {
  const inv = riskRegisterInventory(tenant);
  const rows = inv.rows as unknown as { id: number; ref: string; title: string; residual: string; ale: number | null; treatment: string; hasPlan: boolean; overAppetite: boolean; open: boolean; currency: string }[];
  const currency = String((inv.summary as Record<string, unknown>).currency || "EUR");
  const quantified = rows.filter((r) => r.ale != null && r.ale > 0 && r.open);

  const toAction = (r: typeof rows[number]): CrqAction => {
    const ale = Number(r.ale || 0); const b = band(ale); const eff = effOf(r);
    const reasons: string[] = [];
    if (r.overAppetite) reasons.push("above risk appetite");
    if (!r.hasPlan && !/accept/i.test(r.treatment)) reasons.push("untreated");
    if (/critical|very high|high/i.test(r.residual)) reasons.push(`${r.residual} residual`);
    return {
      id: r.id, ref: r.ref, title: r.title, level: r.residual, ale, aleLow: b.low, aleHigh: b.high,
      treatment: r.treatment, hasPlan: r.hasPlan, overAppetite: r.overAppetite,
      expectedReduction: Math.round(ale * eff), effectiveness: eff,
      reason: reasons.join(" · ") || "quantified exposure",
    };
  };

  // Q1 — remediate first: highest annualized loss (weight over-appetite + untreated).
  const remediateFirst = [...quantified].map(toAction)
    .sort((a, b) => (b.ale - a.ale) || (Number(b.overAppetite) - Number(a.overAppetite))).slice(0, 25);

  // Q2 — investments that maximize risk reduction: rank by expected ALE removed.
  const investments = [...quantified].map(toAction)
    .filter((a) => a.expectedReduction > 0)
    .sort((a, b) => b.expectedReduction - a.expectedReduction).slice(0, 25);

  // Q3 — risk appetite.
  const overItems = quantified.filter((r) => r.overAppetite).map(toAction).sort((a, b) => b.ale - a.ale);
  const overALE = overItems.reduce((s, a) => s + a.ale, 0);

  const totalALE = Math.round(quantified.reduce((s, r) => s + Number(r.ale || 0), 0));
  const pb = band(totalALE);
  const untreated = quantified.filter((r) => !r.hasPlan && !/accept/i.test(r.treatment)).length;

  // Scenario comparison: current vs treat-over-appetite vs treat-all (operational decision support).
  const reduceOver = overItems.reduce((s, a) => s + a.expectedReduction, 0);
  const reduceAll = quantified.map(toAction).reduce((s, a) => s + a.expectedReduction, 0);
  const scenarios = [
    { name: "Current exposure", ale: totalALE, reductionPct: 0, note: "Today's annualized loss expectancy across open quantified risks." },
    { name: "Treat all over-appetite risks", ale: Math.max(0, totalALE - reduceOver), reductionPct: totalALE ? Math.round((reduceOver / totalALE) * 100) : 0, note: `Bring the ${overItems.length} risk(s) above appetite under control.` },
    { name: "Treat the full register", ale: Math.max(0, totalALE - reduceAll), reductionPct: totalALE ? Math.round((reduceAll / totalALE) * 100) : 0, note: "Upper bound of achievable annualized risk reduction at assumed control effectiveness." },
  ];

  const money = (n: number): string => `${currency} ${n.toLocaleString("en-US")}`;
  const questions = [
    { q: "Which exposures should we remediate first?", a: remediateFirst.length ? `Top exposure: ${remediateFirst[0].ref || "#" + remediateFirst[0].id} "${remediateFirst[0].title}" at ${money(remediateFirst[0].ale)}/yr. The top 5 represent ${money(remediateFirst.slice(0, 5).reduce((s, a) => s + a.ale, 0))}/yr of the ${money(totalALE)} portfolio.` : "No quantified open risks — quantify risks with FAIR-MAM/TEF to populate this view." },
    { q: "Which investments maximize risk reduction?", a: investments.length ? `Treating "${investments[0].title}" is expected to remove ~${money(investments[0].expectedReduction)}/yr (the largest single reduction). Prioritise treatments by expected annualized loss removed; add a cost per treatment to compute ROSI.` : "No treatable quantified risks." },
    { q: "Which risks are outside our risk appetite?", a: `${overItems.length} risk(s) are above appetite, carrying ${money(Math.round(overALE))}/yr of annualized loss — these are the board-level decisions.` },
    { q: "How should we optimize limited resources?", a: `Treating the over-appetite set first cuts ~${scenarios[1].reductionPct}% of portfolio ALE; treating the full register caps at ~${scenarios[2].reductionPct}%. Sequence spend against the expected-reduction ranking.` },
  ];

  return {
    currency,
    portfolio: { totalALE, aleLow: pb.low, aleHigh: pb.high, quantifiedRisks: quantified.length, openRisks: rows.filter((r) => r.open).length, overAppetite: overItems.length, untreated, aboveAppetiteALE: Math.round(overALE) },
    remediateFirst, investments,
    appetite: { overCount: overItems.length, withinCount: quantified.length - overItems.length, overALE: Math.round(overALE), items: overItems.slice(0, 25) },
    scenarios, questions, generated: new Date().toISOString(),
  };
}
