# Adversary Opportunity Index (AOI)

> XORCISM's rename and implementation of the "threat debt" idea
> (cf. AttackIQ, *"Threat Debt: the unit of measure adversaries already use against you"*, Jun 2026).
> AOI is **not** a re-brand of that vendor's `Threat Debt Index™` — it is our own composition over
> engines XORCISM already ships. The accounting vocabulary (STOCK / FLOW, accrued / paid-down) is
> generic and kept; the trademarked branding and diagrams are not used.

## 1. What it is

A single, **derived** top-line for the *true adversary opportunity* in an environment: every gap that
sits on a **viable attack path** to a crown jewel, weighted by exploitability, by the adversaries that
actually use those techniques, by business impact, and **net of the controls you can prove**.

AOI is the **attacker's-eye sibling** of the EnterpriseRiskScore (ERS):

| | EnterpriseRiskScore | Adversary Opportunity Index |
|---|---|---|
| Question | "What is the state of my balance sheet?" | "What can an attacker actually cash in right now?" |
| Organizing principle | asset / register / incident / compliance rollups | **reachable entry→crown-jewel paths** |
| Lens | defender | attacker |

Defining AOI on **paths** (not asset rollups) is the deliberate differentiator that stops it from
merely tracking ERS — the trap called out in the design review.

## 2. The model (Phase 1, implemented)

The "Attack Path Test" is a **hard gate** applied before any weighting — it is what separates signal
from a vulnerability backlog:

```
a debt item counts  ⟺
  Q1  it lies ON a reachable entry→crown-jewel path        (attackpath.ts)
  Q2  adversaries actually use the technique it enables     (tid.ts, threat-weighted)
  Q3  controls fail to stop it (residual after proven ctl)  (tid.ts ∩ assurance.ts)
```

```
rawDebt        = Σ_paths [ (Σ on-path node exposure / 100) × jewelWeight(path) × 100 ]
defenceResidual= clamp( (100 − tidScore)/100 − 0.15·assuranceCredit , 0.05 , 1 )   // Q2 ∩ Q3, credited
AOI (STOCK)    = round( 1000 × (1 − e^(−rawDebt / SCALE)) × defenceResidual )       // bounded, monotonic
FLOW           = AOI(today) − AOI(previous snapshot)
```

- `node exposure` (0..100) = fusion exploitability (EPSS · KEV · public-exploit) — already computed by
  `attackPathGraph`.
- `jewelWeight` ∈ [0.2 .. 1] = the crown jewel's BusinessValue normalized across jewels.
- `tidScore` (0..100) = threat-weighted defence coverage (detection/mitigation/test pillars over the
  techniques adversaries use). `assuranceCredit` = fraction of controls **proven from telemetry**.
- `SCALE` = 2000 (tunable via `XOR_AOI_SCALE`). The saturating curve keeps AOI in [0,1000], monotonic
  in exposure, and *moves only when real exposure changes*.

**Double-count guard.** `tidScore` already credits detection/mitigation. The assurance term is therefore
only a *small* extra credit (weight 0.15, capped by the 0.05 residual floor) so a genuinely
well-defended estate is not double-discounted into nonsense — while still honouring "credit the controls
you already have."

**Graceful fallback.** With no attack-path data (no subnet adjacency / BIA edges / crown jewels),
`pathData=false` and `rawDebt` falls back to the fusion-weighted exposure worklist (`topExposures`,
same units), flagged in the payload.

### Price the fix (choke-point ROI)

Hardening a **choke point** retires every path through it. For each choke point the worklist reports the
estimated paydown `ΔAOI = AOI(now) − AOI(rawDebt × (1 − chokePaths/totalPaths))`, ranked highest-ROI
first — "price the fix before you make it."

## 3. The seven sources of threat debt → existing XORCISM modules

AOI re-instruments **nothing**; it composes live modules. Phase-1 "live" sources are scored into the
index today; "tracked" sources are surfaced as counts and fold into the index in Phase 2.

| Source | Status | XORCISM origin |
|---|---|---|
| Vulnerabilities | live | `ASSETVULNERABILITY` + `fusion.ts` (EPSS/KEV/exploit) via attack-path node exposure |
| Misconfigurations | tracked | `XOVAL` OVAL/CIS fails (`configuration.ts`, DevSecOps IaC) |
| Control weaknesses | live | `assurance.ts` (proven-vs-compliant) |
| Identity & access debt | tracked | `IDENTITY` risk (`identities.ts`/`identitygov.ts`/`itdr.ts`) |
| Detection & response debt | live | `tid.ts` exposed techniques (+ `purpleteam.ts` missing Sigma) |
| Network & segmentation debt | live | east-west adjacencies on paths (`attackpath.ts`, `zerotrust.ts`) |
| AI & automation debt | tracked | `AISYSTEM` ungoverned / MCP servers (`aisystems.ts`/`aibas.ts`) |

## 4. Surfaces

- **Module** `server/threatdebt.ts` — `adversaryOpportunityIndex(tenant, graph?)`,
  `recordThreatDebtSnapshot`, `threatDebtHistory`, `ensureThreatDebtTables`.
- **Route** `server/routes/threatdebt.ts` — `GET /api/threat-debt` (records today's snapshot so history
  accrues on view), `POST /api/threat-debt/snapshot`. RBAC: read/update `XORCISM.ASSET`.
- **Page** `/adversary-opportunity` — index gauge + STOCK/FLOW + sparkline, the 7 sources, the
  price-the-fix worklist, the top debt-carrying paths. Landing card (EN/FR).
- **Board report** — `boardReport()` gains `adversaryOpportunity { index, net, defenceResidual, topFix }`
  (reuses the attack-path graph it already builds — no double computation).
- **Table** `THREATDEBTSNAPSHOT (SnapshotID, TenantID, CreatedDate, AOI, RawDebt, Paths)` — STOCK history,
  upsert per tenant per day, mirroring `ORGANISATIONRISKSCORE`.

## 4b. Reach (enterprise visibility + agent/API access)

- **Dashboard KPI tile** — `/api/dashboard/kpis` carries `adversaryOpportunity` (`threatDebtLatest`:
  latest snapshot index + net vs the prior, a cheap read — no recompute on dashboard load). The
  dashboard strip renders it next to *Enterprise risk* (the attacker's-eye sibling, board-visible).
- **Public REST** — `GET /api/v1/adversary-opportunity` (scope `exposure:read`): index, STOCK/FLOW
  (net + paid-down/accrued + open items), per-source counts, and the top paydown.
- **MCP tool** — `adversary_opportunity` in `mcp/xorcism-mcp.mjs` (13th tool) → the v1 endpoint, so
  Claude Desktop / Cursor can ask "what's our adversary opportunity?" with scopes enforced server-side.
- **Per-source price-the-fix** — `ledgerBySource` ranks the open ledger debt retirable per source
  (pre-remediation modeling beyond choke points); surfaced as `sourceFixes` on the page + v1.
- **MSSP rollup** — `/mssp` carries an AOI column per tenant (`threatDebtLatest`) + an `avgAoi` summary,
  so a super-admin compares adversary opportunity across clients (cheap snapshot read).
- **ChatOps** — the `aoi` command (`chatops.ts`) returns the index + net/paid/accrued + the top paydown
  in Slack mrkdwn, so you can ask "what's our adversary opportunity?" from Slack/Teams.

## 5. Roadmap

- **Phase 1 (done, verified):** vuln + control-weakness + detection + network sources through the Attack
  Path Test → scalar AOI (STOCK) + net FLOW, snapshot history, page, board line, choke-point worklist.
- **Phase 2 (done, verified):** `THREATDEBTLEDGER` item-level open/closed ledger across all asset
  (vuln/network, Attack-Path-Test-gated) and posture (control/identity/AI/misconfig) sources →
  **exact** paid-down vs accrued FLOW (the post's "60 paid down, 46 accrued"), computed as a set-diff
  between reconciliations. `collectDebtItems` builds the canonical item set; `reconcileLedger` commits
  open/touch/close on each snapshot; `ledgerFlow` reports period accrued/paid + open balance.
  `seedThreatDebtDemo(tenant)` back-dates ~30 days of an improving trend for the demo.
- **Phase 3 (done, verified):** `recordThreatDebtSnapshot` emits `threatdebt.accrued`
  (severity scaled by this-reconcile's opened debt: ≥150 critical, ≥60 high, else medium) and
  `threatdebt.paid_down` (info) — **only on real ledger churn** (idempotent). The CROC orchestrator
  (`propose()`) routes `threatdebt.*` to a new **`threatdebt-paydown`** copilot carrying the specific
  recommendation (top choke point or highest-debt source), queued as a CROCACTION for human approval;
  approving runs the generic `executeApprovedAction` (SOAR + `croc.action_executed` "loop closed").
  The recommendation comes from `paydownReco(aoi)` (the post's "Agentic OS," reusing what CROC does).
  **Pay down through CTEM:** an approved `threatdebt.*` paydown calls `mobilizeToCtem` →
  `ctem.createExposure` (classified `CTEM-EXP-3`, entered at the **Prioritize** stage, Source
  "AOI paydown"), so the paydown flows through the CTEM lifecycle and shows in `/ctem`
  ("…tracked in CTEM (exposure #N); loop closed").
- **Per-item price the fix (done):** `topLedgerItems` ranks the highest-debt open ledger items (the
  finest-grain "price the fix", complementing choke-point ΔAOI and per-source `ledgerBySource`),
  surfaced as `topItems` on the page.
- **Reverse CTEM re-credit (done):** the forward `mobilizeToCtem` stamps the targeted ledger items
  with the new `THREATDEBTLEDGER.CtemExposureID` link (keys from `topOpenItemKeys`). When that exposure
  reaches the Remediate stage, `ctemCreditedKeys` returns its linked keys and `reconcileLedger` drops
  them from the live set — so they **close (paid down) and are suppressed from re-opening** even if a
  stale scan still reports the finding ("credit the controls you can prove via CTEM validation"). The
  CTEM↔AOI loop is now bidirectional. *Honest scope:* only items explicitly linked by a forward paydown
  are credited (no blind matching).

## 6. Pitfalls handled

- **Double-counting ERS** → AOI is path-defined, not a re-sum of asset rollups.
- **Control double-discount** → assurance is a small capped extra credit on top of `tidScore`.
- **Validated, not just compliant** → control credit derives from telemetry/BAS-proven controls.
- **Normalization / stability** → bounded saturating curve; deterministic (same inputs → same number).
- **Performance** → `attackPathGraph` is capped (≤2000 assets, ≤60-node subnets); snapshots are computed
  on read/schedule, not per-widget.

## 7. Verification (Phase 1)

Run against a **copy** of the production databases (`DB_DIR` override; production never written), under
the portable Node 20 (better-sqlite3 ABI):

- Server `tsc` build clean; client esbuild clean; module loads against the real schema.
- All live sources populate (demo: vulns 12, control-weakness 2, detection 6); snapshot **idempotent per
  day**; **FLOW** correct (injected prior 42 → today 5 → net −37); history accrues.
- Curve calibration (SCALE=2000): rawDebt 500 / 1500 / 4000 / 9000 → AOI 155 / 317 / 519 / 890 —
  monotonic, residual-scaled, bounded — the post's "612"-style band for estates that carry path debt.
- The demo tenant scores AOI ≈ 5 — the **correct** result for a well-defended, low-exposure estate
  (no viable paths, TID 89/100, 71% proven controls): the score really does move only with real exposure.
- **Phase 2 ledger:** `seedThreatDebtDemo(3)` back-dates 31 snapshots declining 208 → 27. After a
  reconcile, an injected stale item closes correctly and the two live control-weakness items open →
  `flow = { net −22, paidDown 99, accrued 53, openItems 2 }`; a second same-day reconcile is idempotent
  (no churn). Exactly the post's "down N — X paid down, Y accrued" shape.
- **Phase 3 agentic loop:** churn emits `threatdebt.accrued` (idempotent on re-run); the medium accrual
  is correctly *not* escalated; a high accrual → orchestrator proposes a `threatdebt-paydown` action
  (conf 75); approve → execute → outcome "loop closed" + a `croc.action_executed` event. Full
  propose→approve→execute verified.
```
python/node verification harness lives outside the tree; re-run after any scoring change.
```
