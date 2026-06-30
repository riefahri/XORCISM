# VALENCE GRC connector

[VALENCE](https://github.com/hiro001-eth/VALENCE-GRC-Platform) (MIT) is an **audit-grade GRC platform**
that turns SIEM telemetry into **quantitative risk**: it runs **FAIR Monte Carlo** simulations
(Threat Event Frequency ~ Poisson × Loss Event Magnitude ~ Log-Normal, 1000 iterations) to produce
**Annual Loss Expectancy (ALE)** and **Value-at-Risk (VaR 95%)** in dollars, monitors controls
continuously with a **RAG status**, keeps a **SHA-256 hash-chained tamper-evident evidence chain**, and
maps controls across **SOC 2 / ISO 27001 / NIST CSF / PCI DSS / DORA / CMMC**. Python/FastAPI, MIT.

This `import` connector pulls a VALENCE run export into XORCISM's compliance store.

## What it imports

VALENCE's per-control evaluations → an XORCISM **Compliance AUDIT** (`XCOMPLIANCE`) via the runner's
`compliance` path — one `AUDITFINDING` per failed / at-risk control, the financial risk carried inline:

| VALENCE control evaluation | XORCISM |
|---|---|
| control id / name | finding `rule_id` / `title` |
| RAG status (green / amber / red) | `result` (green → pass, amber/red → fail) + `severity` (Low/Med/High) |
| framework refs (SOC2 / ISO / NIST CSF / PCI…) | finding `references` |
| value · threshold · **ALE** · **VaR 95%** | finding `discussion` (carried so the $ risk is visible) |
| any `CVE-…` referenced | appended to `references` |

`benchmark` is **VALENCE**, `host` is the organisation. Passing (green) controls are counted in the audit
summary, not stored as findings. Feeds **/compliance-management**, **/compliance** and the FAIR/CRQ stack.

## Configuration

Worker-safe: it only reads an exported file or a **read-only** API — no DB access, no offensive action.

| Source | How |
|---|---|
| `file` parameter | A VALENCE export JSON — `{metrics\|controls\|results:[…]}` (each: id, name, framework(s), rag_status, value, threshold, ale, var_95), or a bare array. |
| `VALENCE_URL` env (worker) | Base URL of a running VALENCE instance; a base URL gets `/api/metrics` appended (read-only GET). |
| `VALENCE_TOKEN` env | Optional bearer token for that API. |
| `org` parameter | Organisation label recorded as the audit host (default: from the export, else `VALENCE`). |
| `min_rag` parameter | `green` \| `amber` \| `red` — minimum RAG that becomes a finding (default `amber`: amber+red controls are findings; green passes). |

Field names vary between VALENCE versions, so extraction is defensive (rag_status/status/state, ale/average_exposure, var_95/value_at_risk, framework/frameworks/mappings…).

## Offline dry run

```bash
python connectors/valence/run.py                          # built-in sample (Acme Corp, 3 controls)
python connectors/valence/run.py --file run.json --min-rag red
```

Imported controls surface in **/compliance-management** and **/compliance** as a VALENCE audit.

> Related XORCISM capability added alongside this connector (inspired by VALENCE's cryptographic evidence
> chain): the audit log (`XAUDITLOG`) is now a **tamper-evident SHA-256 hash chain** — verify it at
> `GET /api/admin/audit/verify` (super-admin). XORCISM already covers VALENCE's FAIR Monte Carlo / ALE /
> loss-exceedance (FAIR-TEF), loss magnitude (FAIR-MAM), CRQ, the risk register and SIEM/SOAR ingestion.
