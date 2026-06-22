# Drata

`drata` · **import** connector · category **GRC**

Drata — continuous security & compliance automation (SOC 2, ISO 27001, GDPR…). Imports Drata policies + evidence/documents into the XORCISM controlled-document register (XCOMPLIANCE.DOCUMENT). Offline: a JSON export. Live: set DRATA_API_KEY (Bearer) and optionally DRATA_API_BASE (default https://public-api.drata.com). Tool: https://drata.com.

**Upstream:** https://public-api.drata.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of Drata policies/evidence. |
| `base` | string | no | — | Drata API base URL (default https://public-api.drata.com). Live mode needs DRATA_API_KEY in the worker env. |
| `max_items` | int | no | `2000` | Maximum documents to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Drata*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:drata`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/drata/sample.json --connector drata
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
