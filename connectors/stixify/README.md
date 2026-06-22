# Stixify

`stixify` · **import** connector · category **CTI**

Stixify (dogesec) — extracts STIX 2.1 intelligence from threat reports/PDFs. Imports Stixify reports (and the ATT&CK techniques referenced in their extracted objects) into XORCISM threat intelligence (XTHREAT.INTELEXCHANGE). Offline: a JSON export of reports / a STIX bundle. Live: set STIXIFY_API_KEY (API-KEY header) and optionally STIXIFY_BASE (default https://api.stixify.com). API: https://api.stixify.com/schema/swagger-ui/.

**Upstream:** https://api.stixify.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of Stixify reports or a STIX bundle ({objects:[…]}). |
| `base` | string | no | — | Stixify API base (default https://api.stixify.com). Live mode needs STIXIFY_API_KEY in the worker env. |
| `max_items` | int | no | `200` | Maximum reports to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Stixify*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:stixify`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
