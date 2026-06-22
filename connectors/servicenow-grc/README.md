# ServiceNow GRC

`servicenow-grc` · **import** connector · category **GRC**

ServiceNow GRC / IRM — policies, controls and documents from the Now Platform. Imports GRC policy + document records into the XORCISM controlled-document register (XCOMPLIANCE.DOCUMENT) via the Table API. Offline: a JSON export. Live: set SERVICENOW_INSTANCE (e.g. acme = acme.service-now.com) + SERVICENOW_USER + SERVICENOW_PASSWORD (Basic auth). Tool: https://www.servicenow.com.

**Upstream:** https://www.servicenow.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of ServiceNow GRC records. |
| `base` | string | no | — | Instance base URL (https://<inst>.service-now.com). Overrides SERVICENOW_INSTANCE. Live needs SERVICENOW_USER + SERVICENOW_PASSWORD. |
| `tables` | string | no | — | Comma-separated GRC tables to pull (default sn_grc_policy,sn_grc_document). |
| `max_items` | int | no | `2000` | Maximum records per table. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *ServiceNow GRC*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:servicenow-grc`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
