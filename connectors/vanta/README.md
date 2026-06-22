# Vanta

`vanta` · **import** connector · category **GRC**

Vanta — security & compliance automation (SOC 2, ISO 27001, HIPAA…). Imports Vanta policies + collected evidence/documents into the XORCISM controlled-document register (XCOMPLIANCE.DOCUMENT). Offline: a JSON export ({documents:[…]} or {policies:[…],evidence:[…]}). Live: set VANTA_API_TOKEN (Bearer) and optionally VANTA_API_BASE (default https://api.vanta.com). Tool: https://www.vanta.com.

**Upstream:** https://api.vanta.com

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of Vanta policies/evidence/documents. |
| `base` | string | no | — | Vanta API base URL (default https://api.vanta.com). Live mode needs VANTA_API_TOKEN in the worker env. |
| `max_items` | int | no | `2000` | Maximum documents to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Vanta*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:vanta`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
