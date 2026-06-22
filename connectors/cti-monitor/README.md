# CTI Monitor

`cti-monitor` · **import** connector · category **CTI**

CTI Monitor (0xw01f) — self-hosted threat-intelligence workspace that collects, enriches and risk-scores CTI from open sources (RSS, paste sites…) with AI classification and actor reputation. Imports its threat-intelligence records into XORCISM (XTHREAT.INTELEXCHANGE). Offline: a JSON export. Live: set CTI_MONITOR_URL (e.g. http://localhost:8000) + optional CTI_MONITOR_TOKEN. Tool: https://github.com/0xw01f/CTI-Monitor (license CC BY-NC 4.0 — non-commercial).

**Upstream:** https://github.com/0xw01f/CTI-Monitor

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of CTI Monitor threat records ({threats:[…]} or a flat list). |
| `base` | string | no | — | CTI Monitor base URL (e.g. http://localhost:8000). Overrides CTI_MONITOR_URL. |
| `path` | string | no | — | API path to pull (default /api/threats). |
| `max_items` | int | no | `1000` | Maximum records to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *CTI Monitor*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:cti-monitor`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
