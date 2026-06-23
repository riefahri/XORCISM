# n8n

`n8n` · **import** connector · category **Automation**

Drives n8n (fair-code workflow automation, the open-source SOAR/glue) from XORCISM. Live mode POSTs a context payload (target / IOC / incident) to an n8n workflow's webhook (N8N_WEBHOOK_URL or the `webhook` param; optional N8N_API_KEY header) and ingests the JSON the workflow returns; offline mode parses a saved n8n execution-result JSON. Any indicators the workflow returns are imported as CTI (XTHREAT.INTELEXCHANGE); any findings are imported as ASSET/VULNERABILITY. Reuses the JoasASantos/n8n-CyberSecurity-Workflows catalogue (IOC enrichment, phishing triage, alert routing, vuln prioritization, recon…) — see the Purple/Blue/Red Team Operations automation-playbook templates. Worker-safe: stdlib only, secrets via env.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `webhook` | url | no | — | n8n workflow webhook URL to trigger (falls back to the N8N_WEBHOOK_URL worker env var). |
| `workflow` | string | no | — | Workflow name/id to invoke (passed in the payload; informational). |
| `context` | string | no | — | Context to pass to the workflow (e.g. an IOC, URL, host or incident id). |
| `file` | file | no | — | Offline mode: path to a saved n8n execution-result JSON to import (instead of triggering a webhook). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *n8n*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:n8n`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
