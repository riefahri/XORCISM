# AuditBoard

`auditboard` · **import** connector · category **GRC**

AuditBoard — connected risk, audit & compliance platform. Imports AuditBoard policies + evidence/documents into the XORCISM controlled-document register (XCOMPLIANCE.DOCUMENT). Offline: a JSON export. Live: set AUDITBOARD_BASE (https://<tenant>.auditboardapp.com) + AUDITBOARD_API_TOKEN (Bearer). Tool: https://www.auditboard.com.

**Upstream:** https://<tenant

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export of AuditBoard policies/evidence. |
| `base` | string | no | — | AuditBoard tenant base URL (https://<tenant>.auditboardapp.com). Overrides AUDITBOARD_BASE. Live needs AUDITBOARD_API_TOKEN. |
| `max_items` | int | no | `2000` | Maximum documents to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *AuditBoard*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:auditboard`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
