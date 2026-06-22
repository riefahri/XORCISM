# Jira

`jira` · **import** connector · category **Ticketing**

Imports security issues from Atlassian Jira (Cloud or Server/Data Center) into XORCISM as findings. Each Jira issue becomes a VULNERABILITY (CVE referenced in summary/description if present, else JIRA-<key>; severity mapped from the issue priority); the affected asset is resolved from the issue's component, an asset-like label, or the `asset`/`project` fallback. Live mode queries the Jira REST API (`/rest/api/3/search` with JQL, paginated); offline mode parses a saved Jira search-results JSON. Secrets via worker env only: JIRA_URL (base), JIRA_USER (email, Cloud) + JIRA_TOKEN (API token / PAT). No DB access in run.py (worker-safe).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Jira search-results JSON export to import (offline mode). |
| `project` | string | no | — | Live mode: Jira project key to import (builds JQL `project = KEY AND statusCategory != Done`). |
| `jql` | string | no | — | Live mode: explicit JQL overriding `project` (e.g. `labels in (security, vulnerability) AND statusCategory != Done`). |
| `max` | int | no | `200` | Live mode: maximum issues to import (paginated). (range 1–5000) |
| `asset` | string | no | — | Fallback asset name when an issue has no component/asset label (default: the project key). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Jira*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:jira`.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
