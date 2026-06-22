# EU Vulnerability Database (EUVD)

`euvd` · **import** connector · category **Threat Intelligence**

Imports vulnerabilities from the ENISA EU Vulnerability Database (EUVD, https://euvd.enisa.europa.eu) — the official EU repository established under NIS2. Each EUVD entry has its own id (EUVD-YYYY-NNNNN) and usually aliases one or more CVE ids; it is upserted into XVULNERABILITY.VULNERABILITY keyed on the CVE (or the EUVD id when CVE-less): existing CVEs are enriched in place with their EUVDId / EUVDUrl (and CVSS/EPSS/description filled when missing), and EUVD-only entries are added as new vulnerabilities. Live mode queries the public EUVD API (recent / critical / exploited / search, or a specific CVE / EUVD id); offline mode parses a saved EUVD JSON export. No authentication required; no DB access in run.py (worker-safe).

**Upstream:** https://euvd.enisa.europa.eu

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to an EUVD JSON export to import (offline mode). |
| `mode` | enum | no | `recent` | Live feed: latest vulnerabilities, critical only, known-exploited, or a filtered search. (one of: `recent`, `critical`, `exploited`, `search`) |
| `cve` | string | no | — | Fetch a single CVE's EUVD entry (e.g. CVE-2024-3400). |
| `id` | string | no | — | Fetch a single EUVD entry by its id (e.g. EUVD-2024-45012). |
| `query` | string | no | — | mode=search: free-text query. |
| `vendor` | string | no | — | mode=search: filter by vendor name. |
| `product` | string | no | — | mode=search: filter by product name. |
| `max` | int | no | `100` | Maximum entries to import (paginated for search). (range 1–2000) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *EU Vulnerability Database (EUVD)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:euvd`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
