# Artemis

`artemis` · **import** connector · category **Web Scanner** · ⚠️ **intrusive** (engagement scope enforced)

Imports web vulnerability findings from Artemis (CERT Polska, https://github.com/CERT-Polska/Artemis), a modular scanner that checks websites for misconfigurations and known vulnerabilities (exposed .git/VCS, outdated CMS like Joomla/WordPress, directory listing, subdomain takeover, vulnerable services, Nuclei templates, weak passwords…). Each scanned target host/URL becomes an ASSET; each interesting finding (module + message, CVE if referenced) becomes a VULNERABILITY with a mapped severity. Offline mode: parse an Artemis results/report JSON export. Live mode: with `target` (+ `api_base`), submit a scan to the Artemis API and import the results. Active/intrusive web scanning. No DB access in run.py (worker-safe).

**Upstream:** https://github.com/CERT-Polska/Artemis

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to an Artemis results/report JSON export to import (offline mode). |
| `target` | target | no | — | Live mode: host or URL for Artemis to scan (must be in the engagement scope). |
| `api_base` | url | no | `http://localhost:5000` | Live mode: base URL of the Artemis web API (default http://localhost:5000). |
| `api_key` | string | no | — | Live mode: API token for the Artemis backend (env ARTEMIS_API_TOKEN also honored). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Artemis*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:artemis`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
