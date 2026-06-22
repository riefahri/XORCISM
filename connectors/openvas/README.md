# OpenVAS / Greenbone

`openvas` · **import** connector · category **Vulnerability Scanner** · ⚠️ **intrusive** (engagement scope enforced)

OpenVAS / Greenbone Vulnerability Management (GVM). Offline mode parses a GMP XML report export (<report><results><result>…): each scanned host becomes an ASSET and each result becomes a VULNERABILITY (CVE refs, else NVT:<oid>; severity from the threat/CVSS). Live mode drives gvmd over GMP (python-gvm) — creates a target, runs a 'Full and fast' scan task, waits for completion, fetches the report and imports it; connection + credentials via worker env GVM_HOST/GVM_PORT (or GVM_SOCKET) + GVM_USER/GVM_PASSWORD. Active network vulnerability scanning (intrusive) in live mode. No DB access in run.py (worker-safe).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a Greenbone GMP XML report to import (offline mode). |
| `target` | target | no | — | Live mode: host or IP/CIDR for gvmd to scan (must be in the engagement scope). |
| `min_cvss` | string | no | `0.1` | Minimum CVSS severity to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *OpenVAS / Greenbone*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:openvas`.
- **Self-test** — parse **and import** the bundled `sample.xml` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/openvas/sample.xml --connector openvas
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
