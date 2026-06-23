# Zabbix — Infrastructure Monitoring

`zabbix` · **import** connector · category **Monitoring**

Imports the monitored estate and active problems from Zabbix (open-source infrastructure monitoring for networks, servers, cloud and applications) into XORCISM Asset Monitoring. Each Zabbix host becomes an ASSET (network discovery) plus a MONITORINGCHECK (server monitor, status up/down/paused from host availability); each active problem becomes a MONITORINGINCIDENT (severity-mapped). Config (worker environment variables): ZABBIX_URL (the Zabbix front-end base, e.g. https://zabbix.local), ZABBIX_TOKEN (an API token) or ZABBIX_USER + ZABBIX_PASSWORD. Offline: pass `file` = a Zabbix export JSON ({hosts, problems} or a raw host.get response), or run with no config for the bundled sample.

**Upstream:** https://zabbix.local

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | no | — | Zabbix front-end base URL (overrides ZABBIX_URL); the connector appends /api_jsonrpc.php. |
| `file` | file | no | — | Offline JSON export ({hosts, problems}, a raw host.get {result:[...]} response, or a flat host list). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Zabbix — Infrastructure Monitoring*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:zabbix`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/zabbix/sample.json --connector zabbix
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
