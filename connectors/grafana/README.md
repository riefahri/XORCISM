# Grafana

`grafana` · **import** connector · category **Monitoring**

Grafana — observability & alerting. Imports Grafana datasource health + alert rules as XORCISM Asset Monitoring monitors (MONITORINGCHECK) and firing alerts as incidents (MONITORINGINCIDENT). Offline: a JSON export ({monitors,monitoring_incidents} or Grafana-native {datasources,alert_rules,alerts}). Live: set GRAFANA_URL + GRAFANA_TOKEN (service-account / API key, Bearer). Tool: https://github.com/grafana/grafana.

**Upstream:** https://github.com/grafana/grafana

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Offline JSON export (normalized monitors/incidents, or Grafana datasources/alert-rules/alerts). |
| `base` | string | no | — | Grafana base URL (https://grafana.example.com). Overrides GRAFANA_URL. Live needs GRAFANA_TOKEN. |
| `max_items` | int | no | `2000` | Maximum monitors to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *Grafana*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:grafana`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/grafana/sample.json --connector grafana
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
