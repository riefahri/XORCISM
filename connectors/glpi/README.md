# GLPI — IT Asset Management (CMDB)

`glpi` · **import** connector · category **IT Asset Management**

Imports the IT inventory from GLPI (open-source IT Service Management & asset-management suite / CMDB) into XORCISM. Each Computer, NetworkEquipment, Phone, Printer or Peripheral becomes an ASSET (network discovery), carrying its operating system and IP when available, so the authoritative IT estate shows up alongside the rest of the attack surface (CVE matching, monitoring, BIA, ...). Config (worker environment variables): GLPI_URL (the GLPI base, e.g. https://glpi.local), GLPI_APP_TOKEN (API client app-token) and GLPI_USER_TOKEN (a personal API token; initSession -> Session-Token). Offline: pass `file` = a GLPI export JSON ({Computer, NetworkEquipment, ...}, a GLPI API list response, or a flat item list), or run with no config for the bundled sample.

**Upstream:** https://glpi.local

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | no | — | GLPI base URL (overrides GLPI_URL); the connector appends /apirest.php. |
| `file` | file | no | — | Offline JSON export ({Computer:[...], NetworkEquipment:[...]}, a GLPI {data:[...]} page, or a flat item list). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *GLPI — IT Asset Management (CMDB)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:glpi`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/glpi/sample.json --connector glpi
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
