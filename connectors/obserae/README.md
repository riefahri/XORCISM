# Obserae connector — NetFlow/IPFIX → network discovery, services & sessions

[Obserae](https://github.com/spartan-conseil/obserae) (by **Spartan Conseil**) is a self-hosted
**NetFlow v5/v9 & IPFIX collector** that reconstructs network sessions, builds a *cartography* of
hosts and services, and lets you investigate by logical name rather than raw IP. It runs as a Docker
container or a Linux binary (amd64/arm64, incl. Raspberry Pi) on top of DuckDB, with a web GUI
(Cockpit / Cartography / Sessions / Queries) and a CLI.

This connector turns an Obserae **cartography + sessions export** into network-observability data
**around ASSET** in XORCISM — for discovery, monitoring and SOC investigation:

| Obserae           | XORCISM                                                                 |
|-------------------|------------------------------------------------------------------------|
| host / cartography| **ASSET** (created or updated — network discovery)                     |
| listening service | **ASSETSERVICE** (the ASSET↔SERVICE relationship: protocol / port / service) |
| reconstructed flow| **NETWORKSESSION** (protocol, source↔destination assets/IPs/ports, bytes/packets, first/last seen, state) |

The result is visible at **`/network-sessions`** (top services/ports, top talkers, the session list,
newly-discovered assets) and links straight into Asset Management.

## Usage

This is an **import** connector (worker-safe — no DB, no network access; PyYAML preferred, JSON
accepted as a fallback). Export your cartography + sessions from Obserae (or build the YAML below),
then run the connector with the file path.

```
# from XORCISM → Connectors → Obserae, set:
file = /path/on/worker/obserae-export.yaml
```

A sample is provided in [`sample.yaml`](sample.yaml). To preview the normalized output:

```
python run.py sample.yaml
```

## Expected YAML schema

All three sections are optional; provide what you have. Sessions reference assets by **IP or name**
(unknown endpoints are auto-discovered as new assets).

```yaml
assets:                       # cartography (network discovery)
  - name: web-prod-01         # logical name (falls back to hostname / ip)
    ip: 10.0.0.21
    hostname: web-prod-01.corp
    os: Linux
    zone: DMZ
    tags: [server, internet-facing]

services:                     # listening services  →  ASSET ↔ SERVICE
  - asset: 10.0.0.21          # ip or name
    protocol: tcp
    port: 443
    service: https
    banner: nginx/1.25
    first_seen: 2026-06-22T08:00:00Z
    last_seen:  2026-06-22T09:00:00Z
    flows: 128

sessions:                     # reconstructed flows  →  NETWORKSESSION
  - src: 203.0.113.5          # source (ip or name)
    dst: 10.0.0.21            # destination (ip or name)
    protocol: tcp
    src_port: 51514
    dst_port: 443
    service: https
    bytes: 184320
    packets: 220
    flows: 3
    state: established        # tcp state, optional
    direction: inbound        # optional
    first_seen: 2026-06-22T08:00:00Z
    last_seen:  2026-06-22T08:05:00Z
```

### Field aliases accepted

So an export from a different stage of the Obserae pipeline still imports:

- assets: `hosts`, `cartography`; `address`→ip, `os_name`→os, `network`→zone, `labels`→tags
- services: `ports`; `host`/`ip`/`name`→asset, `proto`→protocol, `app`/`name`→service, `flow_count`→flows
- sessions: `flows`, `netflow`; `source`/`src_ip`/`client`→src, `destination`/`dst_ip`/`server`→dst,
  `sport`/`dport`→ports, `octets`→bytes, `pkts`→packets, `start`/`end`→first/last_seen, `tcp_state`→state

## Normalized output (runner contract)

```json
{ "source": "Obserae",
  "netflow": { "assets": [...], "services": [...], "sessions": [...] } }
```

`runner.import_netflow` upserts assets (by name), `ASSETSERVICE` (unique per asset+protocol+port,
flow counts accumulated) and `NETWORKSESSION` rows. No `ToolID`/DB coupling in `run.py`.
