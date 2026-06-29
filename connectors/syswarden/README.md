# SysWarden connector

[SysWarden](https://github.com/duggytuxy/syswarden) ([syswarden.io](https://syswarden.io)) is an
open-source, enterprise-grade **Host Intrusion Detection & Prevention System** / security
orchestrator for critical Linux infrastructure (GPLv3). It combines:

- hardware-level network filtering (**L2–L4** via `nftables`/`pf`) — malicious packets dropped at the NIC,
- the **OWASP ModSecurity** WAF (**L7**) for deep HTTP inspection,
- **WireGuard** cloaking of SSH / admin interfaces,
- automated **CIS Level 2** hardening.

This connector imports a SysWarden **status/report export** and maps it to the XORCISM model.

## What it imports

| SysWarden | XORCISM |
|---|---|
| Protected host (hostname / IP / OS + hardening posture) | **ASSET** |
| CIS hardening control not applied / failed | **finding** `SYSWARDEN-CIS-<id>` (severity from the control) |
| Disabled defensive component (nftables / ModSecurity / WireGuard) | **posture finding** `SYSWARDEN-COMP-<name>` |
| Source IP blocked by nftables / ModSecurity | **threat-intel IOC** → `XTHREAT.INTELEXCHANGE` |

Normalized result: `{assets, services, cpes:[], vulns, intel}`.

## Configuration

The connector is **worker-safe**: it only reads an exported file — no live host access, no DB writes.

| Source | How |
|---|---|
| `file` parameter | Upload a SysWarden status JSON (e.g. `syswarden --status --json > status.json`). |
| `SYSWARDEN_STATUS` env (worker) | Absolute path to that JSON on the worker. |
| `min_severity` parameter | `low` \| `medium` \| `high` — minimum hardening-finding severity (default `low`). |

The parser is defensive about field names (they vary between SysWarden versions): it accepts
`host{}` or top-level `hostname/ip/os`; `hardening.controls[]` (`status`/`applied`/`severity`);
`components{}`; and blocked IPs under `blocked`/`blocked_ips`/`blocks` or `firewall`/`waf`/`ips`.

## Offline dry run

```bash
python connectors/syswarden/run.py            # uses a built-in sample
python connectors/syswarden/run.py --file status.json --min-severity medium
```

Expected status JSON (minimal):

```json
{
  "host": { "hostname": "edge01.example.com", "ip": "203.0.113.10", "os": "Debian 12" },
  "hardening": { "cis_level": 2, "score": 88, "controls": [
    { "id": "5.2.10", "title": "Ensure SSH root login is disabled", "status": "failed", "severity": "high" }
  ]},
  "components": { "nftables": "active", "modsecurity": "active", "wireguard": "inactive" },
  "blocked": [ { "ip": "198.51.100.7", "reason": "volumetric DDoS (NIC drop)", "count": 91234 } ]
}
```

The SysWarden host posture surfaces in **Asset Management** + the **SOC**; blocked-IP IOCs feed **CTI**.
