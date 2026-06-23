# burpwn

`burpwn` · **import** connector · category **Web Pentest** · ⚠️ **intrusive** (engagement scope enforced)

Imports captured web traffic from burpwn (own2pwn-fr/burpwn) — a standalone Rust intercepting proxy + execution sandbox for agentic web pentesting that stores every HTTP/HTTPS flow in a per-session SQLite database. Offline mode parses a burpwn flow export (JSON: `burpwn req list --json`); live mode (Linux, requires bubblewrap/nftables) runs a command through the proxy via `burpwn exec -- <cmd>` and reads the captured flows. The target host becomes an ASSET, each discovered endpoint becomes a component on it, and interesting observations (auth endpoints, server errors, reflected/sensitive parameters) become VULNERABILITY findings. Active web pentest (intrusive). Wired into the web-app pentest attack chains.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a burpwn flow export to import (JSON, e.g. `burpwn req list --json > flows.json`). |
| `target` | url | no | — | Live mode (Linux): base URL to exercise through the burpwn proxy (must be in the engagement scope). |
| `command` | string | no | `curl -sk {target}` | Live mode: command run inside the burpwn sandbox ({target} is substituted). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *burpwn*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:burpwn`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
