# ressrf — SSRF scanner

`ressrf` · **import** connector · category **vuln** · ⚠️ **intrusive** (engagement scope enforced)

ressrf (R0X4R) — automated Server-Side Request Forgery (SSRF) discovery: mutates parameters and headers while correlating out-of-band (OAST) callbacks. Confirmed SSRF findings are imported as VULNERABILITY / ASSETVULNERABILITY against the target asset. Authorized testing only (target must be in the engagement scope). Tool: https://github.com/R0X4R/ressrf.

**Upstream:** https://github.com/R0X4R/ressrf

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | yes | — | Target URL/host to test for SSRF (within the authorized engagement scope). |
| `collab` | string | no | — | Custom OAST collaborator domain (-c). Otherwise ressrf's default is used. |
| `rate` | int | no | `50` | Max requests/second (-r). (range 1–500) |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *ressrf — SSRF scanner*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:ressrf`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
