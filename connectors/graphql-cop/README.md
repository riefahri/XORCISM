# GraphQL Cop — GraphQL API security audit

`graphql-cop` · **import** connector · category **API Security** · ⚠️ **intrusive** (engagement scope enforced)

Runs GraphQL Cop (https://github.com/dolevf/graphql-cop) against a GraphQL endpoint and imports its findings. GraphQL Cop probes for introspection enabled, GraphiQL/Playground exposed, alias/field/directive/circular-query overloading (DoS), batch queries (DoS), GET-based & urlencoded POST queries (CSRF), and tracing/debug info-leak. The scanned endpoint becomes an ASSET; each positive finding becomes a VULNERABILITY (severity from HIGH/LOW/INFO, with impact + a reproducible curl). Offline: pass `file` = a graphql-cop JSON export (`graphql-cop -t <url> -o json`). Live (ACTIVE WEB SCANNING — authorized scope only): pass `target` = the GraphQL endpoint URL, with the `graphql-cop` binary on the worker PATH (or GRAPHQL_COP_BIN). Recorded as a DevSecOps DAST scan.

**Upstream:** https://github.com/dolevf/graphql-cop

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `target` | target | no | — | Live mode: the GraphQL endpoint URL to scan (e.g. https://app.example.com/graphql). Must be in the engagement scope. |
| `header` | string | no | — | Live mode: extra header(s) as JSON passed to graphql-cop -H (e.g. {"Authorization":"Bearer …"}). |
| `proxy` | string | no | — | Live mode: HTTP(S) proxy URL passed to graphql-cop -x. |
| `file` | file | no | — | Offline mode: a graphql-cop JSON export to import. |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *GraphQL Cop — GraphQL API security audit*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:graphql-cop`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/graphql-cop/sample.json --connector graphql-cop
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

## Secrets & configuration

API keys and other secrets are read from the **worker environment** — never entered in the XORCISM UI. See the description above for the exact variable names.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
