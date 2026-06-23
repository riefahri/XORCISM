# DrogonSec — SAST/SCA/Secrets/IaC (SARIF)

`drogonsec` · **tool-runner** connector · category **appsec**

Runs DrogonSec — an all-in-one open-source scanner combining SAST (20+ languages), SCA (dependency vulnerabilities), secret detection (50+ patterns) and Infrastructure-as-Code analysis — on a local source path or git repository, and imports the results via OASIS SARIF (shared SARIF parser). The scanned project becomes an ASSET; each finding becomes a finding (VULNERABILITY / ASSETVULNERABILITY) with severity from the SARIF rule level / security-severity, and the run is recorded as a DevSecOps SAST scan. Non-intrusive local code scan; no source or secrets leave the worker. Install on the worker: `go install github.com/filipi86/drogonsec/cmd/drogonsec@latest` (or use the `drogonsec` binary on PATH / the Docker image).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `source` | string | yes | — | Path on the worker to scan (a directory or a git repository). |
| `project` | string | no | — | Application/asset name to attach the findings to (default: derived from the source / SARIF). |

## How it works

This is a **tool-runner** connector. It executes the `drogonsec` tool (resolved on the worker `PATH`) and parses its output. The command is run as an argv array (no shell); `{{param}}`, `{{outfile}}` and `{{workdir}}` are substituted with validated values:

```
drogonsec scan {{source}} --format sarif --output {{outfile}}
```

Output: **file** (`.sarif`), parsed by `parse_drogonsec.py` into the normalized `{assets, services, cpes, vulns}` result. Because DrogonSec emits a single SARIF run for all of its engines (SAST / SCA / Secrets / IaC), every finding flows through the one shared SARIF parser, and the run is additionally recorded as a DevSecOps SAST scan (`mapping=drogonsec`) for the `/devsecops` cockpit.

Optional AI-powered remediation (`--enable-ai`) is **not** enabled by this connector, so no source is sent to any AI provider; add the flag locally on the worker if you want it (it uses Ollama locally, or `AI_API_KEY` for a cloud provider).

## Running it

- **From XORCISM** — open **Connectors**, choose *DrogonSec — SAST/SCA/Secrets/IaC (SARIF)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:drogonsec`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
