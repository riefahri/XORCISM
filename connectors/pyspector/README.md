# PySpector

`pyspector` · **import** connector · category **SAST**

Imports Python SAST findings from PySpector (ParzivalHack/PySpector) — a fast Rust-cored static analyzer that scans Python code/repos for security vulnerabilities, hardcoded secrets, config errors, taint flows, LLM-specific issues and supply-chain CVEs. Offline mode parses a PySpector JSON or SARIF report; live mode runs `pyspector scan <path|--url repo>` if the binary is on the worker PATH. The scanned project/repo becomes an ASSET and each finding (rule + severity, CWE/CVE when present) becomes a VULNERABILITY. Worker-safe (no DB).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | Path on the worker to a PySpector report to import (JSON or SARIF: `pyspector scan <path> --format json -o out.json`). |
| `target` | string | no | — | Live mode: a path or Git repo URL to scan with the local `pyspector` binary. |
| `project` | string | no | — | Project / asset name for the scanned codebase (defaults to the target/repo name). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *PySpector*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:pyspector`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
