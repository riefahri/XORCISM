# ThePhishAnalyzer

`thephishanalyzer` · **import** connector · category **Phishing Analysis**

Analyzes a phishing email (.eml / RFC822) — typically a DOCUMENT attached in XORCISM — and extracts its indicators of compromise. Parses headers and authentication results (SPF / DKIM / DMARC), the sender and reply-path, all URLs and the domains/IPs they resolve to, and the SHA-256 of each attachment. Each indicator is imported into the CTI store (XTHREAT.INTELEXCHANGE) tagged 'phishing', and the email itself is recorded as a phishing report. Offline mode parses a local .eml file (worker-safe, no DB, no network). Mirrors achrafhachimiac/ThePhishAnalyzer's email-intake workflow.

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | yes | — | Path on the worker to the phishing email to analyze (.eml / RFC822). In XORCISM this is usually an exported DOCUMENT. |
| `label` | string | no | `phishing` | Label(s) to tag the extracted indicators with (comma-separated). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *ThePhishAnalyzer*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:thephishanalyzer`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
