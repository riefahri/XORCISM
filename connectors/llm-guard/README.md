# AI Guardrail Gateway — block telemetry (LLM Guard / NeMo / Lakera)

`llm-guard` · **import** connector · category **AI Guardrails**

Imports the enforcement telemetry from an inline AI guardrail gateway (LLM Guard, NeMo Guardrails, Llama Guard, Lakera Guard…) — the prompts/responses it BLOCKED or FLAGGED — into XORCISM as AI-guardrail violations, so the inline-enforcement layer shows up alongside the endpoint agent's guardrail posture in the AI Guardrails cockpit. This is the enforcement half of guardrails management (the endpoint agent measures posture; the gateway does the gating). Offline: pass `file` = a gateway telemetry JSON export (LLM-Guard-style scan results or a flat event list); no file → the bundled sample. Each blocked/flagged event → an AIGUARDRAILVIOLATION (severity from risk score, ATT&CK/OWASP-AI-Exchange technique from the scanner name).

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `file` | file | no | — | AI guardrail gateway telemetry JSON export (blocked/flagged prompts). |
| `host` | string | no | — | Label for the protected app/gateway (default: derived from the export, else 'ai-gateway'). |

## How it works

This is an **import** connector. `run.py` exposes `run(params, workdir)` and returns the normalized result `{assets, services, cpes, vulns}` (some connectors also return `hosts` or `intel`). The XORCISM runner imports it — discovered hosts/IPs become **assets**, and findings become **vulnerabilities**. The connector performs **no database access** itself, so it is safe to run on a remote worker.

## Running it

- **From XORCISM** — open **Connectors**, choose *AI Guardrail Gateway — block telemetry (LLM Guard / NeMo / Lakera)*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:llm-guard`.
- **Self-test** — parse **and import** the bundled `sample.json` (no live tool):

  ```bash
  python connectors/runner.py --selftest connectors/llm-guard/sample.json --connector llm-guard
  ```
  > Note: `--selftest` writes to the database. Use a throwaway `XORCISM_DB_DIR` to avoid touching live data.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
