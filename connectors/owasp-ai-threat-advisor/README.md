# OWASP AI Exchange — Agent Threat Advisor

`owasp-ai-threat-advisor` · **report** connector · category **Threat Modeling**

Threat-models an AI / agentic system against the OWASP AI Exchange (https://owaspai.org). Describe the system (LLM app / autonomous agent / ML model; whether it uses tools, has memory, acts autonomously, ingests external content or handles sensitive data) and the advisor returns the applicable AI threats — prompt injection, excessive agency, tool misuse, memory poisoning, rogue agents, identity abuse, data poisoning, model theft and more — each with its lifecycle phase, impact and mitigating controls. Read-only advisory: no DB access, no network, no target (worker-safe). Mirrors the in-app /ai-threat-advisor.

**Upstream:** https://owaspai.org

## Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `system_type` | enum | yes | `agent` | Kind of AI system: llm (LLM application), agent (autonomous agent), ml (classic ML model). (one of: `llm`, `agent`, `ml`) |
| `uses_tools` | bool | no | `True` | The system can invoke tools / functions / actions. |
| `has_memory` | bool | no | `False` | The system has persistent memory or a RAG store. |
| `autonomous` | bool | no | `True` | The system acts autonomously (plans and executes without per-step approval). |
| `external_data` | bool | no | `True` | The system ingests external / untrusted content (web, docs, emails, tool output). |
| `sensitive_data` | bool | no | `False` | The system handles sensitive data (PII, secrets, regulated data). |

## How it works

Connector type: **report**.

## Running it

- **From XORCISM** — open **Connectors**, choose *OWASP AI Exchange — Agent Threat Advisor*, fill in the parameters and run it (admin only; this creates a job consumed by the Python worker `connectors/runner.py`). Required permission: `connector:owasp-ai-threat-advisor`.

---
<sub>Generated from [`connector.json`](connector.json) by `connectors/gen_readmes.py`. Edit the manifest (not this file), then regenerate.</sub>
