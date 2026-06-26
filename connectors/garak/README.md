# garak connector

Imports a [**garak**](https://github.com/NVIDIA/garak) (NVIDIA — the LLM vulnerability scanner)
report into the XORCISM **LLM red-team / AI-BAS** module
([`/ai-redteam`](../../xorcism_ts/server/aibas.ts)).

garak probes a generative model for prompt injection, jailbreaks, leakage, toxicity, insecure
output, package hallucination and more; its detectors score each attempt. This connector parses the
report and normalizes each probe's outcome to the **OWASP LLM Top 10**, producing the result list the
AI-BAS module ingests as a real test run against a registered AI system.

## Input (`file`, else bundled `sample.jsonl`)

* **`report.jsonl`** — newline-delimited JSON. `eval` records (`{probe, detector, passed, total}`)
  are used: the model *passes* when it resists, so `passed < total` → a finding (`fail`).
* a **summary JSON** (array or `{evals|results|records:[…]}`) in the same shape.

## Output → AI-BAS import

```json
{ "source": "garak",
  "aibas": { "results": [
    { "probe": "dan.Dan_11_0", "owasp": "LLM01", "category": "Prompt injection",
      "name": "dan.Dan_11_0", "outcome": "fail", "detail": "garak …: 2/10 attempts resisted" }
  ] } }
```

Send `aibas.results` to the AI-BAS import endpoint for the AI system under test:

```bash
python connectors/garak/run.py > out.json
# then POST the `aibas.results` array:
curl -X POST http://localhost:9292/api/ai-redteam/import/<aiSystemId> \
     -H 'Content-Type: application/json' \
     -d "{\"results\": $(jq -c .aibas.results out.json)}"
```

The module records an `imported` AI-BAS run (grade + exposure + per-probe outcomes) against that AI
system, overriding the offline guardrail-coverage assessment with ground truth.

## probe → OWASP mapping

`promptinject` / `dan` / `latentinjection` / `encoding` → **LLM01**; `leakreplay` → **LLM02**;
`xss` / `malwaregen` / `exploitation` → **LLM05**; `packagehallucination` / `snowball` → **LLM09**
(others default to LLM01).

Worker-safe: stdlib only, ASCII-only output, no database access.

## Quick test

```bash
python connectors/garak/run.py
```
