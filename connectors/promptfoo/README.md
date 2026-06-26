# Promptfoo connector (LLM red-team / eval)

Imports a [Promptfoo](https://github.com/promptfoo/promptfoo) red-team eval result into XORCISM.
Promptfoo is the **automation engine** in the Fortbridge *OWASP Top 10 for LLM Applications* testing
methodology — it runs adversarial test suites (one test per red-team plugin × strategy) and grades each
attempt pass/fail.

## Mapping
Each Promptfoo result → an OWASP LLM Top 10 (2025) outcome:

| Promptfoo plugin | OWASP-LLM |
|---|---|
| `prompt-injection`, `jailbreak`, `hijacking`, `ascii-smuggling`, `harmful:*` | LLM01 Prompt injection |
| `pii*`, `harmful:privacy`, `cross-session-leak` | LLM02 Sensitive information disclosure |
| `sql-injection`, `shell-injection`, `ssrf`, `xss` | LLM05 Improper output handling |
| `rbac`, `bola`, `bfla`, `excessive-agency` | LLM06 Excessive agency |
| `system-prompt-override`, `prompt-extraction`, `debug-access` | LLM07 System prompt leakage |
| `hallucination`, `overreliance` | LLM09 Misinformation |
| `divergent-repetition` | LLM10 Unbounded consumption |

A test **passes** when the model resists, so `gradingResult.pass = false` is a **finding** (`fail`).

## Usage
```bash
promptfoo redteam eval -o results.json        # run your red-team suite against the target model
# then import results.json via the connector (file param), or:
python run.py                                   # demo (bundled sample)
```

The normalized result (`{source, aibas:{results:[...]}}`) is POSTed to
`POST /api/ai-redteam/import/<aiSystemId>` (LLM red-team / AI-BAS, `/ai-redteam`). That run then
**auto-fills** the automatable categories of an engagement in the **LLM Pentest Methodology** cockpit
(`/llm-pentest`).

Worker-safe: stdlib only, ASCII-only output, no DB access. Complements the `garak` and `PyRIT`
importers. From the Fortbridge OWASP-LLM testing methodology.
