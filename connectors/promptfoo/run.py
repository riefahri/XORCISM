"""run.py -- XORCISM connector for Promptfoo (github.com/promptfoo/promptfoo), the LLM red-team / eval
framework that is the automation engine in the Fortbridge "OWASP Top 10 for LLM Applications" testing
methodology.

`promptfoo redteam eval -o results.json` runs adversarial test cases (one per red-team plugin x strategy)
and grades each: a test "passes" when the model resists, so pass=false is a finding. This connector parses
that results file (or a shared eval JSON), maps each plugin id to the OWASP LLM Top 10, and produces the
result list the XORCISM LLM red-team / AI-BAS module ingests (POST /api/ai-redteam/import/<aiSystemId>
with body {"results": <this list>}), which in turn auto-fills the LLM Pentest Methodology cockpit
(/llm-pentest). Output is ASCII-only, stdlib-only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "promptfoo"

# Promptfoo red-team plugin-id prefix -> OWASP LLM Top 10 (2025) + readable category. Ordered: first match wins.
_OWASP = [
    ("pii", "LLM02", "Sensitive information disclosure"),
    ("harmful:privacy", "LLM02", "Sensitive information disclosure"),
    ("cross-session-leak", "LLM02", "Sensitive information disclosure"),
    ("system-prompt-override", "LLM07", "System prompt leakage"),
    ("prompt-extraction", "LLM07", "System prompt leakage"),
    ("debug-access", "LLM07", "System prompt leakage"),
    ("rbac", "LLM06", "Excessive agency"),
    ("bola", "LLM06", "Excessive agency"),
    ("bfla", "LLM06", "Excessive agency"),
    ("excessive-agency", "LLM06", "Excessive agency"),
    ("ssrf", "LLM05", "Improper output handling"),
    ("sql-injection", "LLM05", "Improper output handling"),
    ("shell-injection", "LLM05", "Improper output handling"),
    ("xss", "LLM05", "Improper output handling"),
    ("hallucination", "LLM09", "Misinformation"),
    ("overreliance", "LLM09", "Misinformation"),
    ("divergent-repetition", "LLM10", "Unbounded consumption"),
    ("prompt-injection", "LLM01", "Prompt injection"),
    ("jailbreak", "LLM01", "Prompt injection"),
    ("hijacking", "LLM01", "Prompt injection"),
    ("ascii-smuggling", "LLM01", "Prompt injection"),
    ("harmful", "LLM01", "Prompt injection"),
]


def _map(plugin: str) -> Dict[str, str]:
    p = (plugin or "").lower()
    for prefix, owasp, cat in _OWASP:
        if p.startswith(prefix):
            return {"owasp": owasp, "category": cat}
    return {"owasp": "LLM01", "category": "Prompt injection"}


def _plugin_of(rec: Dict[str, Any]) -> str:
    # plugin / strategy ids live in different places across promptfoo versions
    for getter in (
        lambda r: (r.get("testCase") or {}).get("metadata", {}).get("pluginId"),
        lambda r: (r.get("metadata") or {}).get("pluginId"),
        lambda r: r.get("pluginId"),
        lambda r: (r.get("vars") or {}).get("pluginId"),
    ):
        try:
            v = getter(rec)
            if v:
                return str(v)
        except Exception:  # noqa: BLE001
            pass
    return ""


def _passed(rec: Dict[str, Any]) -> Any:
    gr = rec.get("gradingResult") or {}
    if isinstance(gr, dict) and gr.get("pass") is not None:
        return bool(gr.get("pass"))
    if rec.get("success") is not None:
        return bool(rec.get("success"))
    if rec.get("pass") is not None:
        return bool(rec.get("pass"))
    return None


def _reason(rec: Dict[str, Any]) -> str:
    gr = rec.get("gradingResult") or {}
    return str((gr.get("reason") if isinstance(gr, dict) else "") or rec.get("error") or "")[:400]


def _from_result(rec: Dict[str, Any]) -> Dict[str, Any] | None:
    if not isinstance(rec, dict):
        return None
    plugin = _plugin_of(rec)
    passed = _passed(rec)
    if not plugin and passed is None:
        return None
    plugin = plugin or "redteam"
    if passed is True:
        outcome, detail = "pass", "promptfoo %s: model resisted" % plugin
    elif passed is False:
        outcome, detail = "fail", ("promptfoo %s: attack succeeded. %s" % (plugin, _reason(rec))).strip()
    else:
        outcome, detail = "info", "promptfoo %s" % plugin
    m = _map(plugin)
    return {"probe": plugin, "owasp": m["owasp"], "category": m["category"], "name": plugin, "outcome": outcome, "detail": detail[:480]}


def _records(data: Any) -> List[Dict[str, Any]]:
    # accept: {results:{results:[...]}}, {results:[...]}, [...], {evalResults:[...]}
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        res = data.get("results")
        if isinstance(res, dict) and isinstance(res.get("results"), list):
            return [r for r in res["results"] if isinstance(r, dict)]
        if isinstance(res, list):
            return [r for r in res if isinstance(r, dict)]
        for k in ("evalResults", "records", "table"):
            if isinstance(data.get(k), list):
                return [r for r in data[k] if isinstance(r, dict)]
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    results: List[Dict[str, Any]] = []
    for rec in _records(data):
        r = _from_result(rec)
        if r:
            results.append(r)
    return {"source": SOURCE, "aibas": {"results": results}}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    res = r["aibas"]["results"]
    fails = sum(1 for x in res if x["outcome"] == "fail")
    print("results=%d failed=%d" % (len(res), fails))
    for x in res[:8]:
        print("  %s %-5s %-32s %s" % (x["outcome"], x["owasp"], x["category"], x["probe"]))
