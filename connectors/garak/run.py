"""run.py -- XORCISM connector for garak (github.com/NVIDIA/garak), the LLM vulnerability scanner.

garak probes a generative model (prompt injection, jailbreaks, leakage, toxicity, insecure output,
package hallucination, ...) and its detectors score each attempt. This connector parses a garak
**report** (report.jsonl -- newline-delimited JSON -- or a summary list/JSON) and normalizes the
probe outcomes to the OWASP LLM Top 10, producing the result list the XORCISM LLM red-team / AI-BAS
module ingests (POST /api/ai-redteam/import/<aiSystemId> with body {"results": <this list>}).

garak `eval` records carry {probe, detector, passed, total}: a model "passes" when it resists, so
passed < total means the attack succeeded (a finding). Output is ASCII-only, stdlib-only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

SOURCE = "garak"

# garak probe-family prefix -> OWASP LLM Top 10 + a readable category
_OWASP = [
    ("promptinject", "LLM01", "Prompt injection"),
    ("latentinjection", "LLM01", "Prompt injection"),
    ("dan", "LLM01", "Prompt injection"),
    ("grandma", "LLM01", "Prompt injection"),
    ("encoding", "LLM01", "Prompt injection"),
    ("glitch", "LLM01", "Prompt injection"),
    ("leakreplay", "LLM02", "Sensitive info disclosure"),
    ("xss", "LLM05", "Insecure output handling"),
    ("malwaregen", "LLM05", "Insecure output handling"),
    ("exploitation", "LLM05", "Insecure output handling"),
    ("packagehallucination", "LLM09", "Misinformation"),
    ("snowball", "LLM09", "Misinformation"),
    ("toxicity", "LLM01", "Prompt injection"),
    ("realtoxicityprompts", "LLM01", "Prompt injection"),
    ("av_spam_scanning", "LLM05", "Insecure output handling"),
]


def _map(probe: str) -> Dict[str, str]:
    p = (probe or "").lower()
    for prefix, owasp, cat in _OWASP:
        if p.startswith(prefix) or ("." + prefix) in p:
            return {"owasp": owasp, "category": cat}
    return {"owasp": "LLM01", "category": "Prompt injection"}


def _from_eval(rec: Dict[str, Any]) -> Dict[str, Any] | None:
    probe = str(rec.get("probe") or rec.get("probe_name") or rec.get("probe_classname") or "")
    if not probe:
        return None
    passed = rec.get("passed")
    total = rec.get("total")
    if passed is None and "score" in rec:
        # some summaries carry a pass-rate score 0..1
        try:
            passed, total = float(rec["score"]), 1.0
        except Exception:  # noqa: BLE001
            passed, total = None, None
    if passed is not None and total:
        failed = total - passed
        outcome = "fail" if failed > 0 else "pass"
        detail = "garak %s: %s/%s attempts resisted (%s detector)" % (probe, int(passed) if float(passed).is_integer() else passed, total, rec.get("detector", "?"))
    else:
        outcome = "info"
        detail = "garak %s" % probe
    m = _map(probe)
    return {"probe": probe, "owasp": m["owasp"], "category": m["category"], "name": probe, "outcome": outcome, "detail": detail[:480]}


def _normalize(data: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    items = data if isinstance(data, list) else (data.get("evals") or data.get("results") or data.get("records") or []) if isinstance(data, dict) else []
    for rec in items:
        if not isinstance(rec, dict):
            continue
        if rec.get("entry_type") and rec.get("entry_type") not in ("eval", "result"):
            continue
        r = _from_eval(rec)
        if r:
            out.append(r)
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.jsonl")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    results: List[Dict[str, Any]] = []
    try:
        data = json.loads(raw)  # a JSON array / object
        results = _normalize(data)
    except Exception:  # noqa: BLE001
        # newline-delimited JSON (report.jsonl)
        records = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except Exception:  # noqa: BLE001
                continue
        results = _normalize(records)
    return {"source": SOURCE, "aibas": {"results": results}}


if __name__ == "__main__":
    import tempfile
    r = run({}, tempfile.mkdtemp())
    res = r["aibas"]["results"]
    fails = sum(1 for x in res if x["outcome"] == "fail")
    print("results=%d failed=%d" % (len(res), fails))
    for x in res[:6]:
        print("  %s %-12s %-4s %s" % (x["outcome"], x["owasp"], "", x["probe"]))
