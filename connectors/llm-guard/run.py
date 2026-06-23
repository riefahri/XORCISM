"""run.py — XORCISM connector for an AI guardrail gateway (LLM Guard / NeMo Guardrails / Llama
Guard / Lakera…). It imports the gateway's *enforcement telemetry* — the prompts/responses it
BLOCKED or FLAGGED — into XORCISM as AI-guardrail violations, so the inline-enforcement layer shows
up next to the endpoint agent's guardrail posture in the AI Guardrails cockpit.

This is the "enforcement" half of guardrails management: the endpoint agent measures posture, the
gateway does the actual gating, and its block telemetry lands here.

Modes:
    offline : params["file"] -> a gateway telemetry JSON export. Auto-detects shapes — a list of
              events, {results:[...]} / {events:[...]} / {scan_results:[...]} — and per-event the
              common LLM-Guard fields (scanner/rule, valid/is_valid/blocked, risk_score, prompt).
    demo    : no file -> the bundled sample.json.

Normalized result: {guardrail_violations:[{rule, action, severity, detail, technique}], host, source}
-> runner.import_ai_guardrail (XAGENT.AIGUARDRAILVIOLATION). Worker-safe: stdlib only, no DB access.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

SOURCE = "LLM Guard"
# Map common guardrail scanner/rule names to an OWASP AI Exchange technique.
_TECH = {
    "promptinjection": "AIX-01", "prompt_injection": "AIX-01", "jailbreak": "AIX-01",
    "ban_substrings": "AIX-01", "bansubstrings": "AIX-01", "secrets": "AIX-29", "anonymize": "AIX-29",
    "sensitive": "AIX-29", "pii": "AIX-29", "toxicity": "AIX-05", "bias": "AIX-05",
    "code": "AIX-03", "maliciousurls": "AIX-04", "malicious_urls": "AIX-04", "relevance": "AIX-06",
}


def _tech(rule: str) -> str:
    r = "".join(c for c in str(rule).lower() if c.isalnum() or c == "_")
    for k, v in _TECH.items():
        if k in r:
            return v
    return "AIX-01"


def _sev(score: Any, explicit: Any = None) -> str:
    if explicit:
        s = str(explicit).lower()
        if s in ("critical", "high", "medium", "low", "info"):
            return s
    try:
        f = float(score)
        return "critical" if f >= 0.9 else "high" if f >= 0.7 else "medium" if f >= 0.4 else "low"
    except (TypeError, ValueError):
        return "medium"


def _blocked(e: Dict[str, Any]) -> bool:
    # explicit action
    act = str(e.get("action") or "").lower()
    if act:
        return act in ("block", "blocked", "flag", "flagged", "deny", "denied")
    # LLM Guard style: valid/is_valid == False means it failed the scanner (blocked)
    for k in ("valid", "is_valid", "passed", "allowed"):
        if k in e:
            return not bool(e.get(k))
    if "blocked" in e:
        return bool(e.get("blocked"))
    return False


def _events(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        for k in ("results", "events", "scan_results", "violations", "data"):
            if isinstance(data.get(k), list):
                return data[k]
        return [data]
    return data if isinstance(data, list) else []


def _host(data: Any, params: Dict[str, Any]) -> str:
    if params.get("host"):
        return str(params["host"])
    if isinstance(data, dict):
        for k in ("host", "app", "application", "endpoint", "target"):
            if data.get(k):
                return str(data[k])
    return "ai-gateway"


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    viols: List[Dict[str, Any]] = []
    for e in _events(data):
        if not isinstance(e, dict) or not _blocked(e):
            continue
        rule = e.get("scanner") or e.get("rule") or e.get("name") or e.get("type") or "guardrail rule"
        viols.append({
            "rule": str(rule)[:120], "action": "blocked",
            "severity": _sev(e.get("risk_score", e.get("score")), e.get("severity")),
            "technique": _tech(rule),
            "detail": str(e.get("prompt") or e.get("detail") or e.get("reason") or e.get("output") or "")[:240],
        })
    host = _host(data, params)
    print("[llm-guard] %d guardrail block(s) imported from %s" % (len(viols), host))
    return {"guardrail_violations": viols, "host": host, "source": SOURCE}


if __name__ == "__main__":
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(run(p, "."), indent=2)[:2000])
