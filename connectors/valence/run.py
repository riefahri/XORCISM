"""run.py — Import a VALENCE GRC run export into XORCISM (Compliance).

VALENCE (https://github.com/hiro001-eth/VALENCE-GRC-Platform, MIT) is an audit-grade GRC platform that
turns SIEM telemetry into quantitative risk: it runs FAIR Monte Carlo simulations (Threat Event Frequency
~ Poisson × Loss Event Magnitude ~ Log-Normal) to produce Annual Loss Expectancy (ALE) and Value-at-Risk
(VaR 95%), monitors controls continuously with a RAG status, and maps controls across SOC 2 / ISO 27001 /
NIST CSF / PCI DSS / DORA / CMMC.

This connector maps a VALENCE run export — its per-control evaluations — to an XORCISM Compliance AUDIT
(via the runner's `compliance` import path): one AUDITFINDING per failed / at-risk control, with the
control's financial risk (ALE / VaR) carried in the finding description. Passing (green) controls are
counted in the audit summary, not stored as findings.

Config (worker environment / params, never live offensive access):
    params["file"]      a VALENCE export JSON — an object with metrics/controls/results[] (each item:
                        control id, name, framework(s), rag_status, value, threshold, ale, var_95), OR a
                        bare array of such items.  OR
    VALENCE_URL         base URL of a running VALENCE instance; the read-only metrics API is GET-fetched
                        (a base URL gets /api/metrics appended).
    VALENCE_TOKEN       optional bearer token for that API.
    params["org"]       organisation label recorded as the audit host (default: from export, else VALENCE).
    params["min_rag"]   green|amber|red — minimum RAG severity that becomes a finding (default amber:
                        amber+red controls are findings; green controls pass).

Worker-safe: reads an exported file or a read-only API; no DB access. Field names vary between VALENCE
versions, so extraction is defensive (multiple fallbacks).

Normalized result: {assets:[], …, compliance:{benchmark,baseline,host,results:[…]}, source:"VALENCE"}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/hiro001-eth/VALENCE-GRC-Platform"
_RAG_RANK = {"green": 0, "amber": 1, "red": 2}
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    min_rank = _RAG_RANK.get(str(params.get("min_rag") or "amber").lower(), 1)
    data = _load(params)
    items = _items_of(data)
    org = str(params.get("org") or _first(data if isinstance(data, dict) else {}, "org", "organization", "organisation", "tenant", "company") or "VALENCE").strip() or "VALENCE"

    results: List[Dict[str, Any]] = []
    seen = set()
    for it in items:
        rec = _to_rule(it, min_rank)
        if not rec:
            continue
        if rec["rule_id"] in seen:
            continue
        seen.add(rec["rule_id"])
        results.append(rec)

    return {
        "assets": [], "services": [], "cpes": [], "vulns": [], "intel": [],
        "compliance": {
            "benchmark": "VALENCE", "baseline": "VALENCE continuous control monitoring",
            "os": "", "host": org, "results": results,
        },
        "source": "VALENCE",
    }


# ── Load (offline file or read-only API) ──────────────────────────────────────
def _load(params: Dict[str, Any]) -> Any:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            return json.load(fh)
    import requests

    url = os.getenv("VALENCE_URL")
    if not url:
        raise RuntimeError("Provide a VALENCE export via params['file'] or set VALENCE_URL (worker env)")
    if "/api/" not in url and "?" not in url:
        url = url.rstrip("/") + "/api/metrics"
    headers = {"Accept": "application/json"}
    token = os.getenv("VALENCE_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(url, headers=headers, timeout=120)
    r.raise_for_status()
    return r.json()


def _items_of(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("metrics", "controls", "results", "evaluations", "control_results", "items", "data"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
            if isinstance(v, dict):  # e.g. {"data": {"metrics": [...]}}
                for kk in ("metrics", "controls", "results", "items"):
                    if isinstance(v.get(kk), list):
                        return [x for x in v[kk] if isinstance(x, dict)]
    return []


# ── Map one VALENCE control evaluation → a compliance rule result ─────────────
def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _rag(v: Any) -> int:
    """Normalize a RAG / status value to a rank 0=green 1=amber 2=red (-1 = unknown → treated green)."""
    s = str(v if v is not None else "").strip().lower()
    if not s:
        return -1
    if s in ("green", "ok", "pass", "passed", "compliant", "good", "low", "healthy", "met", "true", "effective"):
        return 0
    if s in ("amber", "yellow", "orange", "warn", "warning", "partial", "medium", "moderate", "degraded", "at risk", "at-risk", "stale"):
        return 1
    if s in ("red", "fail", "failed", "noncompliant", "non-compliant", "critical", "high", "breach", "breached", "unhealthy", "not met", "nodata", "no-data", "false", "ineffective"):
        return 2
    return -1


def _frameworks(it: Dict[str, Any]) -> str:
    fw = _first(it, "frameworks", "framework", "standard", "standards", "mappings", "control_mappings", "references")
    if isinstance(fw, dict):
        return ", ".join(f"{k}: {v}" for k, v in fw.items() if v)
    if isinstance(fw, list):
        return ", ".join(str(x) for x in fw if x)
    return str(fw or "").strip()


def _to_rule(it: Dict[str, Any], min_rank: int) -> Optional[Dict[str, Any]]:
    title = _first(it, "name", "title", "control_name", "metric_name", "label", "description")
    if not title:
        return None
    title = str(title).strip()
    rid = _first(it, "id", "control_id", "metric_id", "key", "ref", "control_ref", "slug") or _slug(title)

    rank = _rag(_first(it, "rag_status", "rag", "status", "state", "result", "posture"))
    if rank < 0:  # no usable status → don't invent a failure
        rank = 0
    # a control becomes a finding ("fail") when its RAG rank reaches the threshold (green never fails)
    is_finding = rank >= max(1, min_rank)
    result = "fail" if is_finding else "pass"
    severity = "High" if rank >= 2 else ("Medium" if rank == 1 else "Low")

    value = _first(it, "value", "current_value", "score", "observed")
    threshold = _first(it, "threshold", "target", "target_value", "limit")
    ale = _first(it, "ale", "annual_loss_expectancy", "average_exposure", "annualized_loss_expectancy")
    var95 = _first(it, "var_95", "var95", "var", "value_at_risk", "p95")
    desc = str(_first(it, "discussion", "rationale", "detail", "details", "description", "narrative") or "").strip()

    meta = " · ".join(filter(None, [
        f"RAG: {['green','amber','red'][rank]}",
        f"value={value}" if value not in (None, "") else "",
        f"threshold={threshold}" if threshold not in (None, "") else "",
        f"ALE=${_money(ale)}" if ale not in (None, "") else "",
        f"VaR95=${_money(var95)}" if var95 not in (None, "") else "",
    ]))
    discussion = (meta + (("\n\n" + desc) if desc else "")).strip()[:4000]
    refs = _frameworks(it)
    # carry any referenced CVE into the references string too
    cves = sorted({m.upper() for m in _CVE_RX.findall(f"{title} {desc}")})
    if cves:
        refs = (refs + " · " if refs else "") + ", ".join(cves)

    return {
        "rule_id": f"valence:{str(rid)[:80]}",
        "title": title[:300],
        "result": result,
        "severity": severity,
        "references": refs[:500],
        "discussion": discussion,
    }


def _money(v: Any) -> str:
    try:
        return f"{float(v):,.0f}"
    except (TypeError, ValueError):
        return str(v)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "control"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="VALENCE GRC connector (offline dry run)")
    ap.add_argument("--file", help="VALENCE export JSON")
    ap.add_argument("--org", default=None)
    ap.add_argument("--min-rag", default="amber")
    a = ap.parse_args()
    if not a.file:
        sample = {"org": "Acme Corp", "metrics": [
            {"id": "MFA-COVERAGE", "name": "MFA enforced on all privileged accounts", "framework": {"soc2": "CC6.1", "iso27001": "A.8.5"},
             "rag_status": "green", "value": 100, "threshold": 95, "ale": 0, "var_95": 0},
            {"id": "PATCH-SLA", "name": "Critical patches applied within SLA", "frameworks": ["SOC2 CC7.1", "NIST CSF PR.PS-02"],
             "rag_status": "amber", "value": 78, "threshold": 90, "ale": 240000, "var_95": 1100000,
             "discussion": "22% of critical patches exceeded the 14-day SLA."},
            {"id": "EDR-COVERAGE", "name": "EDR deployed on all endpoints", "framework": "PCI DSS 5.1",
             "rag_status": "red", "value": 61, "threshold": 100, "ale": 850000, "var_95": 4200000,
             "discussion": "39% of endpoints have no EDR agent reporting."},
        ]}
        fp = os.path.join(tempfile.mkdtemp(), "valence.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "org": a.org, "min_rag": a.min_rag}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    c = res["compliance"]
    fails = sum(1 for r in c["results"] if r["result"] == "fail")
    print(f"\n[valence] {len(c['results'])} controls · {fails} finding(s) · host {c['host']} (tool: {TOOL_URL})", flush=True)
