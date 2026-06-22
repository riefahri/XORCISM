"""run.py — XORCISM connector for Atlassian Opsgenie (on-call alerting / incident mgmt).

Imports Opsgenie alerts into XORCISM as security alerts (XINCIDENT.ALERT via
runner.import_incidents). Opsgenie is a widely used on-call/alerting platform; importing its
alerts unifies paging with the SOC incident layer.

Modes (in order):
    live    : OPSGENIE_API_KEY -> GET https://api.opsgenie.com/v2/alerts (or EU endpoint).
    offline : params["file"] -> parse a saved /v2/alerts export ({data:[...]} or list).
    demo    : neither -> import the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    OPSGENIE_API_KEY    API integration key (sent as "GenieKey ...")     (live)
    OPSGENIE_EU         set to 1 to use https://api.eu.opsgenie.com       (optional)

Normalized result: {"source": "Opsgenie", "alerts": [...]}. Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

SOURCE = "Opsgenie"
_PRIO = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low", "P5": "low"}


def _normalize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for a in rows or []:
        if not isinstance(a, dict):
            continue
        ext = a.get("id") or a.get("tinyId")
        if not ext:
            continue
        owner = a.get("owner")
        out.append({
            "external_id": str(ext),
            "name": str(a.get("message") or ext)[:300],
            "description": str(a.get("description") or a.get("message") or "")[:4000],
            "severity": _PRIO.get(str(a.get("priority") or "").upper(), "medium"),
            "status": a.get("status"),
            "category": "Alert",
            "assignee": owner,
            "tags": a.get("tags"),
            "url": (f"https://app.opsgenie.com/alert/detail/{ext}/details" if a.get("id") else None),
            "asset": a.get("source"),
            "created": a.get("createdAt"),
        })
    return out


def _live(key: str, query: str, limit: int, eu: bool) -> List[Dict[str, Any]]:
    base = "https://api.eu.opsgenie.com" if eu else "https://api.opsgenie.com"
    qs = urllib.parse.urlencode({"query": query or "status: open", "limit": str(min(limit, 100)),
                                 "sort": "createdAt", "order": "desc"})
    req = urllib.request.Request(f"{base}/v2/alerts?{qs}", headers={"Authorization": f"GenieKey {key}"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace") or "null")
    rows = data.get("data") if isinstance(data, dict) else data
    return _normalize(rows or [])


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    query = str(params.get("query") or "status: open")
    key = (os.environ.get("OPSGENIE_API_KEY") or "").strip()
    eu = str(os.environ.get("OPSGENIE_EU") or "").strip() in ("1", "true", "yes")

    if key:
        alerts = _live(key, query, limit, eu)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        rows = data.get("data") if isinstance(data, dict) else data
        alerts = _normalize(rows or [])
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
