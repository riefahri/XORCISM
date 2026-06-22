"""run.py — XORCISM connector for Zammad (open-source help-desk / ticketing).

Imports Zammad tickets into XORCISM as security alerts (XINCIDENT.ALERT via
runner.import_incidents). Zammad is a popular open-source ticketing system; many SOCs use it (or
similar) as their case queue. This brings those tickets into the XORCISM incident layer.

Modes (in order):
    live    : ZAMMAD_URL + ZAMMAD_TOKEN -> GET {url}/api/v1/tickets?expand=true.
    offline : params["file"] -> parse a saved tickets export (list or {tickets:[...]}).
    demo    : neither -> import the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    ZAMMAD_URL      base URL, e.g. https://support.acme.io      (live)
    ZAMMAD_TOKEN    HTTP token access (sent as "Token token=")  (live)

Normalized result: {"source": "Zammad", "alerts": [...]}. Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

SOURCE = "Zammad"
# Zammad default priorities: 1 low / 2 normal / 3 high -> severity (match by name or id).
_PRIO = {"1": "low", "2": "medium", "3": "high", "1 low": "low", "2 normal": "medium", "3 high": "high"}


def _normalize(rows: List[Dict[str, Any]], base: str, group: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for t in rows or []:
        if not isinstance(t, dict):
            continue
        if group and str(t.get("group") or "").strip().lower() != group.strip().lower():
            continue
        ext = t.get("number") or t.get("id")
        if not ext:
            continue
        prio = str(t.get("priority") or t.get("priority_id") or "2").strip().lower()
        out.append({
            "external_id": str(ext),
            "name": str(t.get("title") or ext)[:300],
            "description": str(t.get("note") or t.get("title") or "")[:4000],
            "severity": _PRIO.get(prio, "medium"),
            "status": t.get("state") or t.get("state_id"),
            "category": "Ticket",
            "assignee": t.get("owner"),
            "tags": t.get("group"),
            "url": (f"{base.rstrip('/')}/#ticket/zoom/{t.get('id')}" if base and t.get("id") else None),
            "created": t.get("created_at"),
        })
    return out


def _live(base: str, token: str, limit: int, group: str) -> List[Dict[str, Any]]:
    base = base.rstrip("/")
    qs = urllib.parse.urlencode({"expand": "true", "per_page": str(min(limit, 100)), "sort_by": "created_at", "order_by": "desc"})
    req = urllib.request.Request(f"{base}/api/v1/tickets?{qs}", headers={"Authorization": f"Token token={token}"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace") or "null")
    rows = data if isinstance(data, list) else (data.get("tickets") if isinstance(data, dict) else [])
    return _normalize(rows or [], base, group)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    group = str(params.get("group") or "").strip()
    base = (os.environ.get("ZAMMAD_URL") or "").strip()
    token = (os.environ.get("ZAMMAD_TOKEN") or "").strip()

    if base and token:
        alerts = _live(base, token, limit, group)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        rows = data if isinstance(data, list) else (data.get("tickets") if isinstance(data, dict) else [])
        alerts = _normalize(rows or [], base, group)
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
