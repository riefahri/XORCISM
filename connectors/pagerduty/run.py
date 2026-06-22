"""run.py — XORCISM connector for PagerDuty (on-call / incident-response alerting).

Imports PagerDuty incidents into XORCISM as security alerts (XINCIDENT.ALERT via
runner.import_incidents). PagerDuty is the de-facto on-call/incident platform; surfacing its
incidents in XORCISM ties paging/escalation to the SOC incident layer.

Modes (in order):
    live    : PAGERDUTY_API_TOKEN -> GET https://api.pagerduty.com/incidents.
    offline : params["file"] -> parse a saved /incidents export ({incidents:[...]} or list).
    demo    : neither -> import the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    PAGERDUTY_API_TOKEN    REST API key (sent as "Token token=...")     (live)
    PAGERDUTY_STATUSES     comma list (default triggered,acknowledged)  (optional)

Normalized result: {"source": "PagerDuty", "alerts": [...]}. Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

SOURCE = "PagerDuty"
# PagerDuty priority summary (P1..P5) -> severity; fall back to urgency high/low.
_PRIO = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low", "P5": "low"}


def _normalize(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i in rows or []:
        if not isinstance(i, dict):
            continue
        ext = i.get("id") or i.get("incident_number")
        if not ext:
            continue
        prio = ((i.get("priority") or {}) if isinstance(i.get("priority"), dict) else {}).get("summary")
        sev = _PRIO.get(str(prio or "").upper(), "high" if str(i.get("urgency")) == "high" else "low")
        svc = ((i.get("service") or {}) if isinstance(i.get("service"), dict) else {}).get("summary")
        assignee = None
        for a in i.get("assignments") or []:
            assignee = ((a.get("assignee") or {}) if isinstance(a, dict) else {}).get("summary")
            if assignee:
                break
        out.append({
            "external_id": str(ext),
            "name": str(i.get("title") or i.get("summary") or ext)[:300],
            "description": str(i.get("description") or i.get("title") or "")[:4000],
            "severity": sev,
            "status": i.get("status"),
            "category": "Incident",
            "assignee": assignee,
            "tags": svc,
            "url": i.get("html_url"),
            "asset": svc,
            "created": i.get("created_at"),
        })
    return out


def _live(token: str, statuses: List[str], since_hours: int, limit: int) -> List[Dict[str, Any]]:
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = [("limit", str(min(limit, 100))), ("since", since), ("sort_by", "created_at:desc")]
    for s in statuses:
        params.append(("statuses[]", s))
    url = "https://api.pagerduty.com/incidents?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Token token={token}",
        "Accept": "application/vnd.pagerduty+json;version=2",
    })
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace") or "null")
    rows = data.get("incidents") if isinstance(data, dict) else data
    return _normalize(rows or [])


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    since_hours = int(params.get("since_hours", 168) or 168)
    token = (os.environ.get("PAGERDUTY_API_TOKEN") or "").strip()
    statuses = [s.strip() for s in (os.environ.get("PAGERDUTY_STATUSES") or "triggered,acknowledged").split(",") if s.strip()]

    if token:
        alerts = _live(token, statuses, since_hours, limit)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        rows = data.get("incidents") if isinstance(data, dict) else data
        alerts = _normalize(rows or [])
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
