"""run.py — XORCISM connector for ServiceNow (ITSM / Security Incident Response).

Imports ServiceNow incidents into XORCISM as security alerts (XINCIDENT.ALERT via
runner.import_incidents). ServiceNow is the dominant enterprise ITSM/SecOps ticketing system;
this brings its tickets into XORCISM's incident layer so the SOC has one pane of glass.

Modes (in order):
    live    : SERVICENOW_INSTANCE + SERVICENOW_USER + SERVICENOW_PASSWORD -> Table API.
    offline : params["file"] -> parse a saved Table-API export ({result:[...]} or list).
    demo    : neither -> import the bundled sample.json.

Config (worker environment variables, never entered in the UI):
    SERVICENOW_INSTANCE   e.g. dev12345.service-now.com         (live)
    SERVICENOW_USER       integration user                      (live)
    SERVICENOW_PASSWORD   password                              (live)
    SERVICENOW_TABLE      table name (default "incident";
                          use "sn_si_incident" for SecOps SIR)  (optional)

Normalized result: {"source": "ServiceNow", "alerts": [...]}. Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

SOURCE = "ServiceNow"
# ServiceNow priority 1..5 (1=Critical) -> severity
_PRIO = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "low"}
# incident state codes -> readable status
_STATE = {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed", "8": "Canceled"}


def _scalar(v: Any) -> Any:
    # ServiceNow reference fields come back as {"value": "...", "link": "..."} unless display values requested.
    if isinstance(v, dict):
        return v.get("display_value") or v.get("value")
    return v


def _normalize(rows: List[Dict[str, Any]], instance: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        num = _scalar(r.get("number")) or _scalar(r.get("sys_id"))
        if not num:
            continue
        prio = str(_scalar(r.get("priority")) or "3").strip()[:1]
        state = str(_scalar(r.get("state")) or "").strip()
        sid = _scalar(r.get("sys_id"))
        url = f"https://{instance}/nav_to.do?uri=incident.do?sys_id={sid}" if instance and sid else None
        out.append({
            "external_id": str(num),
            "name": str(_scalar(r.get("short_description")) or num)[:300],
            "description": str(_scalar(r.get("description")) or "")[:4000],
            "severity": _PRIO.get(prio, "medium"),
            "status": _STATE.get(state, _scalar(r.get("state")) or state or None),
            "category": "Ticket",
            "assignee": _scalar(r.get("assigned_to")),
            "tags": _scalar(r.get("category")),
            "url": url,
            "asset": _scalar(r.get("cmdb_ci")),
            "created": _scalar(r.get("opened_at")) or _scalar(r.get("sys_created_on")),
        })
    return out


def _live(instance: str, user: str, pwd: str, table: str, query: str, limit: int) -> List[Dict[str, Any]]:
    instance = instance.replace("https://", "").replace("http://", "").strip("/")
    qs = urllib.parse.urlencode({
        "sysparm_limit": str(limit), "sysparm_query": query or "active=true",
        "sysparm_display_value": "true", "sysparm_exclude_reference_link": "true",
    })
    url = f"https://{instance}/api/now/table/{table}?{qs}"
    token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8", "replace") or "null")
    rows = data.get("result") if isinstance(data, dict) else data
    return _normalize(rows or [], instance)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    query = str(params.get("query") or "active=true")
    instance = (os.environ.get("SERVICENOW_INSTANCE") or "").strip()
    user = (os.environ.get("SERVICENOW_USER") or "").strip()
    pwd = os.environ.get("SERVICENOW_PASSWORD") or ""
    table = (os.environ.get("SERVICENOW_TABLE") or "incident").strip()

    if instance and user and pwd:
        alerts = _live(instance, user, pwd, table, query, limit)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        rows = data.get("result") if isinstance(data, dict) else data
        alerts = _normalize(rows or [], instance)
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
