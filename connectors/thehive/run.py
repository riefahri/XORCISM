"""run.py — XORCISM connector for TheHive (open-source SOAR / case management).

Imports TheHive alerts (or cases) into XORCISM as security alerts (XINCIDENT.ALERT via
runner.import_incidents). TheHive is one of the most-deployed open-source SOC case-management
platforms; bringing its alerts into XORCISM unifies them with the rest of the incident layer.

Modes (in order):
    live     : THEHIVE_URL + THEHIVE_API_KEY set -> TheHive 5 query API (POST /api/v1/query).
    offline  : params["file"] -> parse a saved TheHive alert-export JSON (list or {data:[...]}).
    demo     : neither -> import the bundled sample.json (clearly sample data).

Normalized result: {"source": "TheHive", "alerts": [ {external_id,name,description,severity,
    status,category,tags,url,attack,asset}, ... ]}. Worker-safe: stdlib only, secrets via env,
ASCII-only output.

Config (worker environment variables, never entered in the UI):
    THEHIVE_URL        base URL, e.g. https://thehive.lab        (live)
    THEHIVE_API_KEY    API key (sent as Bearer)                  (live)
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

TOOL_NAME = "TheHive"
SOURCE = "TheHive"
_SEV = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _http(url: str, method: str, headers: Dict[str, str], body: Any = None, timeout: int = 90) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _normalize(raw: List[Dict[str, Any]], base: str, kind: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for a in raw or []:
        if not isinstance(a, dict):
            continue
        ext = a.get("_id") or a.get("id") or a.get("sourceRef") or a.get("caseId")
        if not ext:
            continue
        sev = _SEV.get(int(a.get("severity") or 2), "medium")
        # impacted host from the first hostname/ip/fqdn observable, if any
        asset = None
        for ob in a.get("observables") or a.get("artifacts") or []:
            if isinstance(ob, dict) and ob.get("dataType") in ("hostname", "fqdn", "ip") and ob.get("data"):
                asset = str(ob["data"]); break
        url = f"{base}/{'case' if kind == 'case' else 'alert'}/{a.get('_id') or ext}/details" if base else None
        out.append({
            "external_id": str(ext),
            "name": str(a.get("title") or a.get("name") or ext)[:300],
            "description": str(a.get("description") or "")[:4000],
            "severity": sev,
            "status": a.get("status") or a.get("stage"),
            "category": "Case" if kind == "case" else "Alert",
            "tags": a.get("tags"),
            "assignee": a.get("assignee") or a.get("owner"),
            "url": url,
            "asset": asset,
            "created": a.get("date") or a.get("createdAt"),
        })
    return out


def _live(base: str, key: str, limit: int, kind: str) -> List[Dict[str, Any]]:
    base = base.rstrip("/")
    name = "listCase" if kind == "case" else "listAlert"
    query = {"query": [{"_name": name},
                       {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                       {"_name": "page", "from": 0, "to": int(limit)}]}
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    res = _http(f"{base}/api/v1/query", "POST", headers, query)
    rows = res if isinstance(res, list) else (res.get("data") if isinstance(res, dict) else []) or []
    return _normalize(rows, base, kind)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 200) or 200)
    kind = str(params.get("kind") or "alert").strip().lower()
    base = (os.environ.get("THEHIVE_URL") or "").strip()
    key = (os.environ.get("THEHIVE_API_KEY") or "").strip()

    if base and key:
        alerts = _live(base, key, limit, kind)
    else:
        path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        rows = data.get("data") if isinstance(data, dict) else data
        alerts = _normalize(rows or [], base, kind)
    return {"source": SOURCE, "alerts": alerts[:limit]}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
