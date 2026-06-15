"""run.py — Import of Elastic Security detection alerts (Elasticsearch API).

Queries the alerts index over the requested window; normalizes each alert:
host.name/host.ip → ASSET; detection rule → linked finding.

Config (worker environment variables, never entered in the UI):
    ELASTIC_URL         Elasticsearch endpoint, e.g. https://es.lab:9200  (REQUIRED)
    ELASTIC_API_KEY     API key (Authorization: ApiKey …)                (REQUIRED)
    ELASTIC_INDEX       alerts index (default .alerts-security.alerts-default)
    ELASTIC_VERIFY_TLS  true/false (default true)

Normalized result: {assets, services:[], cpes:[], vulns}.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes")


def _get(src: Dict[str, Any], path: str) -> Optional[Any]:
    """Reads a dotted key (host.name) in flattened OR nested form."""
    if path in src:
        return src[path]
    cur: Any = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(v: Any) -> str:
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return "" if v is None else str(v)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    base = (os.getenv("ELASTIC_URL") or "").rstrip("/")
    api_key = os.getenv("ELASTIC_API_KEY")
    if not base or not api_key:
        raise RuntimeError("ELASTIC_URL et ELASTIC_API_KEY requis (variables d'environnement du worker)")
    index = os.getenv("ELASTIC_INDEX", ".alerts-security.alerts-default")
    verify = _env_bool("ELASTIC_VERIFY_TLS", True)
    since = int(params.get("since_hours", 24) or 24)
    limit = int(params.get("limit", 200) or 200)

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": f"now-{since}h"}}},
    }
    r = requests.post(
        f"{base}/{index}/_search",
        headers={"Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"},
        json=body, verify=verify, timeout=120,
    )
    r.raise_for_status()
    hits = (((r.json() or {}).get("hits") or {}).get("hits")) or []

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for hit in hits:
        src = hit.get("_source") or {}
        host = _first(_get(src, "host.name")) or _first(_get(src, "host.ip"))
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "ip": _first(_get(src, "host.ip")) or host, "key": host})
        name = (_first(_get(src, "kibana.alert.rule.name")) or
                _first(_get(src, "signal.rule.name")) or "Elastic alert")
        sev = (_first(_get(src, "kibana.alert.severity")) or
               _first(_get(src, "signal.rule.severity")) or "medium").lower()
        uuid = (_first(_get(src, "kibana.alert.uuid")) or hit.get("_id") or "")
        ref = f"ELASTIC-{uuid}" if uuid else f"ELASTIC-{host}-{name}"[:60]
        vulns.append({"asset": host, "ref": ref, "name": name[:200], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
