"""run.py — Import of Splunk notable events / alerts via the REST API.

Runs a "oneshot" search over the requested window, normalizes each
result: host (host/dest/src) → ASSET; alert → linked finding.

Config (worker environment variables, never entered in the UI):
    SPLUNK_URL         REST API base, e.g. https://splunk.lab:8089       (REQUIRED)
    SPLUNK_TOKEN       Bearer token (Authorization: Bearer …)           (REQUIRED)
    SPLUNK_QUERY       search (default "search index=notable")
    SPLUNK_VERIFY_TLS  true/false (default true)

Normalized result: {assets:[{hostname,ip,key}], services:[], cpes:[],
                      vulns:[{asset,ref,name,severity}]}.
"""
from __future__ import annotations
import hashlib
import os
from typing import Any, Dict, List


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests  # dependency already present on the worker side

    base = (os.getenv("SPLUNK_URL") or "").rstrip("/")
    token = os.getenv("SPLUNK_TOKEN")
    if not base or not token:
        raise RuntimeError("SPLUNK_URL et SPLUNK_TOKEN requis (variables d'environnement du worker)")
    query = os.getenv("SPLUNK_QUERY", "search index=notable")
    verify = _env_bool("SPLUNK_VERIFY_TLS", True)
    since = int(params.get("since_hours", 24) or 24)
    limit = int(params.get("limit", 200) or 200)

    r = requests.post(
        f"{base}/services/search/jobs/oneshot",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "search": f"{query} | head {limit}",
            "earliest_time": f"-{since}h",
            "latest_time": "now",
            "output_mode": "json",
            "count": str(limit),
        },
        verify=verify, timeout=120,
    )
    r.raise_for_status()
    results = (r.json() or {}).get("results", []) or []

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for ev in results:
        if not isinstance(ev, dict):
            continue
        host = (ev.get("host") or ev.get("dest") or ev.get("dest_ip") or
                ev.get("src") or ev.get("src_ip") or "").strip()
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "ip": host, "key": host})
        name = (ev.get("rule_name") or ev.get("search_name") or ev.get("signature") or
                ev.get("source") or "Splunk alert").strip()
        sev = str(ev.get("urgency") or ev.get("severity") or "medium").lower()
        rid = ev.get("event_id") or ev.get("_cd") or ev.get("rule_id")
        ref = f"SPLUNK-{rid}" if rid else "SPLUNK-" + hashlib.sha1(
            f"{host}|{name}".encode("utf-8")).hexdigest()[:12]
        vulns.append({"asset": host, "ref": ref, "name": name[:200], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
