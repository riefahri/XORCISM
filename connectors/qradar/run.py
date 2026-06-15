"""run.py — Import of IBM QRadar offenses via the REST API.

GET /api/siem/offenses (filtered on last_updated_time); normalizes each
offense: offense_source → ASSET; offense → linked finding.

Config (worker environment variables, never entered in the UI):
    QRADAR_URL         base, e.g. https://qradar.lab                       (REQUIRED)
    QRADAR_TOKEN       authorization token ("SEC" header)                 (REQUIRED)
    QRADAR_VERIFY_TLS  true/false (default true)

Normalized result: {assets, services:[], cpes:[], vulns}.
"""
from __future__ import annotations
import os
import time
from typing import Any, Dict, List

_SEV = {1: "low", 2: "low", 3: "low", 4: "medium", 5: "medium", 6: "medium",
        7: "high", 8: "high", 9: "critical", 10: "critical"}


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    base = (os.getenv("QRADAR_URL") or "").rstrip("/")
    token = os.getenv("QRADAR_TOKEN")
    if not base or not token:
        raise RuntimeError("QRADAR_URL et QRADAR_TOKEN requis (variables d'environnement du worker)")
    verify = _env_bool("QRADAR_VERIFY_TLS", True)
    since = int(params.get("since_hours", 24) or 24)
    limit = int(params.get("limit", 200) or 200)
    since_ms = int((time.time() - since * 3600) * 1000)

    r = requests.get(
        f"{base}/api/siem/offenses",
        headers={"SEC": token, "Accept": "application/json", "Version": "12.0",
                 "Range": f"items=0-{limit - 1}"},
        params={
            "filter": f"last_updated_time > {since_ms}",
            "fields": "id,description,offense_source,magnitude,severity,status,offense_type",
        },
        verify=verify, timeout=120,
    )
    r.raise_for_status()
    offenses = r.json() or []

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for off in offenses:
        if not isinstance(off, dict):
            continue
        host = str(off.get("offense_source") or "").strip()
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "ip": host, "key": host})
        name = str(off.get("description") or "QRadar offense").strip().replace("\n", " ")
        sev = _SEV.get(int(off.get("severity") or off.get("magnitude") or 5), "medium")
        ref = f"QRADAR-{off.get('id')}" if off.get("id") is not None else f"QRADAR-{host}"
        vulns.append({"asset": host, "ref": ref, "name": name[:200], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
