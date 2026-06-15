"""run.py — Import of Lacework host vulnerabilities via the v2 API.

Obtains a temporary token (keyId + secret) then queries the host
vulnerabilities over the requested window. Host → ASSET; vulnId (CVE) → linked finding.

Config (worker environment variables, never entered in the UI):
    LACEWORK_ACCOUNT   e.g. mycompany (or mycompany.lacework.net)  (REQUIRED)
    LACEWORK_KEY_ID    API key identifier                          (REQUIRED)
    LACEWORK_SECRET    API key secret                              (REQUIRED)

Normalized result: {assets, services:[], cpes:[], vulns}.
"""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


def _host_of(item: Dict[str, Any]) -> str:
    tags = item.get("machineTags") or {}
    if isinstance(tags, dict):
        for k in ("Hostname", "hostname", "Name", "InstanceId"):
            if tags.get(k):
                return str(tags[k])
    ev = item.get("evalCtx") or {}
    if isinstance(ev, dict) and ev.get("hostname"):
        return str(ev["hostname"])
    return str(item.get("mid") or "")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    account = (os.getenv("LACEWORK_ACCOUNT") or "").strip()
    key_id = os.getenv("LACEWORK_KEY_ID")
    secret = os.getenv("LACEWORK_SECRET")
    if not account or not key_id or not secret:
        raise RuntimeError("LACEWORK_ACCOUNT, LACEWORK_KEY_ID et LACEWORK_SECRET requis (env worker)")
    host = account if "." in account else f"{account}.lacework.net"
    base = f"https://{host}"
    since = int(params.get("since_hours", 24) or 24)
    limit = int(params.get("limit", 500) or 500)

    # 1) Temporary token
    tok = requests.post(
        f"{base}/api/v2/access/tokens",
        headers={"X-LW-UAKS": secret, "Content-Type": "application/json", "Accept": "application/json"},
        json={"keyId": key_id, "expiryTime": 3600}, timeout=60,
    )
    tok.raise_for_status()
    token = (tok.json() or {}).get("token")
    if not token:
        raise RuntimeError("Échec de l'authentification Lacework (pas de token)")

    # 2) Host vulnerabilities (time window)
    now = datetime.now(timezone.utc)
    body = {
        "timeFilter": {
            "startTime": (now - timedelta(hours=since)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    }
    r = requests.post(
        f"{base}/api/v2/Vulnerabilities/Hosts/search",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body, timeout=120,
    )
    r.raise_for_status()
    data = (r.json() or {}).get("data", []) or []

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for it in data[:limit]:
        if not isinstance(it, dict):
            continue
        h = _host_of(it)
        cve = str(it.get("vulnId") or it.get("cveId") or "").strip()
        if not h or not cve:
            continue
        assets.setdefault(h, {"hostname": h, "key": h})
        ref = cve if cve.upper().startswith("CVE-") else f"LACEWORK-{cve}"
        sev = str(it.get("severity") or "medium").lower()
        vulns.append({"asset": h, "ref": ref, "name": cve[:200], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
