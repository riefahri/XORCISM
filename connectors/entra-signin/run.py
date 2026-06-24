"""run.py - XORCISM inbound connector: Microsoft Entra ID sign-in logs -> IDENTITYSIGNIN.

Ingests Entra sign-in events (the continuous-verification telemetry for the Zero Trust Identity
pillar / UEBA session-risk). Emits a normalized `signins` list -> runner.import_signins.

Modes:
    file : `file` = an exported Entra sign-in log (a JSON array, or a Graph {"value":[...]} object).
    live : `token` or env GRAPH_TOKEN set -> GET https://graph.microsoft.com/v1.0/auditLogs/signIns.
    demo : neither -> a small built-in sample (so the import chain is testable with no credentials).

Read-only against Entra. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

GRAPH = "https://graph.microsoft.com/v1.0/auditLogs/signIns"

_DEMO = [
    {"id": "d1", "userPrincipalName": "alice@contoso.com", "createdDateTime": "2026-06-24T08:00:00Z", "ipAddress": "203.0.113.5",
     "location": {"countryOrRegion": "US", "city": "Seattle"}, "deviceDetail": {"displayName": "ALICE-LT", "operatingSystem": "Windows"},
     "appDisplayName": "Office 365", "clientAppUsed": "Browser", "authenticationRequirement": "multiFactorAuthentication",
     "status": {"errorCode": 0, "failureReason": ""}, "riskLevelDuringSignIn": "none"},
    {"id": "d2", "userPrincipalName": "alice@contoso.com", "createdDateTime": "2026-06-24T09:00:00Z", "ipAddress": "198.51.100.9",
     "location": {"countryOrRegion": "RU", "city": "Moscow"}, "deviceDetail": {"displayName": "", "operatingSystem": "Linux"},
     "appDisplayName": "Office 365", "clientAppUsed": "Browser", "authenticationRequirement": "singleFactorAuthentication",
     "status": {"errorCode": 0, "failureReason": ""}, "riskLevelDuringSignIn": "medium"},
    {"id": "d3", "userPrincipalName": "svc-backup@contoso.com", "createdDateTime": "2026-06-24T03:00:00Z", "ipAddress": "10.0.0.9",
     "location": {"countryOrRegion": "US", "city": ""}, "deviceDetail": {"displayName": "", "operatingSystem": ""},
     "appDisplayName": "Azure CLI", "clientAppUsed": "Mobile Apps and Desktop clients", "authenticationRequirement": "singleFactorAuthentication",
     "status": {"errorCode": 0, "failureReason": ""}, "riskLevelDuringSignIn": "none"},
]


def _normalize(rec: Dict[str, Any]) -> Dict[str, Any]:
    loc = rec.get("location") or {}
    dev = rec.get("deviceDetail") or {}
    st = rec.get("status") or {}
    err = st.get("errorCode")
    mfa = "yes" if str(rec.get("authenticationRequirement") or "").lower() == "multifactorauthentication" else "no"
    return {
        "id": rec.get("id"),
        "user": rec.get("userPrincipalName") or rec.get("userDisplayName"),
        "timestamp": rec.get("createdDateTime"),
        "ip": rec.get("ipAddress"),
        "country": loc.get("countryOrRegion"),
        "city": loc.get("city"),
        "device": dev.get("displayName") or dev.get("operatingSystem"),
        "client_app": rec.get("appDisplayName") or rec.get("clientAppUsed"),
        "mfa": mfa,
        "result": "success" if (err in (0, None) and not st.get("failureReason")) else "failure",
        "failure_reason": st.get("failureReason") or None,
        "risk": rec.get("riskLevelDuringSignIn") or rec.get("riskLevelAggregated"),
    }


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("value", data) if isinstance(data, dict) else data
    token = (str(params.get("token") or "").strip() or os.environ.get("GRAPH_TOKEN", "").strip())
    if token:
        top = int(params.get("top") or 200)
        req = urllib.request.Request(f"{GRAPH}?$top={top}", headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return (json.loads(resp.read().decode("utf-8")) or {}).get("value", [])
    return list(_DEMO)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    records = _load(params)
    signins = [_normalize(r) for r in records if isinstance(r, dict)]
    signins = [s for s in signins if s.get("id") and s.get("user")]
    return {"source": "Microsoft Entra ID", "signins": signins, "count": len(signins)}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
