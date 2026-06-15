"""run.py — Import of Microsoft Sentinel incidents via the Azure Management API.

OAuth2 authentication (client_credentials) then GET of the Sentinel incidents.
Each incident becomes a finding attached to a "<workspace>" asset.

Config (worker environment variables, never entered in the UI):
    SENTINEL_TENANT_ID        Entra ID tenant ID                  (REQUIRED)
    SENTINEL_CLIENT_ID        app registration (client_id)        (REQUIRED)
    SENTINEL_CLIENT_SECRET    client secret                       (REQUIRED)
    SENTINEL_SUBSCRIPTION_ID  Azure subscription                  (REQUIRED)
    SENTINEL_RESOURCE_GROUP   resource group                      (REQUIRED)
    SENTINEL_WORKSPACE_NAME   Log Analytics workspace name        (REQUIRED)

Normalized result: {project, assets:[], services:[], cpes:[],
                      vulns:[{asset,ref,name,severity}]}.
"""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_REQUIRED = [
    "SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET",
    "SENTINEL_SUBSCRIPTION_ID", "SENTINEL_RESOURCE_GROUP", "SENTINEL_WORKSPACE_NAME",
]
_SEV = {"informational": "info", "low": "low", "medium": "medium",
        "high": "high"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    cfg = {k: os.getenv(k) for k in _REQUIRED}
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        raise RuntimeError("Variables d'environnement requises manquantes : " + ", ".join(missing))
    since = int(params.get("since_hours", 24) or 24)
    limit = int(params.get("limit", 200) or 200)
    workspace = cfg["SENTINEL_WORKSPACE_NAME"]

    # 1) OAuth2 token (client_credentials)
    tok = requests.post(
        f"https://login.microsoftonline.com/{cfg['SENTINEL_TENANT_ID']}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": cfg["SENTINEL_CLIENT_ID"],
            "client_secret": cfg["SENTINEL_CLIENT_SECRET"],
            "scope": "https://management.azure.com/.default",
        },
        timeout=60,
    )
    tok.raise_for_status()
    access = (tok.json() or {}).get("access_token")
    if not access:
        raise RuntimeError("Échec de l'authentification Azure (pas d'access_token)")

    # 2) Sentinel incidents (filtered on the time window)
    since_iso = (datetime.now(timezone.utc) - timedelta(hours=since)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (f"https://management.azure.com/subscriptions/{cfg['SENTINEL_SUBSCRIPTION_ID']}"
           f"/resourceGroups/{cfg['SENTINEL_RESOURCE_GROUP']}"
           f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
           f"/providers/Microsoft.SecurityInsights/incidents")
    r = requests.get(
        url,
        headers={"Authorization": f"Bearer {access}"},
        params={"api-version": "2023-11-01", "$top": str(limit),
                "$filter": f"properties/lastModifiedTimeUtc ge {since_iso}"},
        timeout=120,
    )
    r.raise_for_status()
    incidents = (r.json() or {}).get("value", []) or []

    vulns: List[Dict[str, Any]] = []
    for inc in incidents:
        props = (inc or {}).get("properties") or {}
        title = str(props.get("title") or "Sentinel incident").strip()
        sev = _SEV.get(str(props.get("severity") or "medium").lower(), "medium")
        num = props.get("incidentNumber") or inc.get("name")
        ref = f"SENTINEL-{num}" if num else f"SENTINEL-{title}"[:60]
        vulns.append({"asset": workspace, "ref": ref, "name": title[:200], "severity": sev})

    # project → "workspace" asset to which the incidents are attached
    return {"project": workspace, "assets": [], "services": [], "cpes": [], "vulns": vulns}
