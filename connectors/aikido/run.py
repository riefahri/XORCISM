"""run.py — Import Aikido Security issues via the public API v1.

Authenticates with OAuth2 client_credentials (clientId/clientSecret -> bearer token),
then fetches issues (SCA / SAST / DAST / IaC / secrets / cloud). A code repository or
cloud resource becomes an ASSET; each issue (CVE or rule) becomes a linked finding.

Config (worker environment variables, never entered in the UI):
    AIKIDO_CLIENT_ID      API token client id        (REQUIRED)
    AIKIDO_CLIENT_SECRET  API token client secret    (REQUIRED)
    AIKIDO_API_URL        base URL (default https://app.aikido.dev)

Normalized result: {assets, services:[], cpes:[], vulns}. The exact Aikido field names
can vary by issue source, so extraction is defensive (multiple fallbacks).
"""
from __future__ import annotations
import base64
import os
from typing import Any, Dict, List

SEVERITIES = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def _asset_of(issue: Dict[str, Any]) -> str:
    for k in ("code_repo_name", "repository_name", "container_repo_name",
              "cloud_name", "domain", "group_name", "affected_package"):
        v = issue.get(k)
        if v:
            return str(v)
    for k in ("code_repository", "repository", "cloud"):
        sub = issue.get(k)
        if isinstance(sub, dict) and sub.get("name"):
            return str(sub["name"])
    return str(issue.get("id") or "aikido")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    cid = os.getenv("AIKIDO_CLIENT_ID")
    secret = os.getenv("AIKIDO_CLIENT_SECRET")
    base = (os.getenv("AIKIDO_API_URL") or "https://app.aikido.dev").rstrip("/")
    if not cid or not secret:
        raise RuntimeError("AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET required (worker env)")
    limit = int(params.get("limit", 500) or 500)
    status = str(params.get("status", "open") or "open")

    # 1) OAuth2 client_credentials -> bearer token
    basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    tok = requests.post(
        f"{base}/api/oauth/token",
        headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials"}, timeout=60,
    )
    tok.raise_for_status()
    token = (tok.json() or {}).get("access_token")
    if not token:
        raise RuntimeError("Aikido authentication failed (no access_token)")

    # 2) Issues export
    query: Dict[str, Any] = {"format": "json", "per_page": min(limit, 1000)}
    if status and status != "all":
        query["filter_status"] = status
    r = requests.get(
        f"{base}/api/public/v1/issues/export",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        params=query, timeout=120,
    )
    r.raise_for_status()
    payload = r.json()
    issues = payload if isinstance(payload, list) else (payload.get("issues") or payload.get("data") or [])

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for it in issues[:limit]:
        if not isinstance(it, dict):
            continue
        asset = _asset_of(it)
        cve = str(it.get("cve_id") or it.get("cve") or "").strip()
        rule = str(it.get("rule") or it.get("type") or it.get("title") or "Aikido issue").strip()
        issue_id = str(it.get("id") or rule)
        ref = cve if cve.upper().startswith("CVE-") else f"AIKIDO-{issue_id[:60]}"
        sev = SEVERITIES.get(str(it.get("severity") or "medium").lower(), "medium")
        name = (cve or rule)[:200]
        assets.setdefault(asset, {"hostname": asset, "key": asset})
        vulns.append({"asset": asset, "ref": ref, "name": name, "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
