"""run.py — Import of Wiz Issues via the GraphQL API.

OAuth2 authentication (client_credentials, audience wiz-api) then GraphQL
query of the open issues. entitySnapshot.name → ASSET; issue → finding.

Config (worker environment variables, never entered in the UI):
    WIZ_CLIENT_ID      service app identifier                  (REQUIRED)
    WIZ_CLIENT_SECRET  secret                                  (REQUIRED)
    WIZ_API_URL        GraphQL endpoint, e.g. https://api.<region>.app.wiz.io/graphql  (REQUIRED)
    WIZ_AUTH_URL       default https://auth.app.wiz.io/oauth/token

Normalized result: {assets, services:[], cpes:[], vulns}.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List

_QUERY = """
query Issues($first: Int) {
  issues(first: $first, filterBy: {status: [OPEN, IN_PROGRESS]}) {
    nodes {
      id
      severity
      entitySnapshot { name type }
      sourceRule { __typename ... on Control { name } ... on CloudConfigurationRule { name } }
    }
  }
}
"""


def _sev(v: Any) -> str:
    return str(v or "medium").lower()


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    import requests

    cid = os.getenv("WIZ_CLIENT_ID")
    secret = os.getenv("WIZ_CLIENT_SECRET")
    api_url = (os.getenv("WIZ_API_URL") or "").rstrip("/")
    if not cid or not secret or not api_url:
        raise RuntimeError("WIZ_CLIENT_ID, WIZ_CLIENT_SECRET et WIZ_API_URL requis (env worker)")
    auth_url = os.getenv("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token")
    limit = int(params.get("limit", 200) or 200)

    tok = requests.post(
        auth_url,
        data={"grant_type": "client_credentials", "client_id": cid,
              "client_secret": secret, "audience": "wiz-api"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=60,
    )
    tok.raise_for_status()
    access = (tok.json() or {}).get("access_token")
    if not access:
        raise RuntimeError("Échec de l'authentification Wiz (pas d'access_token)")

    r = requests.post(
        api_url,
        headers={"Authorization": f"Bearer {access}", "Content-Type": "application/json"},
        json={"query": _QUERY, "variables": {"first": min(limit, 500)}}, timeout=120,
    )
    r.raise_for_status()
    body = r.json() or {}
    if body.get("errors"):
        raise RuntimeError("Erreur GraphQL Wiz : " + str(body["errors"])[:200])
    nodes = (((body.get("data") or {}).get("issues") or {}).get("nodes")) or []

    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for n in nodes:
        ent = n.get("entitySnapshot") or {}
        host = str(ent.get("name") or "").strip()
        if not host:
            continue
        assets.setdefault(host, {"hostname": host, "key": host})
        rule = (n.get("sourceRule") or {}).get("name") or "Wiz issue"
        ref = f"WIZ-{n.get('id')}" if n.get("id") else f"WIZ-{host}-{rule}"[:60]
        vulns.append({"asset": host, "ref": ref, "name": str(rule)[:200], "severity": _sev(n.get("severity"))})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}
