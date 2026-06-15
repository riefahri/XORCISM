"""run.py — XORCISM connector: import entities from Intrigue Core.

Queries a running Intrigue Core instance's REST API for the discovered entities of
a project and maps them to the XORCISM findings model:
  • IpAddress                  -> ASSET (ip)
  • DnsRecord / Domain / Host  -> ASSET (hostname)
  • Uri                        -> ASSET (host) + service (the URL)

This module performs NO database access (so it also runs on a remote worker): it
returns the normalized result {assets, services, cpes, vulns:[]}.

Config (worker environment variables, never entered in the UI):
    INTRIGUE_CORE_URL    base URL of the Intrigue Core instance       (REQUIRED)
                         e.g. http://127.0.0.1:7777
    INTRIGUE_CORE_API_KEY  API key (sent as Bearer + ?api_key=)        (optional)
    INTRIGUE_VERIFY_TLS  "0"/"false" to skip TLS verification          (default: verify)

Offline / test mode:
    params["file"] = a saved JSON entities payload -> parsed instead of the API.
"""
from __future__ import annotations

import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    project = str(params.get("project") or "").strip()
    limit = int(params.get("limit", 2000) or 2000)
    if not project and not params.get("file"):
        raise RuntimeError("intrigue connector requires a 'project' parameter")

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    else:
        payload = _fetch(project, limit)

    entities = _find_entities(payload)
    return _map_entities(entities[:limit])


# ── Intrigue Core API ─────────────────────────────────────────────────────────
def _fetch(project: str, limit: int) -> Any:
    import requests

    base = (os.getenv("INTRIGUE_CORE_URL") or "").rstrip("/")
    if not base:
        raise RuntimeError("INTRIGUE_CORE_URL is required (worker env)")
    key = os.getenv("INTRIGUE_CORE_API_KEY") or ""
    verify = (os.getenv("INTRIGUE_VERIFY_TLS") or "1").strip().lower() not in ("0", "false", "no", "off")
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass

    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    query: Dict[str, Any] = {"limit": limit}
    if key:
        query["api_key"] = key

    enc = urllib.parse.quote(project, safe="")
    last_err: Optional[Exception] = None
    # Intrigue Core's project/entities path has varied across versions — try a few.
    for path in (f"/v1/projects/{enc}/entities", f"/v1/project/{enc}/entities",
                 f"/v1/{enc}/entities", f"/api/projects/{enc}/entities"):
        try:
            r = requests.get(base + path, headers=headers, params=query, timeout=120, verify=verify)
            if r.status_code == 200:
                return r.json()
            last_err = RuntimeError(f"{path} -> HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise RuntimeError(f"Intrigue Core API: no entities endpoint responded ({last_err})")


# ── Entity extraction + mapping ───────────────────────────────────────────────
def _find_entities(payload: Any) -> List[Dict[str, Any]]:
    """Find the list of entity objects anywhere in the API response."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        for k in ("entities", "data", "results", "items"):
            v = payload.get(k)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
        # fall back: a dict of {id: entity}
        vals = list(payload.values())
        if vals and all(isinstance(v, dict) for v in vals):
            return vals  # type: ignore[return-value]
    return []


def _type_of(e: Dict[str, Any]) -> str:
    t = e.get("type") or e.get("type_string") or e.get("entity_type") or ""
    return str(t).rsplit("::", 1)[-1].lower()  # Intrigue::Entity::IpAddress -> ipaddress


def _name_of(e: Dict[str, Any]) -> Optional[str]:
    n = e.get("name") or e.get("value") or (e.get("details") or {}).get("name")
    return str(n).strip() if n else None


def _map_entities(entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, Any]] = []

    def add_asset(name: str, ip: Optional[str] = None) -> None:
        a = assets.setdefault(name, {"hostname": name, "key": name})
        if ip and not a.get("ip"):
            a["ip"] = ip

    for e in entities:
        etype = _type_of(e)
        name = _name_of(e)
        if not name:
            continue
        if "ipaddress" in etype or etype == "ip":
            assets.setdefault(name, {"hostname": name, "ip": name, "key": name})
        elif "uri" in etype or "url" in etype:
            host = urllib.parse.urlparse(name if "://" in name else "//" + name).hostname or name
            add_asset(host)
            services.append({"asset": host, "cpe": name})
        elif any(k in etype for k in ("dnsrecord", "domain", "host", "nameserver", "aws", "netblock")):
            add_asset(name)
        else:
            # unknown entity (e.g. NetworkService "host:port") that looks like a host
            host = name.rsplit(":", 1)[0] if (":" in name and name.rsplit(":", 1)[-1].isdigit()) else name
            if "." in host and " " not in host:
                add_asset(host)
                if host != name:
                    services.append({"asset": host, "cpe": name})

    return {"assets": list(assets.values()), "services": services, "cpes": [], "vulns": []}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Intrigue Core entities import (dry run)")
    ap.add_argument("--file", help="Saved JSON entities payload instead of the live API")
    ap.add_argument("--project", default="dryrun")
    ap.add_argument("--limit", type=int, default=2000)
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project, "limit": a.limit}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[intrigue] {len(res['assets'])} asset(s), {len(res['services'])} service(s)", flush=True)
