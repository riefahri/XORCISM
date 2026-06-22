"""run.py — XORCISM connector for Cyera (Data Security Posture Management / DSPM).

Cyera (https://www.cyera.com) discovers, classifies and protects sensitive data across cloud,
SaaS and on-prem. This connector imports its inventory + risks into XORCISM:
  * each data store  -> ASSET  (name + engine/type + cloud, sensitivity carried as a finding tag)
  * each data risk / issue -> a finding (VULNERABILITY) attached to its data store
so sensitive-data exposure shows up alongside the rest of the attack surface.

Modes (in order):
    live    : CYERA_CLIENT_ID + CYERA_CLIENT_SECRET -> OAuth2 client-credentials login (JWT) then
              GET data stores + issues from CYERA_API_URL (default https://api.cyera.io).
    offline : params["file"] -> parse a saved Cyera export ({datastores, issues} / results / list).
    demo    : neither -> import the bundled sample.json.

Normalized result: {project?, assets:[...], vulns:[...]} -> runner.import_findings. Worker-safe:
stdlib only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}


def _sev(s: Any) -> str:
    return _SEV.get(str(s or "").strip().lower(), "medium")


def _http(url: str, method: str, headers: Dict[str, str], body: Any = None, timeout: int = 90) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _rows(data: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in keys + ("results", "data", "items", "content"):
            v = data.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _store_name(d: Dict[str, Any]) -> str:
    return str(d.get("name") or d.get("displayName") or d.get("resourceName") or d.get("uid") or d.get("id") or "data-store")


def _normalize(datastores: List[Dict[str, Any]], issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    assets: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []
    by_id: Dict[str, str] = {}
    for d in datastores:
        name = _store_name(d)
        sid = str(d.get("id") or d.get("uid") or name)
        by_id[sid] = name
        cloud = d.get("cloudProvider") or d.get("provider") or d.get("platform")
        engine = d.get("engine") or d.get("type") or d.get("datastoreType")
        assets.append({"hostname": name, "key": name, "os": str(engine or "") or None,
                       "tags": ",".join(filter(None, ["cyera", "dspm", str(cloud or ""), str(engine or "")]))})
        # a highly-sensitive store with no explicit issue still warrants a finding
        sens = str(d.get("sensitivity") or d.get("sensitivityLevel") or "").lower()
        classes = d.get("classifications") or d.get("dataClasses") or []
        if sens in ("critical", "high") or (isinstance(classes, list) and len(classes) >= 1):
            label = ", ".join(str(c.get("name") if isinstance(c, dict) else c) for c in classes[:6]) if isinstance(classes, list) else ""
            vulns.append({"asset": name, "ref": f"CYERA-STORE-{sid}",
                          "name": f"Sensitive data store ({sens or 'classified'})" + (f": {label}" if label else ""),
                          "severity": _sev(sens or "medium")})
    for it in issues:
        ds = it.get("datastore") or it.get("dataStore") or it.get("resource") or {}
        ds_name = (_store_name(ds) if isinstance(ds, dict) else str(ds)) if ds else None
        ds_id = str((ds.get("id") if isinstance(ds, dict) else None) or it.get("datastoreId") or "")
        asset = ds_name or by_id.get(ds_id) or (assets[0]["hostname"] if assets else "cyera")
        iid = str(it.get("id") or it.get("uid") or it.get("name") or "")
        title = str(it.get("name") or it.get("title") or it.get("category") or "Data risk")
        vulns.append({"asset": asset, "ref": f"CYERA-{iid}" if iid else f"CYERA-{title}"[:60],
                      "name": f"{title}" + (f" — {it.get('category')}" if it.get("category") and it.get("category") != title else ""),
                      "severity": _sev(it.get("severity") or it.get("risk"))})
    return {"project": "Cyera DSPM", "assets": assets, "services": [], "cpes": [], "vulns": vulns}


def _live(base: str, cid: str, secret: str, limit: int) -> Dict[str, Any]:
    base = base.rstrip("/")
    tok = _http(f"{base}/v1/login", "POST", {"Content-Type": "application/json"}, {"clientId": cid, "clientSecret": secret})
    jwt = (tok or {}).get("jwt") or (tok or {}).get("access_token") or (tok or {}).get("token")
    if not jwt:
        raise RuntimeError("Cyera login returned no JWT")
    h = {"Authorization": f"Bearer {jwt}", "Accept": "application/json"}
    stores: List[Dict[str, Any]] = []
    for path in (f"/v3/datastores?limit={limit}", f"/v1/datastores?limit={limit}", "/v3/datastores"):
        try:
            stores = _rows(_http(f"{base}{path}", "GET", h), "datastores");
            if stores:
                break
        except Exception:  # noqa: BLE001
            continue
    issues: List[Dict[str, Any]] = []
    for path in (f"/v1/issues?limit={limit}", f"/v3/issues?limit={limit}", "/v1/issues"):
        try:
            issues = _rows(_http(f"{base}{path}", "GET", h), "issues")
            if issues:
                break
        except Exception:  # noqa: BLE001
            continue
    return _normalize(stores[:limit], issues[:limit])


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    base = (os.environ.get("CYERA_API_URL") or "https://api.cyera.io").strip()
    cid = (os.environ.get("CYERA_CLIENT_ID") or "").strip()
    secret = (os.environ.get("CYERA_CLIENT_SECRET") or "").strip()
    if cid and secret:
        return _live(base, cid, secret, limit)
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    stores = _rows(data, "datastores", "dataStores") or _rows(data.get("datastores") if isinstance(data, dict) else None)
    issues = _rows(data, "issues") or _rows(data.get("issues") if isinstance(data, dict) else None)
    if not stores and not issues and isinstance(data, list):
        stores = _rows(data)
    return _normalize(stores[:limit], issues[:limit])


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
