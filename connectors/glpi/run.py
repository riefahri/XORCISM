"""run.py — XORCISM connector for GLPI (IT Asset Management / CMDB) -> Asset inventory.

GLPI (https://glpi-project.org) is an open-source IT Service Management & asset-management
suite (CMDB + helpdesk). This connector imports its inventory into XORCISM:
  * each Computer / NetworkEquipment / Phone / Printer -> ASSET (network discovery), carrying
    its operating system (when available) and serial as the asset address/notes.
So the authoritative IT estate from GLPI shows up alongside the rest of the attack surface and
can be enriched (CVE matching, monitoring, BIA, ...).

Modes (in order):
    live    : GLPI_URL + GLPI_APP_TOKEN + GLPI_USER_TOKEN -> the REST API (initSession ->
              GET /Computer, /NetworkEquipment, ... -> killSession) at <GLPI_URL>/apirest.php.
    offline : params["file"] -> a saved GLPI export ({Computer, NetworkEquipment, ...} / a GLPI
              API list response / a flat item list).
    demo    : neither -> the bundled sample.json.

Normalized result: {project?, assets, source} -> runner.import_findings. Worker-safe: stdlib
only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

TOOL_NAME = "GLPI"
TOOL_URL = "https://glpi-project.org"
SOURCE = "GLPI"

# GLPI item types imported as assets (CMDB hardware) -> nothing here is a tool-runner.
_ITEM_TYPES = ["Computer", "NetworkEquipment", "Phone", "Printer", "Peripheral"]


def _http(url: str, headers: Dict[str, str], method: str = "GET", timeout: int = 60) -> Any:
    req = urllib.request.Request(url, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body) if body.strip() else {}


def _api_base(params: Dict[str, Any]) -> str:
    u = (params.get("url") or os.environ.get("GLPI_URL") or "").strip().rstrip("/")
    if u.endswith("apirest.php"):
        return u
    return u + "/apirest.php"


def _from_api(params: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    base = _api_base(params)
    app_token = (os.environ.get("GLPI_APP_TOKEN") or "").strip()
    user_token = (os.environ.get("GLPI_USER_TOKEN") or "").strip()
    init_headers = {"App-Token": app_token, "Authorization": "user_token " + user_token, "Content-Type": "application/json"}
    sess = _http(base + "/initSession", init_headers)
    session_token = (sess or {}).get("session_token") if isinstance(sess, dict) else None
    if not session_token:
        raise RuntimeError("GLPI initSession returned no session_token (check GLPI_APP_TOKEN / GLPI_USER_TOKEN)")
    headers = {"App-Token": app_token, "Session-Token": session_token, "Content-Type": "application/json"}
    out: Dict[str, List[Dict[str, Any]]] = {}
    try:
        for itype in _ITEM_TYPES:
            try:
                rows = _http(base + "/" + itype + "?range=0-999&expand_dropdowns=true", headers)
            except Exception as e:  # noqa: BLE001 (a disabled item type 4xx must not abort the run)
                print("[glpi] %s: %s" % (itype, e))
                continue
            if isinstance(rows, list):
                out[itype] = rows
            elif isinstance(rows, dict) and isinstance(rows.get("data"), list):
                out[itype] = rows["data"]
    finally:
        try:
            _http(base + "/killSession", headers)
        except Exception:  # noqa: BLE001
            pass
    return out


def _str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _os_name(rec: Dict[str, Any]) -> Optional[str]:
    # expand_dropdowns gives a name; otherwise it's a numeric id we ignore. Also accept explicit keys.
    for k in ("operatingsystems_id", "operatingsystem", "os"):
        v = rec.get(k)
        if isinstance(v, str) and v and not v.isdigit():
            return v
    return None


def _map_item(rec: Dict[str, Any], itype: str, assets: List[Dict[str, Any]]) -> None:
    name = _str(rec.get("name")) or _str(rec.get("completename")) or (("GLPI-" + itype + "-" + str(rec.get("id"))) if rec.get("id") is not None else None)
    if not name:
        return
    ip = _str(rec.get("ip")) or _str(rec.get("networkport_ip"))
    assets.append({"hostname": name, "key": name, "ip": ip, "os": _os_name(rec)})


def _normalize(buckets: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    assets: List[Dict[str, Any]] = []
    for itype, rows in buckets.items():
        for rec in rows or []:
            if isinstance(rec, dict):
                _map_item(rec, itype, assets)
    # de-dupe by name (a host may appear under several item types)
    seen: Dict[str, Dict[str, Any]] = {}
    for a in assets:
        seen.setdefault(a["key"], a)
    return {"project": "GLPI CMDB", "assets": list(seen.values()), "services": [], "cpes": [], "vulns": [], "source": SOURCE}


def _from_export(data: Any) -> Dict[str, List[Dict[str, Any]]]:
    if isinstance(data, dict):
        # {Computer:[...], NetworkEquipment:[...]} or a single GLPI API {data:[...]} page.
        if any(k in data for k in _ITEM_TYPES):
            return {k: data.get(k) or [] for k in _ITEM_TYPES if isinstance(data.get(k), list)}
        if isinstance(data.get("data"), list):
            return {"Computer": data["data"]}
        return {"Computer": [data]}
    if isinstance(data, list):
        return {"Computer": data}
    return {}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            buckets = _from_export(json.load(fh))
    elif (params.get("url") or os.environ.get("GLPI_URL")):
        buckets = _from_api(params)
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8") as fh:
            buckets = _from_export(json.load(fh))
    out = _normalize(buckets)
    print("[glpi] %d asset(s) from %d item type(s)" % (len(out["assets"]), len(buckets)))
    return out


if __name__ == "__main__":
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(run(p, "."), indent=2)[:2000])
