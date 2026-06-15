"""run.py — Import Rudder nodes & compliance via the Rudder REST API.

Rudder (https://www.rudder.io) is a continuous configuration-management and
compliance platform. This connector pulls managed nodes (inventory) and their
configuration-compliance state and maps them to the XORCISM findings model:

  * each managed node            -> ASSET (hostname, IP, OS)
  * installed software (opt-in)  -> CPE linked to the node
  * each rule a node is NOT fully compliant with -> finding
        (ref = RUDDER-<ruleId>, severity derived from the compliance %)

Config (worker environment variables, never entered in the UI):
    RUDDER_URL         base URL of the Rudder server                 (REQUIRED)
                       e.g. https://rudder.example.com  (the /rudder/api/latest
                       path is appended automatically if omitted)
    RUDDER_API_TOKEN   API token (Administration -> API accounts)    (REQUIRED)
    RUDDER_VERIFY_TLS  "0"/"false" to skip TLS verification          (default: verify)
                       (Rudder servers often use a self-signed certificate)

Normalized result: {assets, services, cpes:[], vulns}. Rudder field names vary a
little between versions, so extraction is defensive (multiple fallbacks).

Offline / test mode:
    params["file"] = a saved JSON with optional {"nodes":[...], "compliance":[...]}
    arrays (the .data.nodes payloads) -> parsed instead of calling the API.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple


# ── Public entry point ────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    scope = str(params.get("scope", "all") or "all")
    limit = int(params.get("limit", 1000) or 1000)
    min_compliance = float(params.get("min_compliance", 100) or 100)
    include_software = bool(params.get("include_software", False))

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            data = json.load(fh)
        nodes = (data.get("nodes") or [])[:limit]
        comp_nodes = (data.get("compliance") or [])[:limit]
    else:
        base, token, verify = _config()
        nodes = _fetch_nodes(base, token, verify, limit, include_software) if scope in ("nodes", "all") else []
        comp_nodes = _fetch_compliance(base, token, verify, limit) if scope in ("compliance", "all") else []

    assets, services = _assets_and_services(nodes, include_software)
    have = {a["key"] for a in assets}
    for cn in comp_nodes:  # compliance-only nodes still become assets
        nid = str(cn.get("id") or "")
        if nid and nid not in have:
            assets.append({"hostname": cn.get("hostname") or cn.get("name") or nid, "key": nid})
            have.add(nid)
    vulns = _vulns_from_compliance(comp_nodes, min_compliance)

    return {"assets": assets, "services": services, "cpes": [], "vulns": vulns}


# ── Rudder API ────────────────────────────────────────────────────────────────
def _config() -> Tuple[str, str, bool]:
    url = os.getenv("RUDDER_URL")
    token = os.getenv("RUDDER_API_TOKEN")
    if not url or not token:
        raise RuntimeError("RUDDER_URL and RUDDER_API_TOKEN are required (worker env)")
    base = url.rstrip("/")
    if "/api/" not in base:
        base += "/api/latest" if base.endswith("/rudder") else "/rudder/api/latest"
    verify_raw = (os.getenv("RUDDER_VERIFY_TLS") or "1").strip().lower()
    verify = verify_raw not in ("0", "false", "no", "off")
    return base, token, verify


def _get(base: str, path: str, token: str, verify: bool, query: Optional[Dict[str, Any]] = None) -> Any:
    import requests

    if not verify:  # self-signed Rudder: silence the single warning
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass
    r = requests.get(
        base + path,
        headers={"X-API-Token": token, "Accept": "application/json"},
        params=query, timeout=120, verify=verify,
    )
    r.raise_for_status()
    j = r.json()
    if isinstance(j, dict) and j.get("result") == "error":
        raise RuntimeError(f"Rudder API error on {path}: {j.get('errorDetails') or j.get('error') or j}")
    return j


def _nodes_of(j: Any) -> List[Dict[str, Any]]:
    data = (j or {}).get("data") if isinstance(j, dict) else None
    nodes = (data or {}).get("nodes") if isinstance(data, dict) else None
    return [n for n in (nodes or []) if isinstance(n, dict)]


def _fetch_nodes(base: str, token: str, verify: bool, limit: int, include_software: bool) -> List[Dict[str, Any]]:
    # "full" includes software + network sections; "default" is lighter (no software).
    query = {"include": "full" if include_software else "default"}
    return _nodes_of(_get(base, "/nodes", token, verify, query))[:limit]


def _fetch_compliance(base: str, token: str, verify: bool, limit: int) -> List[Dict[str, Any]]:
    # level=2 returns the per-rule breakdown inside each node.
    return _nodes_of(_get(base, "/compliance/nodes", token, verify, {"level": 2}))[:limit]


# ── Mapping to the XORCISM findings model ─────────────────────────────────────
def _assets_and_services(nodes: List[Dict[str, Any]], include_software: bool):
    assets: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    for n in nodes:
        nid = str(n.get("id") or n.get("hostname") or "").strip()
        if not nid:
            continue
        assets.append({
            "hostname": n.get("hostname") or nid,
            "key": nid,
            "ip": _primary_ip(n),
            "os": _os_name(n),
        })
        if include_software:
            for sw in n.get("software") or []:
                name = sw.get("name") if isinstance(sw, dict) else sw
                ver = sw.get("version") if isinstance(sw, dict) else None
                if name:
                    services.append({"asset": nid, "cpe": (f"{name} {ver}".strip() if ver else str(name))})
    return assets, services


def _vulns_from_compliance(comp_nodes: List[Dict[str, Any]], min_compliance: float) -> List[Dict[str, Any]]:
    vulns: List[Dict[str, Any]] = []
    for n in comp_nodes:
        nid = str(n.get("id") or "").strip()
        if not nid:
            continue
        for rule in n.get("rules") or []:
            rid = rule.get("id")
            if not rid:
                continue
            pct = _as_float(rule.get("compliance"))
            if pct is not None and pct >= min_compliance:
                continue  # rule is compliant enough — not a finding
            name = str(rule.get("name") or rid)
            if pct is not None:
                name = f"{name} [{round(pct)}% compliant]"
            vulns.append({
                "asset": nid,
                "ref": f"RUDDER-{rid}",
                "name": name[:200],
                "severity": _severity(pct, rule),
            })
    return vulns


def _primary_ip(node: Dict[str, Any]) -> Optional[str]:
    ips = node.get("ipAddresses") or node.get("ip_addresses") or []
    if isinstance(ips, str):
        ips = [ips]
    for ip in ips:
        s = str(ip)
        if s and not s.startswith("127.") and s != "::1":
            return s
    for nic in node.get("networkInterfaces") or []:
        for ip in (nic.get("ipAddresses") or []) if isinstance(nic, dict) else []:
            s = str(ip)
            if s and not s.startswith("127.") and s != "::1":
                return s
    return None


def _os_name(node: Dict[str, Any]) -> Optional[str]:
    os_ = node.get("os")
    if isinstance(os_, dict):
        return os_.get("fullName") or " ".join(
            str(x) for x in (os_.get("name"), os_.get("version")) if x) or None
    return str(os_) if os_ else None


def _severity(pct: Optional[float], rule: Dict[str, Any]) -> str:
    details = rule.get("complianceDetails") or {}
    if isinstance(details, dict) and (details.get("error") or details.get("nonCompliant")):
        return "high"
    if pct is None:
        return "medium"
    if pct < 50:
        return "high"
    if pct < 80:
        return "medium"
    return "low"


def _as_float(v: Any) -> Optional[float]:
    try:
        return float(v) if v not in (None, "") else None
    except (ValueError, TypeError):
        return None


# ── Standalone CLI (offline dry run) ──────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Rudder connector (dry run / offline)")
    ap.add_argument("--file", help="Saved JSON {nodes:[...], compliance:[...]} instead of the live API")
    ap.add_argument("--scope", default="all", choices=["nodes", "compliance", "all"])
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--min-compliance", type=float, default=100)
    ap.add_argument("--include-software", action="store_true")
    a = ap.parse_args()
    res = run({"file": a.file, "scope": a.scope, "limit": a.limit,
               "min_compliance": a.min_compliance, "include_software": a.include_software},
              tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[rudder] {len(res['assets'])} asset(s), {len(res['services'])} software link(s), "
          f"{len(res['vulns'])} compliance finding(s)", flush=True)
