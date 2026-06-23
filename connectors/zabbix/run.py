"""run.py — XORCISM connector for Zabbix (infrastructure monitoring) -> Asset Monitoring.

Zabbix (https://www.zabbix.com) is an open-source monitoring platform for networks, servers,
cloud and applications. This connector imports its monitored estate + active problems into
XORCISM Asset Monitoring:
  * each Zabbix host        -> ASSET (network discovery) + a MONITORINGCHECK (server monitor,
                               status up/down/paused from host availability)
  * each active problem      -> a MONITORINGINCIDENT (severity-mapped, started_at from the clock)

Modes (in order):
    live    : ZABBIX_URL + (ZABBIX_TOKEN api-token, or ZABBIX_USER + ZABBIX_PASSWORD) -> the JSON-RPC
              API (apiinfo/host.get/problem.get) at <ZABBIX_URL>/api_jsonrpc.php.
    offline : params["file"] -> a saved Zabbix export ({hosts, problems} / JSON-RPC {result:[...]} /
              a flat host list).
    demo    : neither -> the bundled sample.json.

Normalized result: {assets, monitors, monitoring_incidents, source} -> runner.import_monitoring
(+ import_findings for the assets). Worker-safe: stdlib only, secrets via env, ASCII-only output,
no DB access.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "Zabbix"
TOOL_URL = "https://www.zabbix.com"
SOURCE = "Zabbix"

# Zabbix trigger/problem severity (0..5) -> XORCISM severity.
_SEV = {"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "info", "0": "info"}


def _http(url: str, payload: Dict[str, Any], token: Optional[str], timeout: int = 60) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json-rpc"}
    # Zabbix 6.4+ accepts the API token as a Bearer header (and ignores the "auth" field).
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        return json.loads(resp.read().decode("utf-8", "replace") or "{}")


def _rpc(base: str, method: str, params: Any, token: Optional[str], rid: int = 1) -> Any:
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params, "id": rid}
    # Pre-6.4 servers want the token in the "auth" field (login/apiinfo never carry auth).
    if token and method not in ("apiinfo.version", "user.login"):
        payload["auth"] = token
    out = _http(base, payload, token if method != "user.login" else None)
    if isinstance(out, dict) and out.get("error"):
        raise RuntimeError("zabbix %s: %s" % (method, out["error"].get("data") or out["error"].get("message")))
    return out.get("result") if isinstance(out, dict) else None


def _endpoint(url: str) -> str:
    u = url.rstrip("/")
    if u.endswith("api_jsonrpc.php"):
        return u
    return u + "/api_jsonrpc.php"


def _from_api(params: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    base = _endpoint((params.get("url") or os.environ.get("ZABBIX_URL") or "").strip())
    token = (os.environ.get("ZABBIX_TOKEN") or "").strip()
    if not token:
        user = (os.environ.get("ZABBIX_USER") or "").strip()
        pwd = os.environ.get("ZABBIX_PASSWORD") or ""
        if user:
            # user.login returns the session token used as auth for later calls.
            token = _rpc(base, "user.login", {"username": user, "password": pwd}, None) \
                or _rpc(base, "user.login", {"user": user, "password": pwd}, None)
    hosts = _rpc(base, "host.get", {
        "output": ["hostid", "host", "name", "status", "available"],
        "selectInterfaces": ["ip", "dns", "available"],
    }, token) or []
    problems = _rpc(base, "problem.get", {
        "output": ["eventid", "name", "severity", "clock", "objectid", "r_eventid"],
        "selectHosts": ["hostid", "name"],
        "recent": False, "sortfield": ["eventid"], "sortorder": "DESC", "limit": 1000,
    }, token) or []
    return hosts, problems


def _host_ip(h: Dict[str, Any]) -> Optional[str]:
    for itf in h.get("interfaces") or []:
        ip = (itf.get("ip") or "").strip()
        if ip and ip not in ("0.0.0.0", "127.0.0.1"):
            return ip
        dns = (itf.get("dns") or "").strip()
        if dns:
            return dns
    return None


def _host_available(h: Dict[str, Any]) -> str:
    # host.status: 0 monitored, 1 unmonitored(disabled) -> paused.
    if str(h.get("status")) == "1":
        return "paused"
    # availability: prefer host.available, else any interface available flag. 1 available, 2 unavailable.
    avail = str(h.get("available") or "")
    if not avail or avail == "0":
        flags = [str(i.get("available") or "0") for i in (h.get("interfaces") or [])]
        if "2" in flags:
            avail = "2"
        elif "1" in flags:
            avail = "1"
    if avail == "2":
        return "down"
    if avail == "1":
        return "up"
    return "up"  # unknown availability -> assume up (monitored)


def _norm(hosts: List[Dict[str, Any]], problems: List[Dict[str, Any]]) -> Dict[str, Any]:
    assets: List[Dict[str, Any]] = []
    monitors: List[Dict[str, Any]] = []
    by_id: Dict[str, str] = {}
    for h in hosts:
        name = (h.get("name") or h.get("host") or "").strip()
        if not name:
            continue
        hid = str(h.get("hostid") or name)
        by_id[hid] = name
        ip = _host_ip(h)
        assets.append({"hostname": name, "key": name, "ip": ip})
        monitors.append({
            "name": "Zabbix: " + name, "type": "server", "target": ip or name, "asset": name,
            "status": _host_available(h), "external_id": "zbx-host-" + hid, "source": SOURCE,
        })
    incidents: List[Dict[str, Any]] = []
    for p in problems:
        title = (p.get("name") or "Problem").strip()
        eid = str(p.get("eventid") or "")
        # host comes either as a direct hostid (export) or via selectHosts (live API).
        hid = str(p.get("hostid") or "")
        ph = p.get("hosts") or []
        if not hid and ph:
            hid = str(ph[0].get("hostid") or "")
        asset = by_id.get(hid) or (ph[0].get("name") if ph else None)
        clock = p.get("clock")
        started = None
        try:
            if clock:
                started = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(clock)))
        except (ValueError, TypeError):
            started = None
        resolved = str(p.get("r_eventid") or "0") not in ("", "0")
        incidents.append({
            "title": title, "monitor": ("Zabbix: " + asset) if asset else None, "asset": asset,
            "status": "up" if resolved else "down", "severity": _SEV.get(str(p.get("severity")), "info"),
            "started_at": started, "external_id": "zbx-prob-" + eid if eid else None, "source": SOURCE,
        })
    incidents = [i for i in incidents if i.get("external_id")]
    return {"assets": assets, "monitors": monitors, "monitoring_incidents": incidents, "source": SOURCE}


def _from_export(data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if isinstance(data, dict) and "result" in data:        # raw JSON-RPC host.get response
        data = data["result"]
    if isinstance(data, dict):
        return data.get("hosts") or data.get("host") or [], data.get("problems") or data.get("problem") or []
    if isinstance(data, list):
        return data, []
    return [], []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            hosts, problems = _from_export(json.load(fh))
    elif (params.get("url") or os.environ.get("ZABBIX_URL")):
        hosts, problems = _from_api(params)
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8") as fh:
            hosts, problems = _from_export(json.load(fh))
    out = _norm(hosts, problems)
    print("[zabbix] %d host(s), %d monitor(s), %d active problem(s)"
          % (len(out["assets"]), len(out["monitors"]), len(out["monitoring_incidents"])))
    return out


if __name__ == "__main__":
    import sys
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(run(p, "."), indent=2)[:2000])
