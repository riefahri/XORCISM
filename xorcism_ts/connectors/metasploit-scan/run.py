"""run.py — Network scan via Metasploit RPC (msfrpcd).

Runs "db_nmap -sV [ -p ports] <target>" in an MSF console, waits for completion,
then reads hosts / services / vulnerabilities from the MSF database via the RPC API (so
compatible with a remote msfrpcd). Returns a normalized result:
    {assets, services, vulns, cpes:[]}

Configuration (worker environment variables, never entered in the UI):
    MSF_RPC_PASS   msfrpcd password (REQUIRED)
    MSF_RPC_HOST   msfrpcd host (default 127.0.0.1)
    MSF_RPC_PORT   msfrpcd port (default 55553)
    MSF_RPC_USER   user (default msf)
    MSF_RPC_SSL    true/false (default true)
    MSF_RPC_WORKSPACE  MSF workspace (default default)

Prerequisites: msfrpcd running (msfrpcd -P <pass> -U msf -a 0.0.0.0) and
            "pip install pymetasploit3" on the worker.
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
from typing import Any, Dict, List

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/\-]{1,255}$")  # ip/host/cidr, no shell metacharacter
PORTS_RE = re.compile(r"^[0-9,\-]{1,64}$")


def _s(v: Any) -> str:
    """Decodes bytes → str (the msgpack RPC can return bytes)."""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return "" if v is None else str(v)


def _client():
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "pymetasploit3 manquant sur le worker : pip install pymetasploit3"
        ) from e
    password = os.getenv("MSF_RPC_PASS")
    if not password:
        raise RuntimeError("MSF_RPC_PASS non défini (mot de passe msfrpcd) sur le worker")
    host = os.getenv("MSF_RPC_HOST", "127.0.0.1")
    port = int(os.getenv("MSF_RPC_PORT", "55553"))
    user = os.getenv("MSF_RPC_USER", "msf")
    ssl = os.getenv("MSF_RPC_SSL", "true").lower() in ("1", "true", "yes")
    return MsfRpcClient(password, server=host, port=port, username=user, ssl=ssl)


def _run_db_nmap(client, target: str, ports: str) -> None:
    """Runs db_nmap in a console and waits for it to become idle again."""
    cid = client.call("console.create")["id"]
    try:
        cmd = "db_nmap -sV"
        if ports and PORTS_RE.match(ports):
            cmd += " -p " + ports
        cmd += " " + target + "\n"
        client.call("console.write", [cid, cmd])
        time.sleep(2)
        deadline = time.time() + 1800  # 30 min max
        idle = 0
        while time.time() < deadline:
            r = client.call("console.read", [cid])
            if not r.get("busy"):
                idle += 1
                if idle >= 2:  # two consecutive idle reads = finished
                    break
            else:
                idle = 0
            time.sleep(3)
    finally:
        try:
            client.call("console.destroy", [cid])
        except Exception:
            pass


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = (params.get("target") or "").strip()
    if not TARGET_RE.match(target):
        raise ValueError("cible invalide")
    ports = (params.get("ports") or "").strip()
    ws = os.getenv("MSF_RPC_WORKSPACE", "default")

    client = _client()
    _run_db_nmap(client, target, ports)

    # Read the results from the MSF database via RPC (works remotely).
    hosts_raw = client.call("db.hosts", [{"workspace": ws}]).get("hosts", []) or []
    svcs_raw = client.call("db.services", [{"workspace": ws}]).get("services", []) or []
    vulns_raw = client.call("db.vulns", [{"workspace": ws}]).get("vulns", []) or []

    assets: Dict[str, Dict[str, Any]] = {}
    for h in hosts_raw:
        addr = _s(h.get("address"))
        name = _s(h.get("name")) or addr
        if not addr:
            continue
        assets[addr] = {"hostname": name or addr, "ip": addr, "key": addr,
                        "os": _s(h.get("os_name"))}

    services: List[Dict[str, Any]] = []
    for sv in svcs_raw:
        addr = _s(sv.get("host"))
        if not addr:
            continue
        services.append({"asset": addr, "name": _s(sv.get("name")),
                         "port": _s(sv.get("port"))})

    vulns: List[Dict[str, Any]] = []
    for v in vulns_raw:
        addr = _s(v.get("host"))
        vname = _s(v.get("name")) or "Metasploit finding"
        refs_raw = " ".join(_s(r) for r in (v.get("refs") or []))
        cves = sorted({m.upper() for m in CVE_RE.findall(refs_raw)})
        refs = cves or ["MSF-" + re.sub(r"\W+", "_", f"{addr}:{vname}")[:60]]
        for ref in refs:
            vulns.append({"asset": addr, "ref": ref, "name": vname, "severity": "high"})

    return {"assets": list(assets.values()), "services": services,
            "vulns": vulns, "cpes": []}


if __name__ == "__main__":
    # Manual test: MSF_RPC_PASS=... python run.py <target> [ports]
    tgt = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    prt = sys.argv[2] if len(sys.argv) > 2 else ""
    print(json.dumps(run({"target": tgt, "ports": prt}, "."), indent=2, ensure_ascii=False))
