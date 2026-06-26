"""run.py — XORCISM connector for Metatron (offensive security / penetration testing).

Imports a Metatron engagement export into XORCISM:
  * each discovered host    -> ASSET
  * each open service       -> a service on its host (port/proto/product)
  * each enumerated vuln    -> a vulnerability on its host (CVE-linked where present)
  * each CONFIRMED exploit  -> a vulnerability flagged exploitable (name prefixed "Exploited:")

so a pentest result feeds the attack surface, and the host -> service -> exploit -> impact steps are
available for pentest attack chains (XCHAIN, /pentest/chain). INTRUSIVE: authorized targets only.

Modes (in order):
    live    : METATRON_API_TOKEN -> GET findings from METATRON_API_URL.
    offline : params["file"]     -> parse a saved Metatron export.
    demo    : neither            -> import the bundled sample.json.

Normalized result: {project, assets, services, cpes, vulns, exploitable} -> runner.import_findings.
Worker-safe: stdlib only, secrets via env, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any, Dict, List

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _sev(s: Any) -> str:
    return _SEV.get(str(s or "").strip().lower(), "medium")


def _http(url: str, headers: Dict[str, str], timeout: int = 120) -> Any:
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", "replace") or "null")


def _list(data: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for k in keys + ("hosts", "results", "data", "items", "targets"):
            v = data.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _host_name(h: Dict[str, Any]) -> str:
    return str(h.get("host") or h.get("ip") or h.get("hostname") or h.get("address") or h.get("name") or "target")


def _exploited(f: Dict[str, Any]) -> bool:
    if f.get("exploited") or f.get("exploit") or f.get("compromised"):
        return True
    return str(f.get("status") or f.get("outcome") or "").strip().lower() in ("exploited", "compromised", "success")


def _normalize(hosts: List[Dict[str, Any]], project: str) -> Dict[str, Any]:
    assets: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    vulns: List[Dict[str, Any]] = []
    n_exploit = 0
    for h in hosts:
        name = _host_name(h)
        ip = str(h.get("ip") or (name if re.match(r"^\d+\.\d+\.\d+\.\d+$", name) else "") or "")
        assets.append({"hostname": name, "key": name, "ip": ip or None, "tags": "metatron,pentest,offensive"})
        for s in (h.get("services") or h.get("ports") or []):
            if not isinstance(s, dict):
                continue
            port = s.get("port") or s.get("portid")
            services.append({"asset": name, "port": int(port) if str(port or "").isdigit() else None,
                             "proto": str(s.get("proto") or s.get("protocol") or "tcp"),
                             "name": str(s.get("service") or s.get("name") or ""),
                             "product": str(s.get("product") or s.get("banner") or "")})
        for f in (h.get("findings") or h.get("vulnerabilities") or h.get("vulns") or h.get("exploits") or []):
            if not isinstance(f, dict):
                continue
            title = str(f.get("title") or f.get("name") or f.get("vuln") or "finding")
            cve = f.get("cve") or (_CVE.search(json.dumps(f)[:400]).group(0).upper() if _CVE.search(json.dumps(f)[:400]) else None)
            fid = str(f.get("id") or title)[:60]
            ex = _exploited(f)
            if ex:
                n_exploit += 1
            vulns.append({"asset": name, "ref": cve or f"METATRON-{fid}",
                          "name": (("Exploited: " if ex else "") + title)[:280],
                          "severity": "critical" if ex else _sev(f.get("severity") or f.get("risk")),
                          "exploited": ex})
    return {"project": project or "Metatron pentest", "assets": assets, "services": services, "cpes": [],
            "vulns": vulns, "exploitable": n_exploit}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 2000) or 2000)
    base = (os.environ.get("METATRON_API_URL") or "").strip()
    token = (os.environ.get("METATRON_API_TOKEN") or "").strip()
    if base and token:
        h = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        data = _http(base.rstrip("/") + "/findings", h)
        hosts = _list(data, "hosts", "targets")
        return _normalize(hosts[:limit], str((data.get("engagement") if isinstance(data, dict) else "") or ""))
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    project = str((data.get("engagement") or data.get("project") or "") if isinstance(data, dict) else "")
    hosts = _list(data, "hosts", "targets") or (_list(data) if isinstance(data, list) else [])
    return _normalize(hosts[:limit], project)


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
