"""run.py — MITRE Caldera connector (adversary emulation).

Connects to a Caldera server via its v2 API (read-only) and normalizes:
  • Caldera agents (deployed implants)         → ASSET (hostname/host, key=paw, os=platform)
  • abilities executed in the operations        → findings (ref = ATT&CK technique,
    linked to the targeted host; severity according to the execution success)

Configuration ONLY by environment variables (never entered here):
    CALDERA_URL      e.g. http://caldera.lab:8888
    CALDERA_API_KEY  Caldera API key ("KEY" header; defined in conf/local.yml)

The connector DOES NOT LAUNCH an operation: it imports the existing results. The
triggering of an emulation (intrusive action) stays manual on the Caldera side, within
the authorized engagement scope.

Normalized result: {assets:[{hostname,key,os}], vulns:[{asset,ref,name,severity}], cpes:[]}
"""
from __future__ import annotations
import json
import os
import sys
from typing import Any, Dict, List, Optional

# status of a Caldera link: 0 = success; -2/-3/-4/-5 = in progress/failure/timeout
STATUS_SEVERITY = {0: "high"}


def _client() -> "tuple[str, Dict[str, str]]":
    url = os.environ.get("CALDERA_URL")
    key = os.environ.get("CALDERA_API_KEY")
    if not url or not key:
        raise RuntimeError(
            "définissez CALDERA_URL et CALDERA_API_KEY (variables d'environnement)"
        )
    return url.rstrip("/"), {"KEY": key, "Accept": "application/json"}


def _agents(url: str, hdr: Dict[str, str]) -> List[Dict[str, Any]]:
    import requests  # lazy
    r = requests.get(f"{url}/api/v2/agents", headers=hdr, timeout=30)
    r.raise_for_status()
    out: List[Dict[str, Any]] = []
    for a in r.json() or []:
        host = a.get("host") or a.get("display_name") or a.get("paw")
        out.append({
            "hostname": host,
            "key": a.get("paw"),
            "os": a.get("platform"),
        })
    return out


def _op_links(url: str, hdr: Dict[str, str], op: Dict[str, Any]) -> List[Dict[str, Any]]:
    import requests  # lazy
    oid = op.get("id")
    # Dedicated endpoint if available; otherwise the links are embedded in the operation.
    try:
        r = requests.get(f"{url}/api/v2/operations/{oid}/links", headers=hdr, timeout=30)
        if r.status_code == 200:
            return r.json() or []
    except requests.RequestException:
        pass
    return op.get("chain") or op.get("host_group") or []


def _operations(url: str, hdr: Dict[str, str], op_filter: Optional[str]) -> List[Dict[str, Any]]:
    import requests  # lazy
    r = requests.get(f"{url}/api/v2/operations", headers=hdr, timeout=30)
    r.raise_for_status()
    ops = r.json() or []
    if op_filter:
        f = str(op_filter).strip().lower()
        ops = [o for o in ops if f in str(o.get("name", "")).lower() or f == str(o.get("id", "")).lower()]

    vulns: List[Dict[str, Any]] = []
    seen: set = set()
    for op in ops:
        for ln in _op_links(url, hdr, op):
            ab = ln.get("ability") or {}
            tech = ab.get("technique_id") or ab.get("technique")
            ref = tech or ab.get("ability_id") or ab.get("name")
            if not ref:
                continue
            paw = ln.get("paw")
            sev = STATUS_SEVERITY.get(ln.get("status"), "info")
            k = (paw, ref)
            if k in seen:
                continue
            seen.add(k)
            label = ab.get("name") or ab.get("technique_name") or ref
            tname = ab.get("technique_name")
            vulns.append({
                "asset": paw,
                "ref": ref,
                "name": f"{label}" + (f" ({tname})" if tname and tname != label else ""),
                "severity": sev,
            })
    return vulns


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    url, hdr = _client()
    assets = _agents(url, hdr)
    agents_only = str(params.get("agents_only", "")).lower() in ("1", "true", "yes")
    vulns: List[Dict[str, Any]] = [] if agents_only else _operations(url, hdr, params.get("operation"))
    return {"assets": assets, "vulns": vulns, "cpes": []}


if __name__ == "__main__":
    op = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(run({"operation": op}, "."), indent=2, ensure_ascii=False))
