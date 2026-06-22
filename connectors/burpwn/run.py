"""run.py — XORCISM connector: burpwn captured web flows -> ASSET + endpoints + findings.

Offline: parse a burpwn flow export (JSON list of flows, or {flows|requests|results:[...]}).
Live:    if `target` is set and the `burpwn` binary is on PATH (Linux), run a command through the
         proxy (`burpwn exec -- <command>`) and read the captured flows (`burpwn req list --json`).

Each flow ~ {method, url|host+path, status, request/response}. Normalized result {assets, cpes, vulns}:
  - target host           -> ASSET (host)
  - each discovered path   -> component/endpoint (cpe-style string) on the asset
  - interesting flows      -> VULNERABILITY findings (5xx errors, auth/login endpoints, reflected or
                              sensitive query parameters)

Worker-safe: stdlib only, no DB. ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from typing import Any, Dict, List

_SENSITIVE = re.compile(r"\b(token|passwd|password|pwd|secret|apikey|api_key|session|auth|jwt|redirect|url|next|callback|file|path|cmd|exec)\b", re.I)
_AUTH_PATH = re.compile(r"/(login|signin|sign-in|auth|oauth|admin|account|reset|sso|token)\b", re.I)


def _flows(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return data
    for k in ("flows", "requests", "results", "items", "data"):
        if isinstance(data.get(k), list):
            return data[k]
    return []


def _run_burpwn(target: str, command: str, workdir: str) -> Any:
    if not shutil.which("burpwn"):
        raise RuntimeError("burpwn binary not found on PATH (Linux only); provide a 'file' (JSON export) for offline mode")
    subprocess.run(["burpwn", "session", "new"], cwd=workdir, capture_output=True, text=True, timeout=60)
    cmd = command.replace("{target}", target)
    subprocess.run(["burpwn", "exec", "--"] + cmd.split(), cwd=workdir, capture_output=True, text=True, timeout=900)
    out = subprocess.run(["burpwn", "req", "list", "--json"], cwd=workdir, capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout or "[]")


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        target = str(params.get("target") or "").strip()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("burpwn: provide a 'file' (JSON export) or a 'target' URL for live mode")
        data = _run_burpwn(target, str(params.get("command") or "curl -sk {target}"), workdir)

    flows = _flows(data)
    hosts: Dict[str, Dict[str, Any]] = {}
    endpoints = set()
    vulns: List[Dict[str, Any]] = []

    def host_of(url: str) -> str:
        try:
            return urllib.parse.urlparse(url).netloc or url
        except Exception:
            return url

    for fl in flows:
        url = fl.get("url") or ((fl.get("scheme", "https") + "://" + fl.get("host", "") + fl.get("path", "")) if fl.get("host") else "")
        if not url:
            continue
        host = host_of(url)
        if not host:
            continue
        hosts.setdefault(host, {"hostname": host, "key": host})
        p = urllib.parse.urlparse(url)
        path = p.path or "/"
        method = str(fl.get("method", "GET")).upper()
        status = int(fl.get("status") or fl.get("status_code") or 0)
        endpoints.add(host + " " + method + " " + path)
        # findings
        if status >= 500:
            vulns.append({"asset": host, "ref": "BURPWN-5XX", "name": "Server error on %s %s (HTTP %d)" % (method, path, status), "severity": "Medium"})
        if _AUTH_PATH.search(path):
            vulns.append({"asset": host, "ref": "BURPWN-AUTH", "name": "Authentication/admin endpoint exposed: %s" % path, "severity": "Low"})
        if p.query and _SENSITIVE.search(p.query):
            param = _SENSITIVE.search(p.query).group(1)
            vulns.append({"asset": host, "ref": "BURPWN-PARAM", "name": "Sensitive parameter '%s' on %s (review for injection/SSRF/IDOR)" % (param, path), "severity": "Low"})

    # dedupe findings
    seen, uniq = set(), []
    for v in vulns:
        k = (v["asset"], v["name"])
        if k not in seen:
            seen.add(k); uniq.append(v)

    cpes = sorted("endpoint:" + e for e in endpoints)[:500]
    return {"source": "burpwn", "assets": list(hosts.values()), "cpes": cpes, "vulns": uniq,
            "summary": {"hosts": len(hosts), "flows": len(flows), "endpoints": len(endpoints), "findings": len(uniq)}}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--target")
    ap.add_argument("--command", default="curl -sk {target}")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target, "command": a.command}, tempfile.mkdtemp()), indent=2))
