"""run.py — XORCISM connector for GraphQL Cop (https://github.com/dolevf/graphql-cop).

GraphQL Cop is a Python security auditing tool for GraphQL APIs (by Dolev Farhi). It probes a
GraphQL endpoint for common misconfigurations & weaknesses: introspection enabled, GraphiQL /
Playground exposed, alias/field/directive/circular-query overloading (DoS), batch queries (DoS),
GET-based & urlencoded POST queries (CSRF), tracing/debug modes (info leak). This connector maps
its findings into XORCISM:
  * the scanned GraphQL endpoint  -> ASSET (host)
  * each positive finding (result=true) -> a VULNERABILITY on it (severity from HIGH/LOW/INFO),
    carrying the impact + a reproducible curl in the description.

Modes (in order):
    offline : params["file"] -> a graphql-cop JSON export (`graphql-cop -t <url> -o json > out.json`).
    live    : params["target"] (the GraphQL endpoint) + the `graphql-cop` binary on the worker PATH
              (or GRAPHQL_COP_BIN, e.g. "python3 /opt/graphql-cop/graphql-cop.py") -> runs a scan
              and parses its JSON. ACTIVE WEB SCANNING (intrusive) — authorized scope only.
    demo    : neither -> the bundled sample.json.

Normalized result: {assets, vulns, source} -> runner.import_findings (also recorded as a DevSecOps
DAST scan). Worker-safe: stdlib only, no DB access, ASCII output.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import urllib.parse
from typing import Any, Dict, List, Optional

TOOL_NAME = "GraphQL Cop"
TOOL_URL = "https://github.com/dolevf/graphql-cop"
SOURCE = "graphql-cop"

_SEV = {"high": "high", "critical": "critical", "medium": "medium", "low": "low", "info": "info", "informational": "info"}


def _sev(s: Any) -> str:
    return _SEV.get(str(s or "").strip().lower(), "medium")


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _host(target: Optional[str]) -> str:
    t = str(target or "").strip()
    if not t:
        return "graphql-api"
    if "://" not in t:
        t = "http://" + t
    try:
        h = urllib.parse.urlparse(t).hostname
        return h or "graphql-api"
    except ValueError:
        return "graphql-api"


def _slug(title: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in str(title).lower()).strip("-")[:60] or "finding"


def _from_tool(params: Dict[str, Any]) -> Any:
    target = str(params.get("target") or "").strip()
    if not target:
        raise RuntimeError("live mode needs a target (the GraphQL endpoint URL)")
    binary = (os.environ.get("GRAPHQL_COP_BIN") or "").strip()
    cmd = shlex.split(binary) if binary else [shutil.which("graphql-cop") or "graphql-cop"]
    cmd += ["-t", target, "-o", "json"]
    hdr = str(params.get("header") or "").strip()
    if hdr:
        cmd += ["-H", hdr]
    proxy = str(params.get("proxy") or "").strip()
    if proxy:
        cmd += ["-x", proxy]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    out = (r.stdout or "").strip()
    # graphql-cop prints the JSON array on stdout; tolerate leading banner lines.
    start = out.find("[")
    if start > 0:
        out = out[start:]
    return json.loads(out) if out else []


def _normalize(data: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    # Accept a list of findings, or {results:[...]} / {findings:[...]}.
    if isinstance(data, dict):
        data = data.get("results") or data.get("findings") or data.get("data") or []
    findings = data if isinstance(data, list) else []
    host = _host(params.get("target"))
    assets = [{"hostname": host, "key": host}]
    vulns: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if not _truthy(f.get("result")):
            continue   # result=false → the check passed (not vulnerable)
        title = str(f.get("title") or "GraphQL issue").strip()
        impact = str(f.get("impact") or "").strip()
        desc = str(f.get("description") or "").strip()
        curl = str(f.get("curl_verify") or "").strip()
        name = ("[graphql-cop] " + title + (" — " + impact if impact else ""))[:300]
        vulns.append({
            "asset": host, "ref": "GRAPHQLCOP-" + _slug(title), "name": name,
            "severity": _sev(f.get("severity")),
            "description": (desc + ("\nVerify: " + curl if curl else ""))[:1000] or None,
        })
    return {"project": "GraphQL Cop: " + host, "assets": assets, "services": [], "cpes": [], "vulns": vulns, "source": SOURCE}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    elif params.get("target"):
        data = _from_tool(params)
    else:
        sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.json")
        with open(sample, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    out = _normalize(data, params)
    print("[graphql-cop] %d GraphQL issue(s) on %s" % (len(out["vulns"]), out["assets"][0]["hostname"]))
    return out


if __name__ == "__main__":
    p = {"file": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(run(p, "."), indent=2)[:2000])
