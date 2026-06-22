"""run.py — XORCISM connector: CyberSentinel AI → assets / services / cpes / vulns.

CyberSentinel AI (https://github.com/3sk1nt4n/cybersentinel-ai) is an agentic,
local AI-driven security platform that orchestrates 33 tools (Nmap, Nuclei, Nikto,
SQLMap, Shodan, VirusTotal, ELK, Neo4j…) in a Kali sandbox and analyzes the results
with a local LLM (Ollama), mapping findings to MITRE ATT&CK in a knowledge graph.

Offline: parse a CyberSentinel results JSON export (--file).
Live:    POST a scan to the CyberSentinel FastAPI backend (api_base) for `target`
         and import whatever JSON results come back.

Normalized XORCISM result {assets, services, cpes, vulns}:
  - scanned target host / URL        -> ASSET (host)
  - discovered service / open port   -> service/CPE on that asset
  - vulnerability / finding          -> VULNERABILITY (CVE ref or title + severity)

The JSON shape is parsed defensively: known per-tool sections, nested findings, or
a recursive walk that attaches each finding to the nearest host on its path. The
MITRE ATT&CK technique id (T####) is appended to a finding's name when present.
No DB access (worker-safe).
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SEV = {"critical", "high", "medium", "moderate", "low", "info", "informational", "unknown"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = str(params.get("target") or "").strip()
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    elif target:
        data = _run_live(target, params, workdir)
    else:
        raise RuntimeError(
            "cybersentinel-ai: provide a 'file' (JSON results export) or a 'target' (+ api_base) for live mode"
        )
    return _parse(data, target)


def _run_live(target: str, params: Dict[str, Any], workdir: str) -> Any:
    api_base = str(params.get("api_base") or "http://localhost:8000").rstrip("/")
    api_key = str(params.get("api_key") or "").strip()
    scan_type = str(params.get("scan_type") or "full").strip()
    payload = json.dumps({"target": target, "scan_type": scan_type, "type": scan_type}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    # Best-effort: the CyberSentinel FastAPI backend exposes a scan endpoint; try the
    # common paths and import whatever JSON results are returned.
    last_err = ""
    for path in ("/api/scan", "/api/v1/scan", "/scan", "/api/scans", "/api/agent/scan"):
        try:
            req = urllib.request.Request(api_base + path, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3600) as resp:  # noqa: S310 (operator-supplied api_base)
                body = resp.read().decode("utf-8", "replace")
            with open(os.path.join(workdir, "cybersentinel.json"), "w", encoding="utf-8") as fh:
                fh.write(body)
            return json.loads(body)
        except Exception as e:  # noqa: BLE001
            last_err = f"{path}: {e}"
            continue
    raise RuntimeError(
        f"cybersentinel-ai live mode could not reach the backend API ({api_base}); last error: {last_err}. "
        "Run the scan in CyberSentinel and import its JSON results via the 'file' parameter instead."
    )


def _host(url: str) -> str:
    s = str(url or "").strip()
    if not s:
        return ""
    if "://" not in s and "/" in s:
        s = "http://" + s
    if "://" in s:
        netloc = urllib.parse.urlparse(s).netloc or ""
        return (netloc.split("@")[-1].split(":")[0] or "").strip().lower()
    return s.split("/")[0].split(":")[0].strip().lower()


def _first(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return str(v).strip()
    return ""


def _parse(data: Any, default_target: str) -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    services: List[Dict[str, str]] = []
    cpes: set = set()
    vulns: List[Dict[str, str]] = []
    seen_v: set = set()

    def add_asset(url_or_host: str) -> str:
        host = _host(url_or_host) or _host(default_target)
        if not host:
            return ""
        assets.setdefault(host, {"hostname": host, "key": host})
        return host

    def add_service(asset: str, label: str) -> None:
        label = (label or "").strip()
        if not label:
            return
        cpes.add(label)
        if asset:
            services.append({"asset": asset, "cpe": label})

    def add_vuln(asset: str, item: Dict[str, Any]) -> None:
        ref = _first(item, "cve", "CVE", "cve_id", "cveId")
        title = _first(item, "title", "name", "template-id", "template_id", "description", "info", "vulnerability")
        if not ref:
            m = _CVE.search(f"{title} {_first(item, 'description', 'matched-at', 'matcher_name')}")
            if m:
                ref = m.group(0).upper()
        if not (ref or title):
            return
        sev = _first(item, "severity", "Severity", "risk", "cvss_severity").capitalize()
        # Enrich the name with the MITRE ATT&CK technique id when present.
        att = _first(item, "attack", "mitre", "technique", "technique_id", "att&ck")
        m = _ATTACK.search(att) or _ATTACK.search(title)
        name = title or ref
        if m and m.group(0) not in name:
            name = f"{name} [{m.group(0)}]"
        key = (asset, (ref or name).lower(), name.lower())
        if key in seen_v:
            return
        seen_v.add(key)
        vulns.append({"asset": asset, "ref": ref or name, "name": name, "severity": sev if sev else ""})

    def looks_like_finding(d: Dict[str, Any]) -> bool:
        if any(k in d for k in ("cve", "CVE", "cve_id", "cveId")):
            return True
        sev = str(d.get("severity") or d.get("Severity") or d.get("risk") or "").strip().lower()
        if sev in _SEV and any(k in d for k in ("title", "name", "template-id", "template_id", "description", "info", "vulnerability", "matched-at")):
            return True
        return any(k in d for k in ("vulnerability", "finding")) and (d.get("title") or d.get("name") or d.get("description"))

    def host_of(d: Dict[str, Any]) -> str:
        return _first(d, "host", "hostname", "ip", "ip_address", "address", "target", "url", "asset", "matched-at")

    # Recursive walk: track the nearest host seen on the path; attach findings/services to it.
    def walk(node: Any, asset: str) -> None:
        if isinstance(node, dict):
            here = host_of(node)
            cur = add_asset(here) if here else asset
            if looks_like_finding(node):
                add_vuln(cur, node)
            # service / open port row
            port = _first(node, "port", "Port")
            svc = _first(node, "service", "service_name", "product", "name")
            if port or (svc and _first(node, "protocol", "proto", "state")):
                lbl = svc or _first(node, "protocol")
                if port:
                    lbl = (lbl + " " if lbl else "") + f"port {port}"
                add_service(cur, lbl)
            for v in node.values():
                if isinstance(v, (dict, list)):
                    walk(v, cur)
        elif isinstance(node, list):
            for it in node:
                walk(it, asset)

    root_asset = add_asset(default_target) if default_target else ""
    # Pick up a top-level target/host if the export carries one.
    if isinstance(data, dict):
        top = host_of(data)
        if top:
            root_asset = add_asset(top)
    walk(data, root_asset)

    # Ensure referenced assets exist; fall back to the seed target.
    for v in vulns:
        if v["asset"]:
            add_asset(v["asset"])
    if not assets and default_target:
        add_asset(default_target)

    return {"assets": list(assets.values()), "services": services, "cpes": sorted(cpes), "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="CyberSentinel AI import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target}, tempfile.mkdtemp()), indent=2))
