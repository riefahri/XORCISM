"""run.py — XORCISM connector: Artemis (CERT-PL) web findings → assets / vulns.

Artemis (https://github.com/CERT-Polska/Artemis) is a modular web vulnerability
scanner: it checks websites for misconfigurations and known vulnerabilities
(exposed .git/VCS, outdated CMS, directory listing, subdomain takeover, vulnerable
services, Nuclei templates, weak passwords…) and produces per-target findings.

Offline: parse an Artemis results/report JSON export (--file).
Live:    submit a scan to the Artemis web API (api_base) for `target` and import it.

Normalized XORCISM result {assets, services, cpes, vulns}:
  - scanned target host / URL  -> ASSET (host)
  - interesting finding        -> VULNERABILITY (module + message; CVE if referenced; severity)

The JSON is parsed defensively (report `messages`, `results`/`task_results`/`findings`
lists, or a recursive walk), so it tolerates schema drift across Artemis versions.
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
_SEV = {"critical", "high", "medium", "moderate", "low", "info", "informational", "unknown"}
# Artemis modules that are inherently high-impact when they fire (used when no explicit severity).
_HIGH_MODULES = re.compile(r"vcs|\.git|exposed|subdomain_takeover|takeover|sql|rce|nuclei|joomla|wordpress|bruter|password|backup|config", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = str(params.get("target") or "").strip()
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    elif target:
        data = _run_live(target, params, workdir)
    else:
        raise RuntimeError("artemis: provide a 'file' (JSON export) or a 'target' (+ api_base) for live mode")
    return _parse(data, target)


def _run_live(target: str, params: Dict[str, Any], workdir: str) -> Any:
    api_base = str(params.get("api_base") or "http://localhost:5000").rstrip("/")
    api_key = str(params.get("api_key") or os.environ.get("ARTEMIS_API_TOKEN") or "").strip()
    payload = json.dumps({"targets": [target], "tag": "xorcism"}).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["X-API-Token"] = api_key
    last_err = ""
    for path in ("/api/add", "/api/scan", "/api/v1/scan", "/api/analysis"):
        try:
            req = urllib.request.Request(api_base + path, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3600) as resp:  # noqa: S310 (operator-supplied api_base)
                body = resp.read().decode("utf-8", "replace")
            with open(os.path.join(workdir, "artemis.json"), "w", encoding="utf-8") as fh:
                fh.write(body)
            return json.loads(body)
        except Exception as e:  # noqa: BLE001
            last_err = f"{path}: {e}"
            continue
    raise RuntimeError(
        f"artemis live mode could not reach the API ({api_base}); last error: {last_err}. "
        "Export the Artemis results to JSON and import them via the 'file' parameter instead."
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
    vulns: List[Dict[str, str]] = []
    seen: set = set()

    def add_asset(url_or_host: str) -> str:
        host = _host(url_or_host) or _host(default_target)
        if not host:
            return ""
        assets.setdefault(host, {"hostname": host, "key": host})
        return host

    def sev_of(item: Dict[str, Any], module: str) -> str:
        s = _first(item, "severity", "Severity", "risk", "severity_level").lower()
        if s in _SEV:
            return s.capitalize().replace("Informational", "Info").replace("Moderate", "Medium")
        # Artemis "status" INTERESTING + a high-impact module → High; otherwise Medium.
        if _HIGH_MODULES.search(module + " " + _first(item, "message", "title", "name")):
            return "High"
        return "Medium"

    def add_finding(target: str, item: Dict[str, Any]) -> None:
        module = _first(item, "module", "receiver", "analysis", "task", "headers")
        msg = _first(item, "message", "title", "name", "status_reason", "description", "text", "result")
        # only import "interesting" results when a status is present
        status = _first(item, "status", "result_status").lower()
        if status and status not in ("interesting", "vulnerable", "found", "high", "medium", "low", "critical"):
            return
        if not (module or msg):
            return
        asset = add_asset(target or _first(item, "target", "url", "host", "domain"))
        m = _CVE.search(f"{msg} {_first(item, 'description', 'data')}")
        if m:
            ref = m.group(0).upper()
        else:
            slug = re.sub(r"[^a-z0-9]+", "-", (module or msg).lower()).strip("-")[:48] or "finding"
            ref = f"ARTEMIS-{slug}"
        name = (f"{module}: " if module else "") + (msg or module or ref)
        sev = sev_of(item, module)
        dkey = (asset, ref.lower(), name.lower())
        if dkey in seen:
            return
        seen.add(dkey)
        vulns.append({"asset": asset, "ref": ref, "name": name[:300], "severity": sev})

    def target_of(d: Dict[str, Any]) -> str:
        return _first(d, "target", "url", "host", "domain", "target_string", "payload")

    # Known shapes: report {messages:[{target,message,...}]}, {results|task_results|findings|data:[…]}, or a list.
    def handle_list(items: List[Any]) -> None:
        for it in items:
            if isinstance(it, dict):
                add_finding(target_of(it), it)

    if isinstance(data, dict):
        handled = False
        for key in ("messages", "results", "task_results", "findings", "data", "reports", "vulnerabilities"):
            v = data.get(key)
            if isinstance(v, list):
                handle_list(v)
                handled = True
        if not handled:
            # single result object, or a {target: [findings]} mapping
            if target_of(data):
                add_finding(target_of(data), data)
            else:
                for k, v in data.items():
                    if isinstance(v, list):
                        for it in v:
                            if isinstance(it, dict):
                                add_finding(_host(k) or target_of(it), it)
    elif isinstance(data, list):
        handle_list(data)

    if not assets and default_target:
        add_asset(default_target)
    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Artemis import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target}, tempfile.mkdtemp()), indent=2))
