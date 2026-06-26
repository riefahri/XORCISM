"""run.py — XORCISM connector for Brakeman (Ruby on Rails static analysis / SAST).

Brakeman (https://brakemanscanner.org) scans Rails source for SQLi, XSS, mass-assignment, command
injection, unsafe redirects and more. This connector imports its JSON report into XORCISM:
  * the scanned application -> ASSET (project context)
  * each warning            -> a finding (VULNERABILITY) on the app, severity from Brakeman confidence

Modes:
    offline : params["file"] -> a Brakeman JSON report (`brakeman -f json`).
    demo    : no config       -> the bundled sample.json.

Normalized result: {project, assets, vulns} -> runner.import_findings. Worker-safe: stdlib only,
ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

_CONF = {"high": "high", "medium": "medium", "weak": "low", "low": "low"}


def _sev(c: Any) -> str:
    return _CONF.get(str(c or "").strip().lower(), "medium")


def _normalize(data: Any) -> Dict[str, Any]:
    warnings: List[Dict[str, Any]] = []
    app = "Rails app"
    if isinstance(data, dict):
        warnings = [w for w in (data.get("warnings") or []) if isinstance(w, dict)]
        app = str((data.get("scan_info") or {}).get("app_path") or data.get("app_path") or "Rails app").rstrip("/").split("/")[-1] or "Rails app"
    elif isinstance(data, list):
        warnings = [w for w in data if isinstance(w, dict)]
    asset = app
    vulns: List[Dict[str, Any]] = []
    for w in warnings:
        wtype = str(w.get("warning_type") or w.get("check_name") or "Warning")
        msg = str(w.get("message") or w.get("warning_code") or "")
        loc = str(w.get("file") or w.get("location", {}).get("file") if isinstance(w.get("location"), dict) else w.get("file") or "")
        line = w.get("line") or (w.get("location", {}).get("line") if isinstance(w.get("location"), dict) else None)
        fp = str(w.get("fingerprint") or w.get("warning_code") or wtype)[:50]
        where = f"{loc}:{line}" if loc and line else loc
        vulns.append({"asset": asset, "ref": f"BRAKEMAN-{fp}",
                      "name": (f"{wtype}: {msg}" + (f" @ {where}" if where else ""))[:280],
                      "severity": _sev(w.get("confidence"))})
    return {"project": f"Brakeman: {app}", "assets": [{"hostname": asset, "key": asset, "tags": "brakeman,sast,rails"}], "services": [], "cpes": [], "vulns": vulns}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 1000) or 1000)
    path = params.get("file") or os.path.join(os.path.dirname(__file__), "sample.json")
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    out = _normalize(data)
    out["vulns"] = out["vulns"][:limit]
    return out


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()))[:2000])
