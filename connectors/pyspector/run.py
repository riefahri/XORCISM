"""run.py — XORCISM connector: PySpector (Python SAST) -> ASSET + VULNERABILITY findings.

Offline: parse a PySpector JSON or SARIF report (`pyspector scan <path> --format json -o out.json`).
Live:    if `target` is set and the `pyspector` binary is on PATH, run a scan and parse its JSON.

Normalized result {project, assets, vulns}:
  - scanned project / repo  -> ASSET (project)
  - each PySpector finding   -> VULNERABILITY (rule id + message, severity, CWE/CVE when present)

Worker-safe: stdlib only, no DB. ASCII-only output.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_CWE = re.compile(r"CWE-\d{1,5}", re.I)
_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
        "low": "Low", "info": "Informational", "informational": "Informational", "warning": "Low", "error": "High"}


def _sev(v: str) -> str:
    return _SEV.get(str(v or "").strip().lower(), "Medium")


def _findings_from_json(data: Any) -> List[Dict[str, Any]]:
    # PySpector JSON: a list of findings, or {findings|results|issues:[...]}, or SARIF {runs:[{results:[...]}]}
    if isinstance(data, dict) and "runs" in data:  # SARIF
        out = []
        for run_ in data.get("runs", []):
            rules = {r.get("id"): r for r in (run_.get("tool", {}).get("driver", {}).get("rules", []) or [])}
            for res in run_.get("results", []):
                rid = res.get("ruleId") or ""
                msg = (res.get("message", {}) or {}).get("text", "") if isinstance(res.get("message"), dict) else str(res.get("message", ""))
                loc = ""
                try:
                    loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                except Exception:
                    pass
                out.append({"rule": rid, "message": msg, "severity": res.get("level", "warning"),
                            "file": loc, "meta": rules.get(rid, {})})
        return out
    if isinstance(data, list):
        items = data
    else:
        items = data.get("findings") or data.get("results") or data.get("issues") or data.get("vulnerabilities") or []
    norm = []
    for f in items:
        if not isinstance(f, dict):
            continue
        norm.append({"rule": f.get("rule") or f.get("rule_id") or f.get("id") or f.get("check") or "PYSPECTOR",
                     "message": f.get("message") or f.get("title") or f.get("description") or "",
                     "severity": f.get("severity") or f.get("level") or "medium",
                     "file": f.get("file") or f.get("path") or f.get("location") or "",
                     "line": f.get("line") or f.get("line_number") or "",
                     "cwe": f.get("cwe") or "", "cve": f.get("cve") or ""})
    return norm


def _run_pyspector(target: str, workdir: str) -> Any:
    if not shutil.which("pyspector"):
        raise RuntimeError("pyspector binary not found on PATH; provide a 'file' (JSON/SARIF export) for offline mode")
    out = os.path.join(workdir, "pyspector.json")
    cmd = ["pyspector", "scan"]
    cmd += (["--url", target] if re.match(r"^https?://|\.git$", target) else [target])
    cmd += ["--format", "json", "-o", out]
    subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=1800)
    with open(out, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        target = str(params.get("target") or "").strip()
    else:
        target = str(params.get("target") or "").strip()
        if not target:
            raise RuntimeError("pyspector: provide a 'file' (report) or a 'target' (path/repo) for live mode")
        data = _run_pyspector(target, workdir)

    project = str(params.get("project") or "").strip() or (re.sub(r"\.git$", "", os.path.basename(target.rstrip("/"))) or "python-project")
    findings = _findings_from_json(data)
    vulns = []
    for f in findings:
        text = "%s %s" % (f.get("message", ""), f.get("rule", ""))
        cve = (_CVE.search(text) or [None]) and (_CVE.search(text).group(0).upper() if _CVE.search(text) else None)
        cwe = f.get("cwe") or (_CWE.search(text).group(0).upper() if _CWE.search(text) else "")
        loc = (f.get("file", "") + (":" + str(f.get("line")) if f.get("line") else "")).strip(":")
        vulns.append({"asset": project, "ref": cve or f.get("rule") or "PYSPECTOR",
                      "name": ("%s — %s" % (f.get("rule", "SAST"), f.get("message", "")))[:300],
                      "severity": _sev(f.get("severity")), "description": (loc + (" (" + cwe + ")" if cwe else "")).strip()})

    return {"source": "PySpector", "project": project, "assets": [{"hostname": project, "key": project}],
            "vulns": vulns, "summary": {"project": project, "findings": len(vulns)}}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--target")
    ap.add_argument("--project")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target, "project": a.project}, tempfile.mkdtemp()), indent=2))
