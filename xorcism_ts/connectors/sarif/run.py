"""run.py — XORCISM connector: import an OASIS SARIF file.

Reads a SARIF 2.1.0 document produced by any compatible static-analysis / scanner
tool and imports its results as findings. The analyzed project/repository becomes
an ASSET; each SARIF result becomes a finding (VULNERABILITY / ASSETVULNERABILITY).
Parsing is done by the shared connectors/_sarif.py parser.

This module performs NO database access (so it also runs on a remote worker): it
returns the normalized result {assets, services, cpes, vulns}.

Parameters:
    file     path on the worker to a .sarif/.json SARIF document (REQUIRED)
    project  asset name to attach the findings to (optional; default: derived
             from the SARIF repository URI / tool name)
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

# Make the shared parser (connectors/_sarif.py) importable wherever this runs.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _sarif import load_sarif, parse_sarif  # noqa: E402


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("sarif connector requires a 'file' parameter (path to a .sarif document)")
    if not os.path.isfile(path):
        raise RuntimeError(f"SARIF file not found: {path}")
    data = load_sarif(path)
    return parse_sarif(data, default_project=params.get("project"))


# ── Standalone CLI (offline dry run) ──────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import tempfile

    ap = argparse.ArgumentParser(description="Import a SARIF file (dry run / offline)")
    ap.add_argument("--file", required=True, help="Path to a .sarif/.json SARIF document")
    ap.add_argument("--project", help="Asset name to attach the findings to")
    a = ap.parse_args()
    res = run({"file": a.file, "project": a.project}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[sarif] {len(res['assets'])} asset(s), {len(res['vulns'])} finding(s)", flush=True)
