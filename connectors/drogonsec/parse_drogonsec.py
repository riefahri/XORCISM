"""parse_drogonsec.py — Parser for the DrogonSec tool-runner connector.

DrogonSec is run with `--format sarif`, so the output is an OASIS SARIF 2.1 document;
parsing is delegated to the shared connectors/_sarif.py parser. DrogonSec unifies SAST,
SCA, secret detection and IaC findings into a single SARIF run, so the same parser that
serves every SARIF-producing tool (Semgrep, …) maps them into XORCISM findings. The
runner additionally records the run as a DevSecOps SAST scan (mapping=drogonsec).
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _sarif import parse_sarif  # noqa: E402


def parse(output: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """`output` is the path to the SARIF file written by DrogonSec (output.kind=file)."""
    project = params.get("project") or _basename(params.get("source"))
    return parse_sarif(output, default_project=project)


def _basename(src: Any) -> str | None:
    if not src:
        return None
    return os.path.basename(str(src).rstrip("/\\")) or str(src)
