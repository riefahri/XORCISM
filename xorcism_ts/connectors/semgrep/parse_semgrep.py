"""parse_semgrep.py — Parser for the Semgrep tool-runner connector.

Semgrep is run with `--sarif`, so the output is an OASIS SARIF document; parsing is
delegated to the shared connectors/_sarif.py parser. Demonstrates the "a connector
runs a tool, emits SARIF, and imports it" pattern — the same parser serves every
SARIF-producing tool.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _sarif import parse_sarif  # noqa: E402


def parse(output: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """`output` is the path to the SARIF file written by Semgrep (output.kind=file)."""
    project = params.get("project") or _basename(params.get("source"))
    return parse_sarif(output, default_project=project)


def _basename(src: Any) -> str | None:
    if not src:
        return None
    return os.path.basename(str(src).rstrip("/\\")) or str(src)
