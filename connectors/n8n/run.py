"""run.py — XORCISM connector: n8n workflow automation (SOAR glue).

Live:    POST a context payload to an n8n workflow webhook (param `webhook` or env N8N_WEBHOOK_URL;
         optional header X-API-Key from env N8N_API_KEY) and read the JSON the workflow returns.
Offline: parse a saved n8n execution-result JSON (param `file`).

The returned/saved JSON is normalized: any indicators (`intel` / `indicators` / `iocs`) -> CTI
(runner.import_threat_intel -> XTHREAT.INTELEXCHANGE); any `vulns`/`assets` -> import_findings.
Worker-safe: stdlib only, secrets via env. ASCII-only output.
"""
from __future__ import annotations

import json
import os
import tempfile
import urllib.request
from typing import Any, Dict, List


def _trigger(url: str, payload: Dict[str, Any]) -> Any:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    key = os.environ.get("N8N_API_KEY")
    if key:
        req.add_header("X-API-Key", key)
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def _norm_intel(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        items = data.get("intel") or data.get("indicators") or data.get("iocs") or []
    elif isinstance(data, list):
        items = data
    else:
        items = []
    out = []
    for it in items:
        if isinstance(it, str):
            out.append({"name": it[:200], "reference": "n8n:" + it, "external_id": it, "tags": "n8n"})
        elif isinstance(it, dict):
            ref = it.get("reference") or it.get("value") or it.get("ioc") or it.get("name")
            if ref:
                out.append({"name": str(it.get("name") or ref)[:200], "reference": "n8n:" + str(ref),
                            "external_id": str(ref), "description": str(it.get("description") or "")[:500],
                            "tags": str(it.get("tags") or "n8n"), "cve_tags": it.get("cve_tags")})
    return out


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        mode = "offline"
    else:
        url = str(params.get("webhook") or os.environ.get("N8N_WEBHOOK_URL") or "").strip()
        if not url:
            raise RuntimeError("n8n: provide a 'webhook' URL or set N8N_WEBHOOK_URL, or pass a 'file' for offline mode")
        payload = {"source": "XORCISM", "workflow": params.get("workflow") or "", "context": params.get("context") or ""}
        data = _trigger(url, payload)
        mode = "live"

    intel = _norm_intel(data)
    # pass through any findings the workflow produced
    vulns = data.get("vulns") if isinstance(data, dict) else None
    assets = data.get("assets") if isinstance(data, dict) else None
    result: Dict[str, Any] = {"source": "n8n", "intel": intel,
                              "summary": {"mode": mode, "workflow": params.get("workflow") or "", "indicators": len(intel),
                                          "findings": len(vulns or [])}}
    if vulns:
        result["vulns"] = vulns
    if assets:
        result["assets"] = assets
    return result


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--webhook")
    ap.add_argument("--workflow")
    ap.add_argument("--context")
    ap.add_argument("--file")
    a = ap.parse_args()
    print(json.dumps(run({"webhook": a.webhook, "workflow": a.workflow, "context": a.context, "file": a.file}, tempfile.mkdtemp()), indent=2))
