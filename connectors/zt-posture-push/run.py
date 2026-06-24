"""run.py - XORCISM outbound connector: push the device-trust feed to the enforcement plane.

XORCISM computes a per-device trust score (zerotrust.ts -> GET /api/zero-trust/device-trust). This
connector ships that posture to your ZTNA / IdP / PEP so access decisions can gate on it - making
XORCISM part of the Zero Trust decision loop (NIST SP 800-207) without being the enforcement point.

Feed source (in order): inline `feed` (JSON) -> `file` (the exported JSON) -> a built-in demo feed.
Only devices with trust below `min_trust` (the non-compliant set; 0 = all) are pushed. The payload
is shaped per `format` (generic | cloudflare | zscaler | okta | entra) - field naming only; the exact
endpoint/schema is vendor-specific, so the operator points `webhook` at their posture API.

Modes:
    live    : ZT_POSTURE_WEBHOOK (or param `webhook`) set, dry_run off -> POSTs and returns {"notify":1}.
    dry-run : no webhook, or dry_run=true -> builds and returns the payload WITHOUT sending.

The runner treats "notify" as an outbound action (no DB read/write). Worker-safe: stdlib only,
secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

_DEMO = {
    "source": "XORCISM Zero Trust", "schema": "device-trust/1", "generated": "1970-01-01T00:00:00Z",
    "threshold": 60, "count": 3, "compliant": 1, "nonCompliant": 2,
    "devices": [
        {"assetId": 1, "name": "prod-web-ec2", "hostname": "prod-web-ec2", "os": "Linux", "criticality": "High",
         "exposure": "Internet", "trust": 12, "tier": "Untrusted", "compliant": False,
         "reasons": ["actively-exploited (KEV) vulnerability", "Internet-facing crown jewel", "not backed up"]},
        {"assetId": 2, "name": "fin-db-01", "hostname": "fin-db-01", "os": "Windows", "criticality": "Critical",
         "exposure": "Internal", "trust": 48, "tier": "Low", "compliant": False, "reasons": ["critical vulnerabilities open"]},
        {"assetId": 3, "name": "corp-laptop-114", "hostname": "corp-laptop-114", "os": "Windows", "criticality": "Medium",
         "exposure": "Internal", "trust": 86, "tier": "Trusted", "compliant": True, "reasons": []},
    ],
}


def _load_feed(params: Dict[str, Any]) -> Dict[str, Any]:
    inline = str(params.get("feed") or "").strip()
    if inline:
        return json.loads(inline)
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return dict(_DEMO)


def _to_int(v: Any, d: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def _shape(dev: Dict[str, Any], fmt: str) -> Dict[str, Any]:
    host = dev.get("hostname") or dev.get("name")
    trust = dev.get("trust")
    compliant = bool(dev.get("compliant"))
    reasons = dev.get("reasons") or []
    if fmt == "cloudflare":  # Cloudflare Access device posture (custom/service-token posture)
        return {"device": host, "compliant": compliant, "score": trust, "details": "; ".join(reasons)}
    if fmt == "zscaler":     # Zscaler device posture / trust signal
        return {"hostname": host, "posture": "pass" if compliant else "fail", "trustLevel": trust, "reasons": reasons}
    if fmt == "okta":        # Okta device-trust / risk signal
        return {"deviceName": host, "managementStatus": "MANAGED" if compliant else "NOT_MANAGED", "riskLevel": "LOW" if trust >= 80 else "MEDIUM" if trust >= 50 else "HIGH", "trustScore": trust}
    if fmt == "entra":       # Microsoft Entra Conditional Access device-compliance signal
        return {"deviceName": host, "isCompliant": compliant, "trustScore": trust, "reasons": reasons}
    return {"hostname": host, "trust": trust, "tier": dev.get("tier"), "compliant": compliant, "criticality": dev.get("criticality"), "reasons": reasons}  # generic


def _post(url: str, payload: Dict[str, Any], token: str) -> bool:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (operator-supplied URL = their ZTNA)
        resp.read()
        return 200 <= resp.status < 300


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    fmt = str(params.get("format") or "generic").strip().lower()
    if fmt not in ("generic", "cloudflare", "zscaler", "okta", "entra"):
        fmt = "generic"
    min_trust = _to_int(params.get("min_trust"), 60)
    feed = _load_feed(params)
    devices: List[Dict[str, Any]] = list(feed.get("devices") or [])
    push = [d for d in devices if min_trust <= 0 or _to_int(d.get("trust"), 0) < min_trust]
    payload = {
        "source": "XORCISM Zero Trust", "format": fmt, "generated": feed.get("generated"),
        "threshold": min_trust, "count": len(push), "devices": [_shape(d, fmt) for d in push],
    }
    webhook = (str(params.get("webhook") or "").strip() or os.environ.get("ZT_POSTURE_WEBHOOK", "").strip())
    token = (str(params.get("token") or "").strip() or os.environ.get("ZT_POSTURE_TOKEN", "").strip())
    dry = str(params.get("dry_run") or "").lower() in ("1", "true", "yes") or not webhook
    base = {"source": "XORCISM Zero Trust posture push", "format": fmt, "evaluated": len(devices), "pushed": len(push)}
    if dry:
        return {**base, "notify": 0, "dry_run": True, "payload": payload}
    ok = _post(webhook, payload, token)
    return {**base, "notify": 1 if ok else 0}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({"format": "cloudflare", "min_trust": 60, "dry_run": True}, tempfile.mkdtemp()), indent=2))
