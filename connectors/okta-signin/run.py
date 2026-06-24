"""run.py - XORCISM inbound connector: Okta System Log sign-ins -> IDENTITYSIGNIN.

Ingests Okta authentication events (the continuous-verification telemetry for the Zero Trust
Identity pillar / UEBA session-risk). Emits a normalized `signins` list -> runner.import_signins.

Modes:
    file : `file` = an exported Okta System Log (a JSON array of log events).
    live : `org` (or OKTA_URL) + `token` (or OKTA_TOKEN) -> GET {org}/api/v1/logs.
    demo : neither -> a small built-in sample.

Read-only against Okta. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_DEMO = [
    {"uuid": "o1", "published": "2026-06-24T08:05:00.000Z", "eventType": "user.session.start",
     "actor": {"alternateId": "carol@acme.com", "displayName": "Carol"},
     "client": {"ipAddress": "203.0.113.20", "geographicalContext": {"country": "United States", "city": "Austin"}, "device": "Computer"},
     "outcome": {"result": "SUCCESS"}, "authenticationContext": {"credentialType": "OTP"}},
    {"uuid": "o2", "published": "2026-06-24T08:10:00.000Z", "eventType": "user.authentication.auth_via_mfa",
     "actor": {"alternateId": "dave@acme.com", "displayName": "Dave"},
     "client": {"ipAddress": "192.0.2.40", "geographicalContext": {"country": "United States", "city": "Austin"}, "device": "Computer"},
     "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}, "authenticationContext": {"credentialType": "PASSWORD"}},
]
_MFA_EVENTS = ("auth_via_mfa", "verify", "factor")
_MFA_CREDS = ("otp", "token", "push", "webauthn", "u2f", "sms", "totp")


def _normalize(rec: Dict[str, Any]) -> Dict[str, Any]:
    actor = rec.get("actor") or {}
    client = rec.get("client") or {}
    geo = client.get("geographicalContext") or {}
    out = rec.get("outcome") or {}
    auth = rec.get("authenticationContext") or {}
    et = str(rec.get("eventType") or "").lower()
    cred = str(auth.get("credentialType") or "").lower()
    mfa = "yes" if (any(k in et for k in _MFA_EVENTS) or any(k in cred for k in _MFA_CREDS)) else "no"
    res = str(out.get("result") or "").upper()
    return {
        "id": rec.get("uuid"),
        "user": actor.get("alternateId") or actor.get("displayName"),
        "timestamp": rec.get("published"),
        "ip": client.get("ipAddress"),
        "country": geo.get("country"),
        "city": geo.get("city"),
        "device": client.get("device"),
        "client_app": rec.get("eventType"),
        "mfa": mfa,
        "result": "success" if res == "SUCCESS" else "failure" if res else "success",
        "failure_reason": out.get("reason") or None,
        "risk": (rec.get("securityContext") or {}).get("isProxy") and "medium" or None,
    }


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else data.get("value", [])
    org = (str(params.get("org") or "").strip() or os.environ.get("OKTA_URL", "").strip()).rstrip("/")
    token = (str(params.get("token") or "").strip() or os.environ.get("OKTA_TOKEN", "").strip())
    if org and token:
        limit = int(params.get("limit") or 200)
        q = urllib.parse.urlencode({"filter": 'eventType sw "user.session" or eventType sw "user.authentication"', "limit": limit})
        req = urllib.request.Request(f"{org}/api/v1/logs?{q}", headers={"Authorization": f"SSWS {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8")) or []
    return list(_DEMO)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    records = _load(params)
    signins = [_normalize(r) for r in records if isinstance(r, dict)]
    signins = [s for s in signins if s.get("id") and s.get("user")]
    return {"source": "Okta", "signins": signins, "count": len(signins)}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
