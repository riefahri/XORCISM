"""run.py - XORCISM inbound connector: Okta sign-on / access policy rules -> ZTPOLICY.

Ingests Okta policy rules into the Zero Trust policy register (NIST SP 800-207 Policy Engine view).
Emits a normalized `zt_policies` list -> runner.import_zt_policies.

Modes:
    file : `file` = an exported policy-rules JSON (an array of Okta rule objects).
    live : `org` (or OKTA_URL) + `token` (or OKTA_TOKEN) -> GET /api/v1/policies?type=… then /rules.
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
    {"id": "r1", "name": "MFA required", "status": "ACTIVE", "_policy": "Default sign-on policy",
     "conditions": {"people": {"groups": {"include": ["Everyone"]}}, "network": {"connection": "ANYWHERE"}},
     "actions": {"signon": {"access": "CHALLENGE", "requireFactor": True}}},
    {"id": "r2", "name": "Deny from blocked zones", "status": "ACTIVE", "_policy": "Default sign-on policy",
     "conditions": {"people": {"groups": {"include": ["Everyone"]}}, "network": {"connection": "ZONE", "include": ["BlockedCountries"]}},
     "actions": {"signon": {"access": "DENY", "requireFactor": False}}},
    {"id": "r3", "name": "Admins require MFA + trusted device", "status": "INACTIVE", "_policy": "Admin policy",
     "conditions": {"people": {"groups": {"include": ["Administrators"]}}, "network": {"connection": "ANYWHERE"}},
     "actions": {"signon": {"access": "ALLOW", "requireFactor": True}}},
]


def _join(*lists) -> str:
    out = []
    for v in lists:
        if isinstance(v, list):
            out.extend(str(x) for x in v if x)
        elif v:
            out.append(str(v))
    return ", ".join(out[:12])


def _normalize(rule: Dict[str, Any]) -> Dict[str, Any]:
    cond = rule.get("conditions") or {}
    people = cond.get("people") or {}
    groups = people.get("groups") or {}
    users = people.get("users") or {}
    net = cond.get("network") or {}
    signon = (rule.get("actions") or {}).get("signon") or {}
    access = str(signon.get("access") or "").upper()
    require_factor = bool(signon.get("requireFactor")) or access == "CHALLENGE"
    block = access == "DENY"
    controls = (["mfa"] if require_factor else []) + (["block"] if block else [])
    cbits = []
    conn = net.get("connection")
    if conn:
        cbits.append("network=" + str(conn))
    if net.get("include"):
        cbits.append("zones=" + _join(net.get("include")))
    pol = rule.get("_policy") or "Okta policy"
    return {
        "id": rule.get("id"),
        "name": f"{pol} / {rule.get('name') or 'rule'}",
        "state": "enabled" if str(rule.get("status") or "").upper() == "ACTIVE" else "disabled",
        "subjects": _join(groups.get("include"), users.get("include")) or "(any)",
        "resources": "(sign-on)",
        "conditions": "; ".join(cbits) or "(any)",
        "grant_controls": ", ".join(controls) or "(allow)",
        "require_mfa": require_factor,
        "require_compliant_device": False,
        "block": block,
    }


def _fetch(url: str, token: str) -> Any:
    req = urllib.request.Request(url, headers={"Authorization": f"SSWS {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else data.get("value", [])
    org = (str(params.get("org") or "").strip() or os.environ.get("OKTA_URL", "").strip()).rstrip("/")
    token = (str(params.get("token") or "").strip() or os.environ.get("OKTA_TOKEN", "").strip())
    if org and token:
        ptype = str(params.get("type") or "OKTA_SIGN_ON").strip()
        policies = _fetch(f"{org}/api/v1/policies?{urllib.parse.urlencode({'type': ptype})}", token) or []
        rules: List[Dict[str, Any]] = []
        for p in policies:
            pid, pname = p.get("id"), p.get("name")
            if not pid:
                continue
            for r in _fetch(f"{org}/api/v1/policies/{pid}/rules", token) or []:
                r["_policy"] = pname
                rules.append(r)
        return rules
    return list(_DEMO)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    pols = [_normalize(r) for r in _load(params) if isinstance(r, dict)]
    pols = [p for p in pols if p.get("id")]
    return {"source": "Okta sign-on policy", "zt_policies": pols, "count": len(pols)}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
