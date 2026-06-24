"""run.py - XORCISM inbound connector: Entra Conditional Access policies -> ZTPOLICY.

Ingests Microsoft Entra ID Conditional Access policies into the Zero Trust policy register
(NIST SP 800-207 Policy Engine view). Emits a normalized `zt_policies` list -> runner.import_zt_policies.

Modes:
    file : `file` = an exported CA policies JSON (a Graph value[] array or {"value":[...]} object).
    live : `token` or env GRAPH_TOKEN set -> GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies.
    demo : neither -> a small built-in sample.

Read-only against Entra. Worker-safe: stdlib only, secrets via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

GRAPH = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

_DEMO = [
    {"id": "p1", "displayName": "Require MFA for all users", "state": "enabled",
     "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
     "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}},
    {"id": "p2", "displayName": "Block legacy authentication", "state": "enabled",
     "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["exchangeActiveSync", "other"]},
     "grantControls": {"operator": "OR", "builtInControls": ["block"]}},
    {"id": "p3", "displayName": "Require compliant device for admins", "state": "enabled",
     "conditions": {"users": {"includeRoles": ["Global Administrator", "Privileged Role Administrator"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
     "grantControls": {"operator": "AND", "builtInControls": ["compliantDevice", "mfa"]}},
    {"id": "p4", "displayName": "MFA for risky sign-ins (report-only)", "state": "enabledForReportingButNotEnforced",
     "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "signInRiskLevels": ["high", "medium"]},
     "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}},
]


def _join(*lists) -> str:
    out = []
    for v in lists:
        if isinstance(v, list):
            out.extend(str(x) for x in v if x)
    return ", ".join(out[:12])


def _normalize(p: Dict[str, Any]) -> Dict[str, Any]:
    cond = p.get("conditions") or {}
    users = cond.get("users") or {}
    apps = cond.get("applications") or {}
    grant = p.get("grantControls") or {}
    controls = [str(c).lower() for c in (grant.get("builtInControls") or [])]
    cbits = []
    if cond.get("clientAppTypes"):
        cbits.append("clients=" + _join(cond.get("clientAppTypes")))
    if cond.get("signInRiskLevels"):
        cbits.append("signInRisk=" + _join(cond.get("signInRiskLevels")))
    if cond.get("platforms"):
        cbits.append("platforms")
    if cond.get("locations"):
        cbits.append("locations")
    return {
        "id": p.get("id"),
        "name": p.get("displayName"),
        "state": p.get("state"),
        "subjects": _join(users.get("includeUsers"), users.get("includeGroups"), users.get("includeRoles")) or "(none)",
        "resources": _join(apps.get("includeApplications")) or "(none)",
        "conditions": "; ".join(cbits) or "(any)",
        "grant_controls": ", ".join(controls) or "(none)",
        "require_mfa": "mfa" in controls,
        "require_compliant_device": "compliantdevice" in controls,
        "block": "block" in controls,
    }


def _load(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    path = str(params.get("file") or "").strip()
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("value", data) if isinstance(data, dict) else data
    token = (str(params.get("token") or "").strip() or os.environ.get("GRAPH_TOKEN", "").strip())
    if token:
        req = urllib.request.Request(GRAPH, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return (json.loads(resp.read().decode("utf-8")) or {}).get("value", [])
    return list(_DEMO)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    pols = [_normalize(p) for p in _load(params) if isinstance(p, dict)]
    pols = [p for p in pols if p.get("id")]
    return {"source": "Microsoft Entra Conditional Access", "zt_policies": pols, "count": len(pols)}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({}, tempfile.mkdtemp()), indent=2))
