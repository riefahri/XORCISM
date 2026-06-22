"""run.py — XORCISM connector: Atlassian Jira issues → findings (assets / vulns).

Imports Jira issues (Cloud or Server/Data Center) as XORCISM findings. Each issue
becomes a VULNERABILITY on the asset it affects (resolved from a component, an
asset-like label, or the `asset`/`project` fallback).

Offline: parse a saved Jira search-results JSON (`GET /rest/api/3/search` response,
         a list of issues, or `{issues:[…]}`).
Live:    query the Jira REST API with JQL, paginated.

Secrets via worker env ONLY:
  JIRA_URL    base URL, e.g. https://acme.atlassian.net
  JIRA_USER   account email (Jira Cloud Basic auth)        — omit for a bearer PAT
  JIRA_TOKEN  API token (Cloud) or Personal Access Token (Server/DC)

Mapping → {assets, vulns}:
  - affected asset (component / asset-label / project / `asset` param) -> ASSET (host)
  - issue -> VULNERABILITY {ref = CVE in summary/description else JIRA-<key>,
             name = "[KEY] summary", severity from priority}

No DB access (worker-safe). Jira Cloud descriptions are ADF (rich JSON) — flattened to text.
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_PRIORITY_SEV = {
    "highest": "Critical", "critical": "Critical", "blocker": "Critical",
    "high": "High", "major": "High",
    "medium": "Medium", "normal": "Medium",
    "low": "Low", "minor": "Low", "lowest": "Low", "trivial": "Low",
}
# An asset-like label (looks like a host/domain/ip) rather than a tag.
_HOSTISH = re.compile(r"^(?:[a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}$|^\d{1,3}(?:\.\d{1,3}){3}$", re.I)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    else:
        data = _fetch_live(params)
    return _parse(data, params)


def _fetch_live(params: Dict[str, Any]) -> Dict[str, Any]:
    base = (os.environ.get("JIRA_URL") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("jira: set JIRA_URL (+ JIRA_USER/JIRA_TOKEN) in the worker env, or use the 'file' parameter")
    user = (os.environ.get("JIRA_USER") or "").strip()
    token = (os.environ.get("JIRA_TOKEN") or os.environ.get("JIRA_PAT") or "").strip()
    if not token:
        raise RuntimeError("jira: set JIRA_TOKEN (API token / PAT) in the worker env")
    jql = str(params.get("jql") or "").strip()
    if not jql:
        proj = str(params.get("project") or "").strip()
        if not proj:
            raise RuntimeError("jira: provide a 'project' key or an explicit 'jql' for live mode")
        jql = f"project = {proj} AND statusCategory != Done ORDER BY priority DESC"
    headers = {"Accept": "application/json"}
    if user:  # Jira Cloud: Basic email:token
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
    else:     # Server/DC: bearer PAT
        headers["Authorization"] = "Bearer " + token

    want = max(1, min(int(params.get("max") or 200), 5000))
    fields = "summary,description,priority,status,labels,components,issuetype,created,updated"
    issues: List[Dict[str, Any]] = []
    start = 0
    while len(issues) < want:
        q = urllib.parse.urlencode({"jql": jql, "startAt": start, "maxResults": min(100, want - len(issues)), "fields": fields})
        req = urllib.request.Request(f"{base}/rest/api/3/search?{q}", headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (operator-supplied JIRA_URL)
            page = json.loads(resp.read().decode("utf-8", "replace"))
        batch = page.get("issues") or []
        if not batch:
            break
        issues.extend(batch)
        total = int(page.get("total") or 0)
        start += len(batch)
        if start >= total:
            break
    return {"issues": issues}


def _adf_text(node: Any) -> str:
    """Flatten an Atlassian Document Format (ADF) description to plain text."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return " ".join(_adf_text(n) for n in node)
    if isinstance(node, dict):
        if node.get("type") == "text" and isinstance(node.get("text"), str):
            return node["text"]
        return _adf_text(node.get("content"))
    return ""


def _first(d: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return str(v).strip()
    return ""


def _parse(data: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(data, dict):
        issues = data.get("issues") or data.get("values") or data.get("results") or []
    elif isinstance(data, list):
        issues = data
    else:
        issues = []

    fallback = str(params.get("asset") or params.get("project") or "").strip().lower() or "jira"
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, str]] = []
    seen: set = set()

    def add_asset(name: str) -> str:
        key = (name or fallback).strip().lower()
        if not key:
            return ""
        assets.setdefault(key, {"hostname": key, "key": key})
        return key

    for it in issues:
        if not isinstance(it, dict):
            continue
        key = _first(it, "key", "id") or "ISSUE"
        f = it.get("fields") if isinstance(it.get("fields"), dict) else it
        summary = _first(f, "summary", "title", "name") or key
        desc = f.get("description")
        desc_txt = _adf_text(desc) if isinstance(desc, (dict, list)) else str(desc or "")
        prio = f.get("priority") or {}
        prio_name = (prio.get("name") if isinstance(prio, dict) else str(prio)) or ""
        severity = _PRIORITY_SEV.get(prio_name.strip().lower(), "")

        # affected asset: a component name, then an asset-like label, then fallback
        asset_name = ""
        comps = f.get("components")
        if isinstance(comps, list):
            for c in comps:
                nm = c.get("name") if isinstance(c, dict) else str(c)
                if nm:
                    asset_name = str(nm)
                    break
        if not asset_name:
            for lab in (f.get("labels") or []):
                if isinstance(lab, str) and _HOSTISH.match(lab):
                    asset_name = lab
                    break
        asset = add_asset(asset_name)

        m = _CVE.search(f"{summary} {desc_txt}")
        ref = m.group(0).upper() if m else f"JIRA-{key}"
        name = f"[{key}] {summary}".strip()
        dkey = (asset, ref.lower(), name.lower())
        if dkey in seen:
            continue
        seen.add(dkey)
        vulns.append({"asset": asset, "ref": ref, "name": name[:300], "severity": severity})

    if not assets:
        add_asset(fallback)
    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Jira issue import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--project", default="")
    ap.add_argument("--asset", default="")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "project": a.project, "asset": a.asset}, tempfile.mkdtemp()), indent=2))
