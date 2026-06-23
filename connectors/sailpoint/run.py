"""run.py — XORCISM connector: SailPoint Identity Security Cloud (IdentityNow) → identities.

Collects the SailPoint IGA system-of-record into XORCISM via the REST API:
  • identities (/v3/public-identities) → human identities  (IDENTITY, type=human, class=identity)
  • accounts   (/v3/accounts)          → non-human / uncorrelated identities (optional)

Auth is app-only (OAuth2 client-credentials). Secrets come from the WORKER ENVIRONMENT, never
the XORCISM UI:
    SAILPOINT_BASE_URL      tenant API base, e.g. https://tenant.api.identitynow.com (or `base_url`)
    SAILPOINT_CLIENT_ID     personal/access-token client id
    SAILPOINT_CLIENT_SECRET client secret
The token (client_credentials) needs the read scopes for identities (and accounts if included).

Offline / test mode: params["file"] = a saved REST JSON export — either
{"identities": [...], "accounts": [...]} or a raw [...] / {"items": [...]} array.

Python stdlib only (urllib) — NO database access here, so the connector also runs on a remote
worker. The runner maps "identities" → IDENTITY (idempotent by Provider+ExternalID).
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "SailPoint"
_ACTIVE = {"active", "enabled", "true", "1"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    include = {s.strip().lower() for s in str(params.get("include") or "identities").replace(" ", "").split(",") if s.strip()}
    max_items = int(params.get("max_items") or 1000)

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        idents, accounts = _from_export(data)
    else:
        base, token = _token(params)
        idents = _paged(base, token, "/v3/public-identities", max_items) if "identities" in include else []
        accounts = _paged(base, token, "/v3/accounts", max_items) if "accounts" in include else []

    identities: List[Dict[str, Any]] = [_map_identity(i) for i in idents] + [_map_account(a) for a in accounts]
    identities = [i for i in identities if i.get("external_id")]
    return {"assets": [], "services": [], "cpes": [], "identities": identities, "source": SOURCE}


# ── auth + REST paging (stdlib) ──────────────────────────────────────────────────
def _token(params: Dict[str, Any]):
    base = str(params.get("base_url") or os.getenv("SAILPOINT_BASE_URL") or "").strip().rstrip("/")
    cid = os.getenv("SAILPOINT_CLIENT_ID") or ""
    secret = os.getenv("SAILPOINT_CLIENT_SECRET") or ""
    if not (base and cid and secret):
        raise RuntimeError(
            "SailPoint live mode needs SAILPOINT_BASE_URL (or base_url), SAILPOINT_CLIENT_ID and "
            "SAILPOINT_CLIENT_SECRET in the worker environment — or pass an offline export via file=.")
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": cid, "client_secret": secret,
    }).encode()
    req = urllib.request.Request(f"{base}/oauth/token", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (configured tenant endpoint)
        tok = json.loads(r.read().decode("utf-8", "replace"))
    if not tok.get("access_token"):
        raise RuntimeError(f"SailPoint token request failed: {tok.get('error_description') or tok}")
    return base, tok["access_token"]


def _paged(base: str, token: str, path: str, max_items: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    offset = 0
    while len(out) < max_items:
        sep = "&" if "?" in path else "?"
        url = f"{base}{path}{sep}limit=250&offset={offset}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=90) as r:  # noqa: S310
            page = json.loads(r.read().decode("utf-8", "replace"))
        rows = page.get("items") if isinstance(page, dict) else (page if isinstance(page, list) else [])
        rows = rows or []
        if not rows:
            break
        out.extend(rows)
        if len(rows) < 250:
            break
        offset += len(rows)
    return out[:max_items]


def _from_export(data: Any) -> tuple:
    if isinstance(data, dict) and any(k in data for k in ("identities", "accounts")):
        return (data.get("identities") or [], data.get("accounts") or [])
    rows = data.get("items") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    idents, accounts = [], []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if "nativeIdentity" in r or "sourceId" in r or "source" in r and "identityId" in r:
            accounts.append(r)
        else:
            idents.append(r)
    return idents, accounts


# ── mappers (SailPoint object → normalized XORCISM identity) ──────────────────────
def _status(v: Any) -> str:
    if v is None or v == "":
        return ""
    return "enabled" if str(v).lower() in _ACTIVE else "disabled"


def _map_identity(i: Dict[str, Any]) -> Dict[str, Any]:
    attrs = i.get("attributes") if isinstance(i.get("attributes"), dict) else {}
    mgr = i.get("manager") or {}
    mgr_name = mgr.get("name") if isinstance(mgr, dict) else (mgr if isinstance(mgr, str) else None)
    profile = i.get("identityProfile") or {}
    prof_name = profile.get("name") if isinstance(profile, dict) else None
    lifecycle = i.get("lifecycleState") or (i.get("status") if isinstance(i.get("status"), str) else None)
    desc = " · ".join(x for x in (i.get("email") or attrs.get("email") or "",
                                   f"manager={mgr_name}" if mgr_name else "",
                                   f"profile={prof_name}" if prof_name else "") if x)
    return {
        "name": i.get("name") or i.get("alias") or i.get("email") or i.get("id"),
        "type": "human", "class": "identity",
        "description": desc, "status": _status(lifecycle or i.get("status")),
        "provider": SOURCE, "external_id": i.get("id"),
        "environment": "IGA", "credential_type": "",
        "privilege": "privileged" if bool(i.get("isManager")) else "",
    }


def _map_account(a: Dict[str, Any]) -> Dict[str, Any]:
    src = a.get("sourceName") or (a.get("source") or {}).get("name") if isinstance(a.get("source"), dict) else a.get("source")
    uncorrelated = bool(a.get("uncorrelated")) or a.get("identityId") in (None, "")
    return {
        "name": a.get("name") or a.get("nativeIdentity") or a.get("id"),
        "type": "non-human", "class": "account",
        "description": (f"source={src}" if src else "") + (" · uncorrelated" if uncorrelated else ""),
        "status": "disabled" if a.get("disabled") is True else ("enabled" if a.get("disabled") is False else ""),
        "provider": SOURCE, "external_id": f"account:{a.get('id')}" if a.get("id") is not None else None,
        "environment": str(src or "IGA"), "credential_type": "account",
        "risk": "High" if uncorrelated else None,
    }


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="SailPoint IGA → identities (dry run)")
    ap.add_argument("--file", help="offline SailPoint REST JSON export")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--include", default="identities")
    ap.add_argument("--max-items", type=int, default=1000)
    a = ap.parse_args()
    res = run({"file": a.file, "base_url": a.base_url, "include": a.include, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[sailpoint] {len(res['identities'])} identit(y/ies)", flush=True)
