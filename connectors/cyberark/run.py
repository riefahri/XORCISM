"""run.py — XORCISM connector: CyberArk Privileged Access Management → identities.

Collects the CyberArk vault into XORCISM via the PVWA / Privilege Cloud REST API:
  • accounts → non-human / privileged identities (IDENTITY, type=non-human, class=privileged-account)
  • users    → human or component identities      (IDENTITY, type=human/non-human, class=user)

Auth is a service-account logon (token). Secrets come from the WORKER ENVIRONMENT, never the
XORCISM UI:
    CYBERARK_BASE_URL     PVWA / Privilege Cloud base (e.g. https://pvwa.example.com), or `base_url`
    CYBERARK_USERNAME     vault service account
    CYBERARK_PASSWORD     vault service account password
    CYBERARK_AUTH_METHOD  CyberArk (default) | LDAP | RADIUS | Windows  (or `auth_method`)
The account needs list/read membership on the safes whose accounts you want to inventory.

Offline / test mode: params["file"] = a saved REST JSON export — either
{"accounts": [...], "users": [...]} or a raw {"value": [...]} / {"Users": [...]} array.

Python stdlib only (urllib) — NO database access here, so the connector also runs on a remote
worker. The runner maps "identities" → IDENTITY (idempotent by Provider+ExternalID).
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

SOURCE = "CyberArk"
_TRUE = {"y", "yes", "true", "1", "on", "enabled"}
_AUTH_METHODS = {"cyberark", "ldap", "radius", "windows"}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    include = {s.strip().lower() for s in str(params.get("include") or "accounts,users").replace(" ", "").split(",") if s.strip()}
    max_items = int(params.get("max_items") or 1000)

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        accounts, users = _from_export(data)
    else:
        base, token, ctx = _logon(params)
        try:
            accounts = _paged(base, token, ctx, "/PasswordVault/API/Accounts", "value", max_items) if "accounts" in include else []
            users = _paged(base, token, ctx, "/PasswordVault/API/Users", "Users", max_items) if "users" in include else []
        finally:
            _logoff(base, token, ctx)

    identities: List[Dict[str, Any]] = [_map_account(a) for a in accounts] + [_map_user(u) for u in users]
    identities = [i for i in identities if i.get("external_id")]
    return {"assets": [], "services": [], "cpes": [], "identities": identities, "source": SOURCE}


# ── auth + REST paging (stdlib) ──────────────────────────────────────────────────
def _ssl_ctx() -> Optional[ssl.SSLContext]:
    # CyberArk PVWA is often fronted by an internal CA; allow opting out of verification for that.
    if str(os.getenv("CYBERARK_INSECURE") or "").lower() in _TRUE:
        c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
        return c
    return None


def _logon(params: Dict[str, Any]):
    base = str(params.get("base_url") or os.getenv("CYBERARK_BASE_URL") or "").strip().rstrip("/")
    user = os.getenv("CYBERARK_USERNAME") or ""
    pwd = os.getenv("CYBERARK_PASSWORD") or ""
    method = str(params.get("auth_method") or os.getenv("CYBERARK_AUTH_METHOD") or "CyberArk").strip()
    if method.lower() not in _AUTH_METHODS:
        method = "CyberArk"
    if not (base and user and pwd):
        raise RuntimeError(
            "CyberArk live mode needs CYBERARK_BASE_URL (or base_url), CYBERARK_USERNAME and "
            "CYBERARK_PASSWORD in the worker environment — or pass an offline export via file=.")
    ctx = _ssl_ctx()
    body = json.dumps({"username": user, "password": pwd, "concurrentSession": True}).encode()
    req = urllib.request.Request(f"{base}/PasswordVault/API/Auth/{method}/Logon", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:  # noqa: S310 (configured vault endpoint)
        raw = r.read().decode("utf-8", "replace").strip()
    # The body is the session token, JSON-quoted.
    token = json.loads(raw) if raw.startswith('"') else raw
    if not token:
        raise RuntimeError("CyberArk logon returned an empty token")
    return base, token, ctx


def _logoff(base: str, token: str, ctx) -> None:
    try:
        req = urllib.request.Request(f"{base}/PasswordVault/API/Auth/Logoff", data=b"",
                                     headers={"Authorization": token, "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=30, context=ctx).read()  # noqa: S310
    except Exception:  # noqa: BLE001 — best-effort logoff
        pass


def _paged(base: str, token: str, ctx, path: str, key: str, max_items: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    offset = 0
    while len(out) < max_items:
        sep = "&" if "?" in path else "?"
        url = f"{base}{path}{sep}limit=100&offset={offset}"
        req = urllib.request.Request(url, headers={"Authorization": token, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=90, context=ctx) as r:  # noqa: S310
            page = json.loads(r.read().decode("utf-8", "replace"))
        rows = page.get(key) or page.get("value") or page.get("Users") or []
        if not rows:
            break
        out.extend(rows)
        if page.get("nextLink") is None and len(rows) < 100:
            break
        offset += len(rows)
    return out[:max_items]


def _from_export(data: Any) -> tuple:
    if isinstance(data, dict) and any(k in data for k in ("accounts", "users")):
        return (data.get("accounts") or [], data.get("users") or [])
    rows = data.get("value") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    if not rows and isinstance(data, dict):
        rows = data.get("Users") or []
    accounts, users = [], []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if "platformId" in r or "safeName" in r or "secretType" in r or "address" in r:
            accounts.append(r)
        else:
            users.append(r)
    return accounts, users


# ── mappers (CyberArk object → normalized XORCISM identity) ───────────────────────
def _status(enabled: Any) -> str:
    if enabled is None:
        return ""
    return "enabled" if (enabled is True or str(enabled).lower() in _TRUE) else "disabled"


def _map_account(a: Dict[str, Any]) -> Dict[str, Any]:
    user = a.get("userName") or a.get("name") or ""
    addr = a.get("address") or ""
    name = (f"{user}@{addr}" if user and addr else (user or a.get("name") or a.get("id")))
    platform = a.get("platformId") or ""
    safe = a.get("safeName") or ""
    secret = (a.get("secretType") or "password").lower()
    cred = "ssh-key" if "key" in secret else ("password" if "password" in secret else secret)
    desc = " · ".join(x for x in (f"platform={platform}" if platform else "", f"safe={safe}" if safe else "") if x)
    last = None
    sm = a.get("secretManagement") or {}
    if isinstance(sm, dict):
        last = sm.get("lastModifiedTime") or sm.get("lastReconciledTime")
    return {
        "name": str(name), "type": "non-human", "class": "privileged-account",
        "description": desc, "status": "",
        "provider": SOURCE, "external_id": a.get("id") or name,
        "privilege": "privileged", "environment": addr or "On-Prem",
        "credential_type": cred, "last_used": _epoch(last),
    }


def _map_user(u: Dict[str, Any]) -> Dict[str, Any]:
    component = bool(u.get("componentUser")) or str(u.get("userType") or "").lower() in {"appprovider", "apponly", "built-inadmins"}
    return {
        "name": u.get("username") or u.get("id"),
        "type": "non-human" if component else "human", "class": "user",
        "description": " · ".join(x for x in (u.get("userType") or "", (u.get("source") or "")) if x),
        "status": _status(u.get("enableUser") if u.get("enableUser") is not None else u.get("suspended") is not True),
        "provider": SOURCE, "external_id": f"user:{u.get('id')}" if u.get("id") is not None else None,
        "privilege": "privileged" if str(u.get("userType") or "").lower() in {"built-inadmins", "appprovider"} else "",
        "environment": "Vault", "credential_type": "password",
    }


def _epoch(v: Any) -> Optional[str]:
    """CyberArk timestamps are unix epoch seconds; normalize to ISO date (best-effort)."""
    if v is None or v == "":
        return None
    try:
        import datetime
        return datetime.datetime.utcfromtimestamp(int(float(v))).strftime("%Y-%m-%d")
    except Exception:  # noqa: BLE001
        return str(v)[:10] if isinstance(v, str) else None


if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="CyberArk PAM → identities (dry run)")
    ap.add_argument("--file", help="offline CyberArk REST JSON export")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--auth-method", default="CyberArk")
    ap.add_argument("--include", default="accounts,users")
    ap.add_argument("--max-items", type=int, default=1000)
    a = ap.parse_args()
    res = run({"file": a.file, "base_url": a.base_url, "auth_method": a.auth_method, "include": a.include, "max_items": a.max_items}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[cyberark] {len(res['identities'])} identit(y/ies)", flush=True)
