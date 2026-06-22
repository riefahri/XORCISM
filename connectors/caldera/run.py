"""run.py — MITRE Caldera connector: automation for remote Caldera hosts (adversary emulation).

Connects to a remote MITRE Caldera server (v2 API) to AUTOMATE adversary-emulation operations and
feed the results into XORCISM's BAS layer:
  * agents (deployed implants)               -> ASSET (host, key=paw, os=platform)
  * abilities executed in operations         -> findings (ATT&CK technique linked to the host) AND
    -> emulation_results (technique, outcome) -> runner.import_emulation -> EMULATIONRUN/EMULATIONRESULT
       -> the ATT&CK validation-coverage heatmap (/attack).

Actions (`action` param):
  * import (default) : read existing operations + results — READ-ONLY, safe.
  * launch           : create + start an operation (adversary against an agent group) on the remote
                       Caldera host — automated offensive emulation (admin-only; scope = the Caldera
                       agent group you deployed). Optionally `wait` then import its results.

Remote hosts: target any Caldera host via `caldera_url` (overrides env CALDERA_URL) — so one XORCISM
can drive several remote Caldera servers, and the connector can be scheduled (XSCHEDULE cron) for
recurring automated emulation. The API key stays in the worker env (CALDERA_API_KEY, "KEY" header).

    CALDERA_URL      e.g. https://caldera.lab:8888       (or the caldera_url param)
    CALDERA_API_KEY  Caldera API key (conf/local.yml)
Worker-safe: stdlib only, ASCII-only output, no DB access.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# Caldera link status → BAS outcome. 0=success, -2=discard, -3=queued/collecting, -4=error/untrusted.
_OUTCOME = {0: "Executed", -2: "No result", -3: "Pending", -4: "Failed", 124: "Failed"}


def _client(params: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    url = (str(params.get("caldera_url") or "").strip() or os.environ.get("CALDERA_URL") or "").rstrip("/")
    key = str(params.get("caldera_key") or "").strip() or os.environ.get("CALDERA_API_KEY") or ""
    if not url or not key:
        raise RuntimeError("set CALDERA_URL + CALDERA_API_KEY (env) — or pass caldera_url (key stays in env)")
    return url, {"KEY": key, "Accept": "application/json", "Content-Type": "application/json"}


def _req(url: str, hdr: Dict[str, str], method: str = "GET", body: Any = None, timeout: int = 60) -> Any:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=hdr)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw) if raw else None


def _agents(url: str, hdr: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    try:
        rows = _req(f"{url}/api/v2/agents", hdr) or []
    except Exception:  # noqa: BLE001
        rows = []
    assets, paw2host = [], {}
    for a in rows:
        host = a.get("host") or a.get("display_name") or a.get("paw")
        paw = a.get("paw")
        paw2host[paw] = host
        assets.append({"hostname": host, "key": paw, "os": a.get("platform")})
    return assets, paw2host


def _op_links(url: str, hdr: Dict[str, str], op: Dict[str, Any]) -> List[Dict[str, Any]]:
    oid = op.get("id")
    try:
        r = _req(f"{url}/api/v2/operations/{oid}/links", hdr)
        if isinstance(r, list):
            return r
    except Exception:  # noqa: BLE001
        pass
    return op.get("chain") or []


def _harvest(ops: List[Dict[str, Any]], url: str, hdr: Dict[str, str], paw2host: Dict[str, str], op_filter: Optional[str]):
    """Map Caldera operation links → (findings vulns, emulation_results)."""
    if op_filter:
        f = str(op_filter).strip().lower()
        ops = [o for o in ops if f in str(o.get("name", "")).lower() or f == str(o.get("id", "")).lower()]
    vulns: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen: set = set()
    for op in ops:
        opname = op.get("name") or op.get("id") or "operation"
        for ln in (_op_links(url, hdr, op) if url else (op.get("chain") or op.get("links") or [])):
            ab = ln.get("ability") or {}
            tech = ab.get("technique_id") or ab.get("technique")
            ref = tech or ab.get("ability_id") or ab.get("name")
            if not ref:
                continue
            paw = ln.get("paw")
            host = paw2host.get(paw, paw)
            label = ab.get("name") or ab.get("technique_name") or ref
            status = ln.get("status")
            outcome = _OUTCOME.get(status, "Pending")
            results.append({
                "technique": tech or "", "atomic_guid": str(ln.get("id") or ab.get("ability_id") or ""),
                "name": label, "executor": (ab.get("executor") or {}).get("name") if isinstance(ab.get("executor"), dict) else ab.get("executor", ""),
                "outcome": outcome, "detail": f"Caldera op '{opname}' (status {status})", "host": host,
            })
            k = (paw, ref)
            if k not in seen:
                seen.add(k)
                vulns.append({"asset": host, "ref": ref,
                              "name": f"{label}" + (f" ({ab.get('technique_name')})" if ab.get("technique_name") and ab.get("technique_name") != label else ""),
                              "severity": "high" if status == 0 else "info"})
    return vulns, results


def _resolve(url: str, hdr: Dict[str, str], path: str, want: str, id_key: str) -> Optional[str]:
    """Resolve an adversary/planner by id or (case-insensitive) name → its id."""
    if not want:
        return None
    try:
        rows = _req(f"{url}{path}", hdr) or []
    except Exception:  # noqa: BLE001
        return want
    w = want.strip().lower()
    for r in rows:
        if str(r.get(id_key, "")).lower() == w or str(r.get("name", "")).lower() == w:
            return r.get(id_key)
    return want  # assume it's already an id


def _launch(url: str, hdr: Dict[str, str], params: Dict[str, Any]) -> Dict[str, Any]:
    adv = _resolve(url, hdr, "/api/v2/adversaries", str(params.get("adversary") or ""), "adversary_id")
    if not adv:
        raise RuntimeError("launch requires `adversary` (id or name)")
    planner = _resolve(url, hdr, "/api/v2/planners", str(params.get("planner") or "atomic"), "id") or "atomic"
    op = {
        "name": str(params.get("name") or f"XORCISM auto {int(time.time())}"),
        "adversary": {"adversary_id": adv},
        "planner": {"id": planner},
        "source": {"id": str(params.get("source") or "basic")},
        "group": str(params.get("group") or "red"),
        "state": "running", "autonomous": 1, "auto_close": True, "obfuscator": "plain-text",
    }
    return _req(f"{url}/api/v2/operations", hdr, method="POST", body=op) or {}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    # Offline: a saved Caldera operation export (single op or list) → results, no server needed.
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        ops = data if isinstance(data, list) else (data.get("operations") or [data])
        vulns, results = _harvest(ops, "", {}, {}, params.get("operation"))
        return {"assets": [], "vulns": vulns, "cpes": [], "emulation_results": results,
                "scenario": "Caldera (offline import)"}

    url, hdr = _client(params)
    action = str(params.get("action") or "import").strip().lower()
    assets, paw2host = _agents(url, hdr)
    op_filter = params.get("operation")
    scenario = "Caldera import"

    if action in ("launch", "run"):
        op = _launch(url, hdr, params)
        op_id = op.get("id")
        scenario = f"Caldera op {op.get('name') or op_id}"
        wait = int(params.get("wait", 0) or 0)
        op_filter = op_id or op_filter
        deadline = time.time() + wait
        while wait and op_id:
            try:
                cur = _req(f"{url}/api/v2/operations/{op_id}", hdr) or {}
                if str(cur.get("state", "")).lower() in ("finished", "cleanup", "out_of_time") or time.time() > deadline:
                    break
            except Exception:  # noqa: BLE001
                break
            time.sleep(min(10, max(2, wait // 6)))

    if str(params.get("agents_only", "")).lower() in ("1", "true", "yes"):
        return {"assets": assets, "vulns": [], "cpes": []}
    try:
        ops = _req(f"{url}/api/v2/operations", hdr) or []
    except Exception:  # noqa: BLE001
        ops = []
    vulns, results = _harvest(ops, url, hdr, paw2host, op_filter)
    return {"assets": assets, "vulns": vulns, "cpes": [], "emulation_results": results, "scenario": scenario}


if __name__ == "__main__":
    import sys
    op = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(run({"operation": op, "file": op if op and op.endswith(".json") else None}, "."), indent=2, ensure_ascii=False)[:2000])
