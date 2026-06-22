"""run.py — XORCISM connector for Atomic Red Team (BAS / Adversarial Exposure Validation).

Runs Atomic Red Team (redcanaryco) atomic tests on the (possibly remote) worker host and reports
the per-test outcome back to XORCISM's emulation layer (XTHREAT.EMULATIONRUN / EMULATIONRESULT via
runner.import_emulation), which powers the ATT&CK validation-coverage heatmap (/attack). This is
the "validate" stage of CTEM / Adversarial Exposure Validation (AEV) — safely run a known attack
technique on an authorized host and see whether your controls prevent/detect it.

It wraps the canonical **Invoke-AtomicTest** (the standard Atomic Red Team / Invoke-AtomicRedTeam
PowerShell executor that defenders use), so XORCISM does not ship novel offensive code.

SAFETY — by default this connector does NOT execute anything:
  * execute=false (DEFAULT) : plan/check only — lists the atomics for the technique (and optionally
                              checks prerequisites) WITHOUT running them. Outcome = "Planned".
  * execute=true            : actually runs the atomics (Invoke-AtomicTest -Confirm:$false), then
                              optionally cleans up. Only do this on hosts inside your authorized
                              engagement scope (the runner enforces the ROE for target-type params).
Modes for the input:
  * live   : Invoke-AtomicTest available on the host -> plan or execute the `technique`.
  * offline: params["file"] -> import a saved result list (e.g. Invoke-AtomicTest -PassThru export).
  * demo   : neither -> a built-in 2-atomic sample (Outcome "No result (simulated)") so the import
             path + coverage heatmap are exercisable without running anything.

Result shape: {"emulation_results":[{technique, atomic_guid, name, executor, outcome, detail, host}],
               "host", "scenario", "executed"(bool)}. Worker-safe: stdlib only, no DB access.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from typing import Any, Dict, List

TOOL_URL = "https://github.com/redcanaryco/atomic-red-team"
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_TESTLINE = re.compile(r"(T\d{4}(?:\.\d{3})?)-(\d+)\s+(.*)", re.I)


def _host() -> str:
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "localhost"


def _pwsh() -> str | None:
    for exe in ("pwsh", "powershell"):
        try:
            subprocess.run([exe, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"],
                           capture_output=True, timeout=20)
            return exe
        except Exception:  # noqa: BLE001
            continue
    return None


def _have_invoke(pwsh: str) -> bool:
    try:
        r = subprocess.run([pwsh, "-NoProfile", "-Command", "if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {'yes'} else {'no'}"],
                           capture_output=True, text=True, timeout=30)
        return "yes" in (r.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def _sample(technique: str) -> List[Dict[str, Any]]:
    t = technique or "T1059.001"
    return [
        {"technique": t, "atomic_guid": "3ff64f0b-3af2-3866-339d-38d9791407c3",
         "name": "PowerShell - Mshta/script execution (sample)", "executor": "powershell",
         "outcome": "No result (simulated)", "detail": "Demo entry — Invoke-AtomicTest not present; nothing executed.", "host": _host()},
        {"technique": "T1217", "atomic_guid": "16db5b03-46cb-4d2e-b78a-fc11a1c92b9a",
         "name": "Browser Bookmark Discovery (sample)", "executor": "command_prompt",
         "outcome": "No result (simulated)", "detail": "Demo entry — nothing executed.", "host": _host()},
    ]


def _parse_listing(text: str, technique: str) -> List[Dict[str, Any]]:
    """Parse `Invoke-AtomicTest <T> -ShowDetailsBrief` output → one plan entry per atomic."""
    out: List[Dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = _TESTLINE.search(line.strip())
        if m:
            out.append({"technique": m.group(1).upper(), "atomic_guid": f"{m.group(1).upper()}-{m.group(2)}",
                        "name": m.group(3).strip()[:200], "executor": "", "outcome": "Planned (not executed)",
                        "detail": "Listed via -ShowDetailsBrief; not executed.", "host": _host()})
    if not out:  # technique with atomics but odd formatting → one generic plan entry
        out.append({"technique": (technique or _TID.search(text or "") and _TID.search(text).group(0) or "T0000").upper(),
                    "atomic_guid": "", "name": "Atomic test plan", "executor": "",
                    "outcome": "Planned (not executed)", "detail": "Planned.", "host": _host()})
    return out


def _normalize_file(data: Any, technique: str) -> List[Dict[str, Any]]:
    rows = data if isinstance(data, list) else (data.get("results") or data.get("emulation_results") or data.get("tests") or [] if isinstance(data, dict) else [])
    out: List[Dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        tech = str(r.get("technique") or r.get("Technique") or r.get("attack_id") or "")
        if not _TID.search(tech):
            mm = _TID.search(str(r.get("name") or r.get("Name") or ""))
            tech = mm.group(0) if mm else (technique or "T0000")
        outcome = r.get("outcome") or r.get("Outcome")
        if not outcome:
            if "ExitCode" in r:
                outcome = "Executed" if r.get("ExitCode") in (0, "0") else "Failed"
            else:
                outcome = "Executed"
        out.append({
            "technique": _TID.search(tech).group(0).upper() if _TID.search(tech) else tech,
            "atomic_guid": str(r.get("atomic_guid") or r.get("auto_generated_guid") or r.get("GUID") or r.get("test_guid") or ""),
            "name": str(r.get("name") or r.get("Name") or r.get("test_name") or "Atomic test")[:200],
            "executor": str(r.get("executor") or r.get("Executor") or ""),
            "outcome": str(outcome),
            "detail": str(r.get("detail") or r.get("StandardOutput") or "")[:1000], "host": str(r.get("host") or _host()),
        })
    return out


def _run_invoke(pwsh: str, technique: str, test_guids: str, execute: bool, cleanup: bool, check_prereqs: bool) -> List[Dict[str, Any]]:
    args = ["Invoke-AtomicTest", technique]
    if test_guids:
        args += ["-TestGuids", *[g.strip() for g in test_guids.split(",") if g.strip()]]
    if not execute:
        cmd = f"{' '.join(args)} -ShowDetailsBrief"
        r = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=300)
        results = _parse_listing(r.stdout or "", technique)
        if check_prereqs:
            rp = subprocess.run([pwsh, "-NoProfile", "-Command", f"{' '.join(args)} -CheckPrereqs"], capture_output=True, text=True, timeout=300)
            ok = "Prerequisites met" in (rp.stdout or "")
            for x in results:
                x["detail"] += f" Prereqs: {'met' if ok else 'check output'}."
        return results
    # EXECUTE (authorized BAS): run, then optionally clean up.
    cmd = f"{' '.join(args)} -Confirm:$false"
    r = subprocess.run([pwsh, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=1800)
    out = (r.stdout or "") + "\n" + (r.stderr or "")
    blocked = bool(re.search(r"access is denied|operation.*blocked|virus|defender|quarantin|execution of scripts is disabled", out, re.I))
    errored = r.returncode != 0 or bool(re.search(r"\bERROR\b|Exception|not recognized", out))
    outcome = "Prevented" if blocked else ("Failed" if errored else "Executed")
    # one result per test mentioned, else one for the technique
    seen = [(m.group(1).upper(), m.group(2)) for m in re.finditer(r"Executing test:\s*(T\d{4}(?:\.\d{3})?)-(\d+)", out, re.I)]
    results: List[Dict[str, Any]] = []
    for tech, num in (seen or [(technique.upper(), "")]):
        results.append({"technique": tech, "atomic_guid": f"{tech}-{num}" if num else (test_guids.split(',')[0].strip() if test_guids else ""),
                        "name": f"Atomic {tech}" + (f"-{num}" if num else ""), "executor": "",
                        "outcome": outcome, "detail": out.strip()[-800:], "host": _host()})
    if cleanup:
        try:
            subprocess.run([pwsh, "-NoProfile", "-Command", f"{' '.join(args)} -Cleanup -Confirm:$false"], capture_output=True, text=True, timeout=900)
        except Exception:  # noqa: BLE001
            pass
    return results


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    technique = str(params.get("technique") or "").strip()
    target = str(params.get("target") or "").strip()      # host the atomic runs on (ROE-scoped by the runner)
    host = target or _host()
    test_guids = str(params.get("test_guids") or "").strip()
    execute = str(params.get("execute") or "").lower() in ("1", "true", "yes")
    cleanup = str(params.get("cleanup") or "").lower() in ("1", "true", "yes")
    check_prereqs = str(params.get("check_prereqs") or "true").lower() in ("1", "true", "yes")

    # Authorization: LIVE execution of intrusive atomics requires a `target` host — which the runner
    # has already revalidated against an active engagement scope (ROE) before this connector ran. No
    # target ⇒ refuse to execute (plan-only). Importing a saved result file is not execution, so it
    # is exempt. This keeps live execution authorized + audited, never blind.
    if execute and not target and not params.get("file"):
        raise RuntimeError("Executing intrusive atomic tests requires a `target` host inside an active "
                           "engagement scope (ROE). Set the target (and pick the engagement) to authorize execution.")

    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            results = _normalize_file(json.load(fh), technique)
    else:
        pwsh = _pwsh()
        if pwsh and _have_invoke(pwsh) and technique:
            results = _run_invoke(pwsh, technique, test_guids, execute, cleanup, check_prereqs)
        elif execute and technique:
            raise RuntimeError("Invoke-AtomicTest not found. Install Invoke-AtomicRedTeam on the worker "
                               f"(Install-Module -Name invoke-atomicredteam) — {TOOL_URL}")
        else:
            results = _sample(technique)
    for r in results:  # record everything against the authorized target host
        r["host"] = host
    return {"emulation_results": results, "host": host,
            "scenario": f"Atomic Red Team — {technique or 'sample'}", "executed": execute}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({"technique": "T1059.001"}, tempfile.mkdtemp()), indent=2)[:1500])
