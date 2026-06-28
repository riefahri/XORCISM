"""import_ttpforge.py - import Meta's TTPForge TTPs into XTHREAT.ATOMICTEST (BAS library).

TTPForge (github.com/facebookincubator/TTPForge) is Meta's open-source cyber attack-simulation
platform: a Purple-Team engine that automates attacker tactics, techniques and procedures (TTPs)
authored in a declarative YAML format (api_version 2.0) - name / description / optional MITRE
ATT&CK mapping / args / multi-step actions (inline, create_file, edit_file, copy_path, fetch_uri,
http_request, subttp, ...) each with last-in-first-out cleanup.

This makes XORCISM understand the TTPForge format: it parses any TTPForge TTP repository and loads
each TTP as a row in XORCISM's adversary-emulation library, exactly like the Atomic Red Team importer:

  XTHREAT.ATOMICTEST   one row per TTP; Source="TTPForge"; AtomicGUID = the TTP's uuid;
                       AttackID resolved from the `mitre:` block (-> ATTACKTECHNIQUE), Command =
                       a readable rendering of the steps, Cleanup = the steps' cleanup actions.
  XTHREAT.EMULATIONSCENARIO + SCENARIOTEST   the imported TTPs grouped into one runnable scenario.

The imported TTPs feed the BAS / ATT&CK validation-coverage heatmap (/attack) and the emulation
scenarios. Data: a committed snapshot at importers/data/ttpforge.json (parsed from the repo's
example-ttps). Pass `--repo <path>` to re-parse a freshly cloned TTPForge repo (or any repo of
TTPForge-format TTPs - e.g. your own red-team library) and refresh the snapshot. PyYAML is required
ONLY for `--repo`; the default snapshot import has no dependency. MIT-licensed source. Idempotent
(upsert by AtomicGUID). DB dir = XORCISM_DB_DIR env or the default.

    python xorcism_python/importers/import_ttpforge.py
    python xorcism_python/importers/import_ttpforge.py --repo /path/to/TTPForge
    python xorcism_python/importers/import_ttpforge.py --repo /path/to/your-ttp-library --label "Red Team Library"
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_URL

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ttpforge.json")
SOURCE = "TTPForge"
REPO_URL = "https://github.com/facebookincubator/TTPForge"
TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportTTPForge] {msg}", flush=True)


def _clean(s: object) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()


def _attack_ids(mitre: dict) -> str:
    """Extract ATT&CK technique ids from a TTPForge `mitre:` block (prefer sub-techniques)."""
    if not isinstance(mitre, dict):
        return ""
    subs, techs = [], []
    for v in (mitre.get("subtechniques") or []):
        subs += TID.findall(str(v))
    for v in (mitre.get("techniques") or []):
        techs += TID.findall(str(v))
    ids = subs or techs
    # de-dupe, keep order
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i); out.append(i)
    return ", ".join(out)


def _platforms(ttp: dict) -> str:
    """Best-effort platform inference from requirements + step executors."""
    plats = set()
    req = ttp.get("requirements")
    if isinstance(req, dict):
        pls = req.get("platforms")
        if isinstance(pls, list):                      # v2: requirements.platforms[].os
            for p in pls:
                if isinstance(p, dict) and p.get("os"):
                    plats.add(str(p["os"]).lower())
        elif isinstance(req.get("os"), str):
            plats.add(req["os"].lower())
    txt = json.dumps(ttp).lower()
    if "powershell" in txt or "pwsh" in txt or '"cmd"' in txt or "windows" in txt:
        plats.add("windows")
    if re.search(r'"executor"\s*:\s*"(sh|bash|zsh|python3?)"', txt) or "linux" in txt:
        plats.add("linux")
    if "darwin" in txt or "macos" in txt:
        plats.add("macos")
    return ", ".join(sorted(plats)) if plats else "multi"


def _render_steps(steps: list) -> tuple[str, str]:
    """Render a TTP's steps into a readable Command string + a Cleanup string."""
    cmd_parts, cleanup_parts = [], []
    for st in steps or []:
        if not isinstance(st, dict):
            continue
        name = _clean(st.get("name") or "step")
        line = None
        if "inline" in st:
            ex = st.get("executor")
            head = f"# {name}" + (f" (executor: {ex})" if ex else "")
            line = head + "\n" + str(st["inline"]).rstrip()
        elif "print_str" in st:
            line = f"# {name}: print message"
        elif "create_file" in st:
            line = f"# {name}: create_file {st.get('create_file')}" + (f" (mode {st.get('mode')})" if st.get("mode") else "")
        elif "edit_file" in st:
            line = f"# {name}: edit_file {st.get('edit_file')}"
        elif "copy_path" in st:
            line = f"# {name}: copy_path {st.get('copy_path')} -> {st.get('to', '')}"
        elif "remove_path" in st:
            line = f"# {name}: remove_path {st.get('remove_path')}"
        elif "subttp" in st:
            line = f"# {name}: subttp {st.get('subttp')}"
        elif "fetch_uri" in st:
            line = f"# {name}: fetch_uri {st.get('fetch_uri')} -> {st.get('location', '')}"
        elif "http_request" in st or "uri" in st:
            line = f"# {name}: http_request {st.get('uri', st.get('http_request', ''))}"
        elif "change_directory" in st:
            line = f"# {name}: change_directory {st.get('change_directory')}"
        elif "kill_process" in st:
            line = f"# {name}: kill_process"
        elif "expect" in st:
            line = f"# {name}: expect interactive session"
        else:
            line = f"# {name}"
        if line:
            cmd_parts.append(line)
        cu = st.get("cleanup")
        if isinstance(cu, dict) and "inline" in cu:
            cleanup_parts.append(f"# cleanup {name}\n" + str(cu["inline"]).rstrip())
        elif cu == "default":
            cleanup_parts.append(f"# cleanup {name}: automatic (default)")
    return ("\n".join(cmd_parts))[:4000], ("\n".join(cleanup_parts))[:4000]


def _is_ttp(doc: object) -> bool:
    return isinstance(doc, dict) and bool(doc.get("name")) and ("steps" in doc or "mitre" in doc)


def _search_paths(repo: str) -> list[str]:
    cfg = os.path.join(repo, "ttpforge-repo-config.yaml")
    paths = []
    if os.path.isfile(cfg):
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(open(cfg, encoding="utf-8")) or {}
            paths = [os.path.join(repo, p) for p in (data.get("ttp_search_paths") or []) if isinstance(p, str)]
        except Exception:
            paths = []
    if not paths:
        for cand in ("example-ttps", "ttps", "."):
            if os.path.isdir(os.path.join(repo, cand)):
                paths.append(os.path.join(repo, cand)); break
    return paths or [repo]


def _parse_repo(repo: str, label: str) -> dict:
    import yaml  # type: ignore  # required only for --repo
    ttps, seen = [], set()
    for base in _search_paths(repo):
        for f in sorted(glob.glob(os.path.join(base, "**", "*.yaml"), recursive=True)):
            rel = os.path.relpath(f, repo).replace("\\", "/")
            if rel.endswith("ttpforge-repo-config.yaml"):
                continue
            if "/tests/" in f.replace("\\", "/") + "/":   # skip framework self-test fixtures
                continue
            try:
                docs = list(yaml.safe_load_all(open(f, encoding="utf-8")))
            except Exception as e:
                log(f"  ! skip {rel}: {e}")
                continue
            for doc in docs:
                if not _is_ttp(doc):
                    continue
                uid = str(doc.get("uuid") or "").strip() or str(uuid5(NAMESPACE_URL, "xorcism-ttpforge:" + rel + ":" + str(doc.get("name"))))
                if uid in seen:
                    continue
                seen.add(uid)
                attack = _attack_ids(doc.get("mitre") or {})
                command, cleanup = _render_steps(doc.get("steps") or [])
                args = [a.get("name") for a in (doc.get("args") or []) if isinstance(a, dict) and a.get("name")]
                category = rel.split("/")[1] if rel.startswith("example-ttps/") and "/" in rel[13:] else (rel.split("/")[-2] if "/" in rel else "")
                ttps.append({
                    "uuid": uid, "name": _clean(doc.get("name"))[:255],
                    "description": _clean(doc.get("description"))[:4000],
                    "attackId": attack, "platform": _platforms(doc),
                    "executor": SOURCE.lower(), "command": command, "cleanup": cleanup,
                    "args": ", ".join(args)[:500], "category": category, "path": rel,
                })
    return {"meta": {"title": "TTPForge TTPs", "publisher": "Meta Platforms (facebookincubator)",
                     "source": REPO_URL, "label": label, "count": len(ttps),
                     "mapped": sum(1 for t in ttps if t["attackId"])}, "ttps": ttps}


def ensure_table(cur) -> None:
    cur.execute(
        """CREATE TABLE IF NOT EXISTS ATOMICTEST (
             AtomicTestID INTEGER PRIMARY KEY, AtomicGUID TEXT UNIQUE, Name TEXT, Description TEXT,
             AttackID TEXT, AttackTechniqueID INTEGER, Platform TEXT, Executor TEXT,
             Command TEXT, Cleanup TEXT, Source TEXT, ExternalReferences TEXT, CreatedDate DATE)""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_atomic_attack ON ATOMICTEST(AttackID)")
    cur.execute(
        """CREATE TABLE IF NOT EXISTS EMULATIONSCENARIO (
             ScenarioID INTEGER PRIMARY KEY, ScenarioGUID TEXT, Name TEXT, Description TEXT,
             AdversaryRef TEXT, KillChainPhase TEXT, Status TEXT, Confidence INTEGER, TLP TEXT, Labels TEXT,
             CreatedDate DATE, ValidFrom DATE, ValidUntil DATE)""")
    cur.execute(
        """CREATE TABLE IF NOT EXISTS SCENARIOTEST (
             ScenarioTestID INTEGER PRIMARY KEY, ScenarioID INTEGER, AtomicTestID INTEGER,
             StepOrder INTEGER, CreatedDate DATE, UNIQUE(ScenarioID, AtomicTestID))""")


def _tech_id(cur, attack_id: str, has_attack: bool):
    first = (attack_id.split(",")[0].strip() if attack_id else "")
    if not has_attack or not first:
        return None
    r = cur.execute("SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1", (first,)).fetchone()
    return r[0] if r else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Import TTPForge TTPs into XTHREAT.ATOMICTEST")
    ap.add_argument("--repo", help="Path to a cloned TTPForge repo (or any TTPForge-format TTP library) to (re)parse")
    ap.add_argument("--label", default="", help="Scenario label (default: 'Example TTPs', or the repo basename)")
    args = ap.parse_args()

    if args.repo:
        label = args.label or (os.path.basename(os.path.normpath(args.repo)) or "Example TTPs")
        data = _parse_repo(args.repo, label)
        os.makedirs(os.path.dirname(DATA), exist_ok=True)
        json.dump(data, open(DATA, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        log(f"re-parsed: {data['meta']['count']} TTPs ({data['meta']['mapped']} ATT&CK-mapped) -> {DATA}")

    if not os.path.isfile(DATA):
        raise SystemExit(f"No snapshot at {DATA}. Run with --repo <path-to-TTPForge> first.")
    data = json.load(open(DATA, encoding="utf-8"))
    ttps = data.get("ttps", [])
    label = args.label or data.get("meta", {}).get("label") or "Example TTPs"
    log(f"{len(ttps)} TTPForge TTPs to import (label '{label}')")
    if not ttps:
        return 0

    conn = sqlite3.connect(DB_PATH); conn.execute("PRAGMA busy_timeout=15000"); cur = conn.cursor()
    ensure_table(cur)
    has_attack = cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'").fetchone() is not None
    new = 0
    for t in ttps:
        techid = _tech_id(cur, t.get("attackId", ""), has_attack)
        refs = f"{REPO_URL}/blob/main/{t.get('path', '')}" + (f" | args: {t['args']}" if t.get("args") else "")
        cur.execute(
            """INSERT INTO ATOMICTEST
                 (AtomicGUID, Name, Description, AttackID, AttackTechniqueID, Platform, Executor, Command, Cleanup, Source, ExternalReferences, CreatedDate)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(AtomicGUID) DO UPDATE SET Name=excluded.Name, Description=excluded.Description,
                 AttackID=excluded.AttackID, AttackTechniqueID=excluded.AttackTechniqueID, Platform=excluded.Platform,
                 Executor=excluded.Executor, Command=excluded.Command, Cleanup=excluded.Cleanup,
                 Source=excluded.Source, ExternalReferences=excluded.ExternalReferences""",
            (t["uuid"], t["name"], t.get("description", ""), t.get("attackId", ""), techid, t.get("platform", ""),
             t.get("executor", SOURCE.lower()), t.get("command", ""), t.get("cleanup", ""), SOURCE, refs, now()))
        new += 1 if cur.rowcount else 0

    # Group the imported TTPs into one runnable scenario (idempotent by GUID).
    sc_name = f"TTPForge - {label}"
    sc_guid = str(uuid5(NAMESPACE_URL, "xorcism-scenario:" + sc_name))
    row = cur.execute("SELECT ScenarioID FROM EMULATIONSCENARIO WHERE ScenarioGUID=?", (sc_guid,)).fetchone()
    desc = f"Adversary-emulation TTPs from TTPForge ({label}). {REPO_URL}"
    if row:
        sid = row[0]
        cur.execute("UPDATE EMULATIONSCENARIO SET Name=?, Description=?, Status=? WHERE ScenarioID=?", (sc_name, desc, "Ready", sid))
    else:
        cur.execute(
            """INSERT INTO EMULATIONSCENARIO (ScenarioGUID, Name, Description, AdversaryRef, KillChainPhase, Status, TLP, CreatedDate)
               VALUES (?,?,?,?,?,?,?,?)""", (sc_guid, sc_name, desc, "TTPForge", "", "Ready", "CLEAR", now()))
        sid = cur.lastrowid
    guids = [t["uuid"] for t in ttps]
    ph = ",".join("?" * len(guids))
    id_by_guid = {g: i for (i, g) in cur.execute(f"SELECT AtomicTestID, AtomicGUID FROM ATOMICTEST WHERE AtomicGUID IN ({ph})", guids).fetchall()}
    n_link = 0
    for order, t in enumerate(ttps, 1):
        tid = id_by_guid.get(t["uuid"])
        if tid is None:
            continue
        cur.execute("INSERT OR IGNORE INTO SCENARIOTEST (ScenarioID, AtomicTestID, StepOrder, CreatedDate) VALUES (?,?,?,?)", (sid, tid, order, now()))
        n_link += cur.rowcount

    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM ATOMICTEST WHERE Source=?", (SOURCE,)).fetchone()[0]
    resolved = cur.execute("SELECT COUNT(*) FROM ATOMICTEST WHERE Source=? AND AttackTechniqueID IS NOT NULL", (SOURCE,)).fetchone()[0]
    techniques = cur.execute("SELECT COUNT(DISTINCT AttackID) FROM ATOMICTEST WHERE Source=? AND AttackID<>''", (SOURCE,)).fetchone()[0]
    conn.close()
    log(f"Done ({now()}) - {new} new/updated, {total} TTPForge TTPs total "
        f"({techniques} distinct ATT&CK techniques, {resolved} linked to ATTACKTECHNIQUE); "
        f"scenario '{sc_name}' (+{n_link} test links).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
