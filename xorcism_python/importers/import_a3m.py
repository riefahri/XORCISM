"""
import_a3m.py — Import the A3M (Agentic AI Attack Matrix) into XTHREAT.
Jerome Athias - XORCISM

Source: https://www.cyberriskevaluator.com/A3M_Matrix_Agentic_AI_Attack_Matrix.html
(static HTML ; --file for a local copy). The matrix lists tactic columns
(<section class="col"> with a <div class="col-header">) of techniques
(<div class="card"> with <div class="tid">AAT-####</div><div class="tname">…</div>).

Target: XTHREAT.db — A3MTACTIC (matrix order) + A3MTECHNIQUE (AATID UNIQUE). Idempotent.

Usage:
    python import_a3m.py
    python import_a3m.py --file a3m.html
"""
import argparse
import html as htmllib
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
DEFAULT_URL = "https://www.cyberriskevaluator.com/A3M_Matrix_Agentic_AI_Attack_Matrix.html"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportA3M] {msg}", flush=True)


def clean(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", htmllib.unescape(s)).strip()


def load_html(args) -> str:
    if args.file:
        log(f"Reading file {args.file}")
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read()
    log(f"Downloading {DEFAULT_URL}")
    r = requests.get(DEFAULT_URL, timeout=60, headers={"User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"})
    r.raise_for_status()
    return r.text


def parse(html: str):
    """Return [(tactic_name, [(aatid, name), ...]), ...] in matrix order."""
    out = []
    # Each tactic is a <section class="col">…</section> with a col-header + cards.
    sections = re.split(r'<section\b[^>]*class="[^"]*\bcol\b[^"]*"', html)[1:]
    for sec in sections:
        sec = sec.split("</section>")[0]
        hm = re.search(r'class="col-header"[^>]*>(.*?)</div>', sec, re.S)
        if not hm:
            continue
        tactic = clean(hm.group(1))
        cards = re.findall(r'class="tid"[^>]*>(.*?)</div>\s*<div[^>]*class="tname"[^>]*>(.*?)</div>', sec, re.S)
        techs = [(clean(tid), clean(name)) for tid, name in cards if clean(tid)]
        if tactic and techs:
            out.append((tactic, techs))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Import the A3M (Agentic AI Attack Matrix) into XTHREAT")
    ap.add_argument("--file", help="Local HTML copy instead of downloading")
    args = ap.parse_args()

    matrix = parse(load_html(args))
    n_tech = sum(len(t) for _, t in matrix)
    log(f"{len(matrix)} tactics, {n_tech} techniques parsed")
    if not matrix:
        log("Nothing parsed (page structure may have changed).")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS A3MTACTIC (A3MTacticID INTEGER PRIMARY KEY, Name TEXT UNIQUE, MatrixOrder INTEGER, URL TEXT)")
    cur.execute("""CREATE TABLE IF NOT EXISTS A3MTECHNIQUE (
        A3MTechniqueID INTEGER PRIMARY KEY, AATID TEXT UNIQUE, Name TEXT, Description TEXT,
        TacticName TEXT, MatrixOrder INTEGER, URL TEXT)""")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_a3mtech_tactic ON A3MTECHNIQUE(TacticName)")

    new = 0
    for ti, (tactic, techs) in enumerate(matrix, start=1):
        cur.execute(
            """INSERT INTO A3MTACTIC (Name, MatrixOrder, URL) VALUES (?,?,?)
               ON CONFLICT(Name) DO UPDATE SET MatrixOrder=excluded.MatrixOrder""",
            (tactic, ti, DEFAULT_URL),
        )
        for oi, (aatid, name) in enumerate(techs, start=1):
            cur.execute(
                """INSERT INTO A3MTECHNIQUE (AATID, Name, TacticName, MatrixOrder, URL) VALUES (?,?,?,?,?)
                   ON CONFLICT(AATID) DO UPDATE SET Name=excluded.Name, TacticName=excluded.TacticName,
                     MatrixOrder=excluded.MatrixOrder""",
                (aatid, name, tactic, oi, DEFAULT_URL),
            )
            new += cur.rowcount
    conn.commit()
    tac = cur.execute("SELECT COUNT(*) FROM A3MTACTIC").fetchone()[0]
    tech = cur.execute("SELECT COUNT(*) FROM A3MTECHNIQUE").fetchone()[0]
    conn.close()
    log(f"Done ({now()}) — {tac} tactics, {tech} techniques in XTHREAT.A3M*.")


if __name__ == "__main__":
    main()
