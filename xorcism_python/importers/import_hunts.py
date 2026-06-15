"""
import_hunts.py — Import threat hunts from novasky.io into XTHREAT.HUNT.
Jerome Athias - XORCISM

Source : https://novasky.io/hunts (server-rendered HTML ; --file for a local copy).
Each hunt card carries: title, publication date, detection status, a hypothesis
paragraph, a findings paragraph, the tool, and MITRE ATT&CK technique tags.

Target : XTHREAT.db, table HUNT. The importer makes the table self-sufficient:
it creates HUNT if missing and ALTERs in any missing column, so it runs against an
existing database whatever the server version. Idempotent by HuntReference (the hunt
URL): existing rows are updated, new ones inserted (HuntID auto-increments).

Usage:
    python import_hunts.py                 # download and import
    python import_hunts.py --file hunts.html
    python import_hunts.py --url https://novasky.io/hunts
"""
import argparse
import html as htmllib
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from uuid import uuid4

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from xorcism_python import config  # noqa: E402

DB_PATH = os.path.join(config.DB_DIR, "XTHREAT.db")
DEFAULT_URL = "https://novasky.io/hunts"
SOURCE = "novasky.io"

# Full HUNT schema (kept in sync with ensureThreatTables() in xorcism_ts/server/db.ts).
HUNT_COLUMNS = {
    "HuntID": "INTEGER PRIMARY KEY",
    "HuntGUID": "TEXT",
    "HuntName": "TEXT",
    "HuntDescription": "TEXT",
    "CreatedDate": "DATE",
    "HuntReference": "TEXT",
    "ValidFrom": "DATE",
    "ValidUntil": "DATE",
    "HuntStatus": "TEXT",
    "HuntDate": "DATE",
    "HuntTool": "TEXT",
    "AttackTags": "TEXT",
    "HuntFindings": "TEXT",
    "HuntSource": "TEXT",
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportHunts] {msg}", flush=True)


def clean(s: str) -> str:
    """Strip HTML tags, unescape entities, collapse whitespace."""
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = htmllib.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def parse_date(s: str):
    """'Mar 31, 2026' -> '2026-03-31' ; returns None if unparseable."""
    for fmt in ("%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def load_html(args) -> str:
    if args.file:
        log(f"Reading file {args.file}")
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read()
    url = args.url or DEFAULT_URL
    log(f"Downloading {url}")
    r = requests.get(url, timeout=60, headers={"User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"})
    r.raise_for_status()
    return r.text


def parse_hunts(html: str, base: str = "https://novasky.io") -> list:
    """Return a list of hunt dicts parsed from the hunt-listing cards."""
    # Each hunt is an anchor card: <a href="/hunts/SLUG" class="card"> ... </a>
    starts = [(m.start(), m.group(1)) for m in
              re.finditer(r'<a\s+href="(/hunts/[a-z0-9-]+)"\s+class="card"', html)]
    hunts = []
    for pos, href in starts:
        # A card is a single <a>...</a> with no nested anchors, so it ends at the
        # first </a> after its start (NOT at the next card / end of file, otherwise
        # the last card would slurp the rest of the page, e.g. CTI hypothesis tags).
        end = html.find("</a>", pos)
        card = html[pos:end] if end != -1 else html[pos:]

        title = clean((re.search(r"<h3[^>]*>(.*?)</h3>", card, re.S) or [None, ""])[1])
        status = clean((re.search(r'detection-tag\s+lima"[^>]*>(.*?)</span>', card, re.S) or [None, ""])[1])
        date_m = re.search(r"([A-Z][a-z]{2}\.?\s+\d{1,2},\s+\d{4})", card)
        hunt_date = parse_date(date_m.group(1)) if date_m else None
        # First paragraph = hypothesis (italic), second = findings.
        paras = re.findall(r"<p[^>]*>(.*?)</p>", card, re.S)
        description = clean(paras[0]) if len(paras) >= 1 else ""
        findings = clean(paras[1]) if len(paras) >= 2 else ""
        tool = clean((re.search(r'detection-tag\s+fibratus"[^>]*>(.*?)</span>', card, re.S) or [None, ""])[1])
        tags = [clean(t) for t in re.findall(r'class="mitre-tag"[^>]*>(.*?)</span>', card, re.S)]
        tags = [t for t in tags if t]

        if not title:
            continue
        hunts.append({
            "name": title,
            "reference": base + href,
            "status": status or None,
            "date": hunt_date,
            "description": description or None,
            "findings": findings or None,
            "tool": tool or None,
            "attack_tags": ", ".join(tags) if tags else None,
        })
    return hunts


def ensure_table(cur) -> None:
    cols_sql = ", ".join(f"{n} {t}" for n, t in HUNT_COLUMNS.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS HUNT ({cols_sql})")
    existing = {r[1] for r in cur.execute("PRAGMA table_info(HUNT)").fetchall()}
    for name, typ in HUNT_COLUMNS.items():
        if name not in existing:
            # PRIMARY KEY can't be added by ALTER, but it only applies to a freshly
            # created table; an existing HUNT already has its PK.
            coltype = typ.replace(" PRIMARY KEY", "")
            cur.execute(f'ALTER TABLE HUNT ADD COLUMN {name} {coltype}')
            log(f"Added column HUNT.{name}")


def upsert(cur, h: dict) -> bool:
    """Insert or update by HuntReference. Returns True if a new row was inserted."""
    row = cur.execute("SELECT HuntID FROM HUNT WHERE HuntReference=?", (h["reference"],)).fetchone()
    if row:
        cur.execute(
            """UPDATE HUNT SET HuntName=?, HuntDescription=?, HuntReference=?,
                 HuntStatus=?, HuntDate=?, HuntTool=?, AttackTags=?, HuntFindings=?, HuntSource=?
               WHERE HuntID=?""",
            (h["name"], h["description"], h["reference"], h["status"], h["date"],
             h["tool"], h["attack_tags"], h["findings"], SOURCE, row[0]),
        )
        return False
    cur.execute(
        """INSERT INTO HUNT
             (HuntGUID, HuntName, HuntDescription, CreatedDate, HuntReference,
              HuntStatus, HuntDate, HuntTool, AttackTags, HuntFindings, HuntSource)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (str(uuid4()), h["name"], h["description"], now(), h["reference"],
         h["status"], h["date"], h["tool"], h["attack_tags"], h["findings"], SOURCE),
    )
    return True


def _table_exists(cur, name: str) -> bool:
    return cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def link_hunt_ioc(cur) -> int:
    """Auto-link HUNT <-> IOC when they share an ATT&CK technique.

    Hunt techniques come from HUNTATTACK; IOC techniques are extracted (regex Txxxx[.xxx])
    from the IOC's STIX text fields (KillChainPhases, ExternalReferences, Labels, Pattern,
    name, description). Idempotent (UNIQUE(HuntID, IOCID), Relationship='shared-technique').
    Returns the number of new links (0 when there are no IOCs / no shared techniques).
    """
    cur.execute(
        """CREATE TABLE IF NOT EXISTS HUNTIOC (
             HuntIOCID INTEGER PRIMARY KEY, HuntID INTEGER, IOCID INTEGER,
             Relationship TEXT, CreatedDate DATE, UNIQUE(HuntID, IOCID))"""
    )
    if not _table_exists(cur, "IOC") or not _table_exists(cur, "HUNTATTACK"):
        return 0
    hunt_tech: dict = {}
    for hid, aid in cur.execute("SELECT HuntID, AttackID FROM HUNTATTACK").fetchall():
        if aid:
            hunt_tech.setdefault(hid, set()).add(aid)
    if not hunt_tech:
        return 0
    cols = {r[1] for r in cur.execute("PRAGMA table_info(IOC)").fetchall()}
    scan = [c for c in ("KillChainPhases", "ExternalReferences", "Labels", "IndicatorTypes",
                        "Pattern", "IOCName", "IOCDescription") if c in cols]
    if not scan:
        return 0
    new_links = 0
    for row in cur.execute(f"SELECT IOCID, {', '.join(scan)} FROM IOC").fetchall():
        ioc_id = row[0]
        techs = set(_ATTACK_RE.findall(" ".join(str(x) for x in row[1:] if x)))
        if not techs:
            continue
        for hid, htechs in hunt_tech.items():
            if htechs & techs:
                cur.execute(
                    "INSERT OR IGNORE INTO HUNTIOC (HuntID, IOCID, Relationship, CreatedDate) VALUES (?,?,?,?)",
                    (hid, ioc_id, "shared-technique", now()),
                )
                new_links += cur.rowcount
    return new_links


def link_hunt_attack(cur) -> int:
    """Rebuild HUNT <-> ATT&CK technique cross-links from HUNT.AttackTags.

    Each comma-separated technique id in AttackTags becomes a HUNTATTACK row,
    resolving AttackTechniqueID from ATTACKTECHNIQUE when ATT&CK is imported.
    Idempotent (UNIQUE(HuntID, AttackID)). Returns the number of new links.
    """
    cur.execute(
        """CREATE TABLE IF NOT EXISTS HUNTATTACK (
             HuntAttackID INTEGER PRIMARY KEY, HuntID INTEGER, AttackID TEXT,
             AttackTechniqueID INTEGER, CreatedDate DATE, UNIQUE(HuntID, AttackID))"""
    )
    has_attack = cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ATTACKTECHNIQUE'"
    ).fetchone() is not None
    new_links = 0
    rows = cur.execute(
        "SELECT HuntID, AttackTags FROM HUNT WHERE AttackTags IS NOT NULL AND AttackTags<>''"
    ).fetchall()
    for hunt_id, tags in rows:
        for raw in tags.split(","):
            aid = raw.strip()
            if not aid:
                continue
            techid = None
            if has_attack:
                t = cur.execute(
                    "SELECT AttackTechniqueID FROM ATTACKTECHNIQUE WHERE AttackID=? LIMIT 1", (aid,)
                ).fetchone()
                techid = t[0] if t else None
            cur.execute(
                "INSERT OR IGNORE INTO HUNTATTACK (HuntID, AttackID, AttackTechniqueID, CreatedDate) VALUES (?,?,?,?)",
                (hunt_id, aid, techid, now()),
            )
            new_links += cur.rowcount
    return new_links


def main() -> None:
    ap = argparse.ArgumentParser(description="Import threat hunts from novasky.io into XTHREAT.HUNT")
    ap.add_argument("--file", help="Local HTML copy instead of downloading")
    ap.add_argument("--url", help=f"Override source URL (default {DEFAULT_URL})")
    args = ap.parse_args()

    hunts = parse_hunts(load_html(args))
    log(f"{len(hunts)} hunts parsed")
    if not hunts:
        log("Nothing to import (page structure may have changed).")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    ensure_table(cur)
    inserted = sum(1 for h in hunts if upsert(cur, h))
    new_links = link_hunt_attack(cur)
    new_ioc = link_hunt_ioc(cur)
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM HUNT").fetchone()[0]
    nlinks = cur.execute("SELECT COUNT(*) FROM HUNTATTACK").fetchone()[0]
    niocs = cur.execute("SELECT COUNT(*) FROM HUNTIOC").fetchone()[0]
    conn.close()
    log(f"Done ({now()}) — {inserted} new, {len(hunts) - inserted} updated, {total} hunts total; "
        f"{new_links} new HUNTATTACK links ({nlinks} total); {new_ioc} new HUNTIOC links ({niocs} total).")


if __name__ == "__main__":
    main()
