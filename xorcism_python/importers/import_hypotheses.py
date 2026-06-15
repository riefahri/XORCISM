"""
import_hypotheses.py — Import the "Daily CTI hunt hypotheses" from novasky.io into
XTHREAT.HYPOTHESIS.  Jerome Athias - XORCISM

Source : https://novasky.io/hunts (the "Current Hunt Hypotheses" section ; --file for a
local copy). These are working hunt ideas (not published findings), so ConfidenceLevel
is set to "Working" (the page's own framing).

Each hypothesis card (<article class="hunt-hypothesis-card">) carries: a title, a dated
"Daily Hypothesis" tag, a "Hypothesis:" statement, a "Why it matters:" note, a
"Starter hunt:" note, a category, MITRE ATT&CK tags and a source link. The statement,
note, starter, category, tags and source are combined into HypothesisDescription
(HYPOTHESIS has a fixed column set; no extra fields are added).

Target : XTHREAT.db, table HYPOTHESIS. Idempotent by HypothesisName (existing rows are
updated). HYPOTHESIS is created if missing.

Usage:
    python import_hypotheses.py
    python import_hypotheses.py --file hunts.html
    python import_hypotheses.py --url https://novasky.io/hunts
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
CONFIDENCE = "Working"  # the page calls these "working ideas, not published findings"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[ImportHypotheses] {msg}", flush=True)


def clean(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = htmllib.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def parse_date(s: str):
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


def parse_hypotheses(html: str) -> list:
    """Parse the hunt-hypothesis cards into dicts."""
    starts = [m.start() for m in re.finditer(r'<article[^>]*hunt-hypothesis-card[^>]*>', html)]
    out = []
    for pos in starts:
        end = html.find("</article>", pos)
        card = html[pos:end] if end != -1 else html[pos:]

        name = clean((re.search(r"<h3[^>]*>(.*?)</h3>", card, re.S) or [None, ""])[1])
        if not name:
            continue
        # All paragraphs of the card (statement, why-it-matters, starter-hunt).
        paras = [clean(p) for p in re.findall(r"<p[^>]*>(.*?)</p>", card, re.S)]
        paras = [p for p in paras if p]
        category = clean((re.search(r'detection-tag\s+fibratus"[^>]*>(.*?)</span>', card, re.S) or [None, ""])[1])
        tags = [clean(t) for t in re.findall(r'class="mitre-tag"[^>]*>(.*?)</span>', card, re.S)]
        tags = [t for t in tags if t and t.lower() != "daily hypothesis"]
        source = (re.search(r'hunt-hypothesis-card__source"\s+href="([^"]+)"', card) or [None, None])[1]
        date_m = re.search(r"([A-Z][a-z]{2}\.?\s+\d{1,2},\s+\d{4})", card)
        hyp_date = parse_date(date_m.group(1)) if date_m else None

        extra = []
        if category:
            extra.append(f"Category: {category}")
        if tags:
            extra.append("ATT&CK: " + ", ".join(tags))
        if source:
            extra.append(f"Source: {source}")
        description = "\n".join(paras + extra) or None

        out.append({"name": name, "description": description, "date": hyp_date})
    return out


def ensure_table(cur) -> None:
    cur.execute(
        """CREATE TABLE IF NOT EXISTS HYPOTHESIS (
             HypothesisID INTEGER PRIMARY KEY,
             HypothesisGUID TEXT, HypothesisName TEXT, HypothesisDescription TEXT,
             CreatedDate DATE, ValidFromDate DATE, ValidUntil DATE, ConfidenceLevel TEXT)"""
    )


def upsert(cur, h: dict) -> bool:
    row = cur.execute("SELECT HypothesisID FROM HYPOTHESIS WHERE HypothesisName=?", (h["name"],)).fetchone()
    if row:
        cur.execute(
            "UPDATE HYPOTHESIS SET HypothesisDescription=?, ValidFromDate=?, ConfidenceLevel=? WHERE HypothesisID=?",
            (h["description"], h["date"], CONFIDENCE, row[0]),
        )
        return False
    cur.execute(
        """INSERT INTO HYPOTHESIS
             (HypothesisGUID, HypothesisName, HypothesisDescription, CreatedDate, ValidFromDate, ConfidenceLevel)
           VALUES (?,?,?,?,?,?)""",
        (str(uuid4()), h["name"], h["description"], now(), h["date"], CONFIDENCE),
    )
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Import CTI hunt hypotheses from novasky.io into XTHREAT.HYPOTHESIS")
    ap.add_argument("--file", help="Local HTML copy instead of downloading")
    ap.add_argument("--url", help=f"Override source URL (default {DEFAULT_URL})")
    args = ap.parse_args()

    hyps = parse_hypotheses(load_html(args))
    log(f"{len(hyps)} hypotheses parsed")
    if not hyps:
        log("Nothing to import (page structure may have changed).")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout = 5000")
    cur = conn.cursor()
    ensure_table(cur)
    inserted = sum(1 for h in hyps if upsert(cur, h))
    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM HYPOTHESIS").fetchone()[0]
    conn.close()
    log(f"Done ({now()}) — {inserted} new, {len(hyps) - inserted} updated, {total} hypotheses total in XTHREAT.HYPOTHESIS.")


if __name__ == "__main__":
    main()
