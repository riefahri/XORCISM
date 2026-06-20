"""
import_awesome_tools.py — import an "awesome list" README's tool entries into XORCISM.TOOL.
Jerome Athias - XORCISM

Handles the two common awesome-list entry formats, tracking the current section heading
(any `#`..`######`) so non-tool sections can be excluded:

  * bullet links   `* [Name](https://...) - description`  (or `# comment`)
  * markdown table `| **Name** | description | install / link |`  (link cell may hold a
    markdown link, `git clone <url>`, `go install github.com/...`, `pip install <pkg>` → PyPI,
    `npm install <pkg>` → npm; bare URLs are accepted too)

Idempotent: TOOL by ToolName (case-insensitive, skips names already present). Legacy
non-autoincrement PK → new rows take MAX(ToolID)+1. Inserts are scoped to one --category.

    python import_awesome_tools.py --file osint.md --category OSINT --source awesome-osint-arsenal
    python import_awesome_tools.py --file osint.md --category OSINT --list          # report only
    python import_awesome_tools.py --url https://raw.githubusercontent.com/.../README.md --category OSINT
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sqlite3
import sys
import urllib.request
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from xorcism_python import config
    _DB_DIR = config.DB_DIR
except Exception:
    _DB_DIR = os.environ.get("XORCISM_DB_DIR", r"C:\Users\jerom\XORCISM_databases")

# Section headings (lower-cased substring match) whose entries are NOT catalogue tools.
DEFAULT_EXCLUDES = [
    "table of contents", "installation", "stats at a glance", "osint bots", "osint channels",
    "learning resources", "one-click", "awesome osint github", "dork", "get everything",
    "pick a single", "pick just what", "after install", "youtube", "table of content",
]

_HEAD = re.compile(r"^#{1,6}\s+(.*?)\s*$")
_BULLET = re.compile(r"^\s*[-*]\s+\[([^\]]+)\]\(([^)\s]+)\)\s*(?:[-–—#]\s*(.*))?$")


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _clean(s: str) -> str:
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s or "")   # markdown link -> its text
    s = s.replace("**", "").replace("`", "").strip(" *|")
    return re.sub(r"\s+", " ", s).strip()


def _trim_url(u: str) -> str:
    return u.strip().strip("`'\"").rstrip(").,>`'\" ")


def _extract_url(cell: str) -> str:
    cell = (cell or "").strip()
    m = re.search(r"\[[^\]]*\]\((https?://[^)\s]+)\)", cell)           # markdown link
    if m:
        return _trim_url(m.group(1))
    m = re.search(r"git clone\s+(https?://\S+)", cell)
    if m:
        return re.sub(r"\.git$", "", _trim_url(m.group(1)).rstrip("/"))
    m = re.search(r"go install\s+([^\s@`]+)", cell)                   # go install github.com/x/y/...@v
    if m:
        gm = re.match(r"(github\.com/[^/]+/[^/\s]+)", m.group(1))
        if gm:
            return "https://" + gm.group(1)
    m = re.search(r"pip(?:3|x)?\s+install\s+([A-Za-z0-9_.\-]+)", cell)
    if m:
        return "https://pypi.org/project/" + m.group(1) + "/"
    m = re.search(r"npm\s+install\s+(?:-g\s+)?(@?[A-Za-z0-9_.\-/]+)", cell)
    if m:
        return "https://www.npmjs.com/package/" + m.group(1)
    m = re.search(r"(https?://[^\s)|`]+)", cell)                       # bare URL
    if m:
        return _trim_url(m.group(1))
    return ""


def _split_table_row(line: str):
    """A table row '| **Name** | desc | link |' (or with a leading '# / N' column).
    Returns (name, desc, link_cell) or None."""
    if not line.lstrip().startswith("|"):
        return None
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    name = None
    idx = -1
    for i, c in enumerate(cells):
        mm = re.match(r"^\*\*(.+?)\*\*$", c)
        if mm:
            name = _clean(mm.group(1))
            idx = i
            break
    if not name:
        return None
    desc = _clean(cells[idx + 1]) if idx + 1 < len(cells) else ""
    link_cell = cells[-1] if cells else ""
    return name, desc, link_cell


def parse(md: str, excludes):
    section = ""
    excluded = False
    tools, seen = [], set()
    for line in md.splitlines():
        h = _HEAD.match(line)
        if h:
            section = _clean(h.group(1)).lower()
            excluded = any(x in section for x in excludes)
            continue
        if excluded:
            continue
        name = url = desc = None
        b = _BULLET.match(line)
        if b:
            name, url, desc = _clean(b.group(1)), b.group(2).strip(), _clean(b.group(3) or "")
        else:
            row = _split_table_row(line)
            if row:
                name, desc, url = row[0], row[1], _extract_url(row[2])
        if not name:
            continue
        k = name.lower()
        if k in seen or len(name) < 2:
            continue
        seen.add(k)
        tools.append({"name": name, "url": url or "", "description": desc or ""})
    return tools


def import_all(md: str, category: str, source: str, excludes, list_only: bool = False) -> None:
    tools = parse(md, excludes)
    print(f"[parse] {len(tools)} unique tool entr(ies) from {source}")
    if list_only:
        for t in tools:
            print(f"   {t['name']}  —  {t['url'] or '(no url)'}  —  {t['description'][:60]}")
        return

    con = sqlite3.connect(os.path.join(_DB_DIR, "XORCISM.db"), timeout=20)
    con.execute("PRAGMA busy_timeout=20000")
    cur = con.cursor()
    existing = {str(r[0]).lower() for r in cur.execute("SELECT ToolName FROM TOOL WHERE ToolName IS NOT NULL")}
    tid = cur.execute("SELECT COALESCE(MAX(ToolID),0) FROM TOOL").fetchone()[0]
    n_new = n_skip = 0
    for t in tools:
        if t["name"].lower() in existing:
            n_skip += 1
            continue
        tid += 1
        cur.execute(
            "INSERT INTO TOOL (ToolID, ToolGUID, ToolName, ToolDescription, Category, ToolURL, "
            "CreatedDate, ValidFromDate, VocabularyID, isEncrypted) VALUES (?,?,?,?,?,?,?,?,1,0)",
            (tid, str(uuid.uuid4()), t["name"][:200], (t["description"][:2000] or None),
             category, (t["url"][:500] or None), _now(), _now()),
        )
        existing.add(t["name"].lower())
        n_new += 1
    con.commit()
    con.close()
    print(f"[TOOL] {n_new} new (Category='{category}'), {n_skip} already present (deduped by ToolName)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Import an awesome-list README's tools → XORCISM.TOOL")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="parse a saved README.md")
    src.add_argument("--url", help="fetch the README from a raw URL")
    ap.add_argument("--category", required=True, help="TOOL.Category to assign (e.g. OSINT, IoT)")
    ap.add_argument("--source", default="awesome-list", help="label for logging")
    ap.add_argument("--exclude", action="append", default=None,
                    help="extra section substring(s) to exclude (repeatable); replaces defaults if --no-default-excludes")
    ap.add_argument("--no-default-excludes", action="store_true")
    ap.add_argument("--list", action="store_true", help="parse + report, write nothing")
    a = ap.parse_args()
    if a.file:
        md = open(a.file, encoding="utf-8", errors="replace").read()
    else:
        req = urllib.request.Request(a.url, headers={"User-Agent": "XORCISM awesome importer"})
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
            md = r.read().decode("utf-8", "replace")
    excludes = [] if a.no_default_excludes else list(DEFAULT_EXCLUDES)
    if a.exclude:
        excludes += [x.lower() for x in a.exclude]
    import_all(md, a.category, a.source, excludes, a.list)


if __name__ == "__main__":
    main()
