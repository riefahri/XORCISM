"""
run.py — XORCISM connector: detections.ai Intel Exchange → XTHREAT.

Scrapes the community threat-intelligence feed at
https://detections.ai/intel-exchange with a REAL browser (Playwright / Chromium)
and captures the JSON the single-page app loads from its BFF API
(`/bff/api/v1/intel...`). Returns a normalized list of intel items; the XORCISM
runner imports them into `XTHREAT.INTELEXCHANGE` (idempotent by URL) and
cross-links MITRE ATT&CK techniques into `INTELEXCHANGEATTACK`.

This module performs NO database access, so it also runs on a remote worker:
it only returns the normalized result `{"intel": [ ... ]}`.

Lawful / authorized use only. It is polite to the site: one headless session,
a bounded number of items, a realistic User-Agent, no authentication bypass.

Offline / test mode:
    params["file"] = path to a saved BFF JSON payload (or a JSON list of items)
    → parsed instead of scraping. Used by `runner.py --selftest`.

Worker requirements (live scraping):
    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

BASE = "https://detections.ai"
SOURCE = "detections.ai"

_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ── Public entry point ────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    """Connector entry point. Returns the normalized result imported by the runner."""
    max_items = int(params.get("max_items") or 60)
    headful = bool(params.get("headful"))

    if params.get("file"):
        records = list(_iter_record_dicts(_load_json(params["file"])))
        items = _dedupe(_normalize_one(r) for r in records)
    else:
        items = _scrape(max_items, headful)

    items = [i for i in items if i.get("name")][:max_items]
    return {"intel": items, "source": SOURCE}


# ── Live scraping (real browser) ──────────────────────────────────────────────
def _scrape(max_items: int, headful: bool) -> List[Dict[str, Any]]:
    try:
        from playwright.sync_api import sync_playwright  # lazy import
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Playwright is required for live scraping. Install it on the worker:\n"
            "  pip install playwright && playwright install chromium\n"
            "(or pass file=<saved BFF json> to import offline)."
        ) from e

    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
    captured: List[Any] = []  # raw JSON bodies from /bff/api/ responses

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headful)
        ctx = browser.new_context(user_agent=ua, locale="en-US",
                                  viewport={"width": 1366, "height": 900})
        page = ctx.new_page()

        def on_response(resp) -> None:
            try:
                if "/bff/api/" not in resp.url:
                    return
                if "json" not in (resp.headers or {}).get("content-type", ""):
                    return
                captured.append(resp.json())
            except Exception:  # noqa: BLE001 — best effort, ignore non-JSON / aborted
                pass

        page.on("response", on_response)
        page.goto(f"{BASE}/intel-exchange", wait_until="domcontentloaded", timeout=60000)
        _settle(page)

        # Infinite-scroll / pagination: scroll until the item count stalls or the cap.
        items = _items_from_captured(captured)
        stalled = 0
        for _ in range(30):
            if len(items) >= max_items:
                break
            page.mouse.wheel(0, 24000)
            _settle(page, idle_ms=7000)
            new = _items_from_captured(captured)
            if len(new) <= len(items):
                stalled += 1
                if stalled >= 2 and not _click_load_more(page):
                    break
            else:
                stalled = 0
            items = new

        # Fallback: if the BFF capture yielded nothing, parse the rendered DOM.
        if not items:
            items = _scrape_dom(page)

        browser.close()
    return items


def _settle(page, idle_ms: int = 30000) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=idle_ms)
    except Exception:  # noqa: BLE001
        page.wait_for_timeout(1200)


def _click_load_more(page) -> bool:
    """Best-effort click on a 'load more' / 'next' control. Returns True if clicked."""
    for sel in ("text=/load more/i", "text=/show more/i", "text=/^more$/i",
                "button:has-text('Next')", "[aria-label*='next' i]"):
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=800):
                loc.click(timeout=1500)
                _settle(page, idle_ms=7000)
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _scrape_dom(page) -> List[Dict[str, Any]]:
    """DOM fallback: collect intel cards by their detail links. Best effort."""
    try:
        rows = page.eval_on_selector_all(
            "a[href*='/intel-exchange/'], a[href*='/intel/']",
            """els => els.map(a => {
                 const card = a.closest('article,li,div') || a;
                 return { href: a.href, text: (card.innerText || a.innerText || '').slice(0, 4000) };
               })""",
        )
    except Exception:  # noqa: BLE001
        return []
    out: List[Dict[str, Any]] = []
    for r in rows:
        text = (r.get("text") or "").strip()
        if not text:
            continue
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        title = lines[0] if lines else None
        desc = " ".join(lines[1:4]) if len(lines) > 1 else None
        out.append(_normalize_one({
            "title": title, "description": desc, "url": r.get("href"),
            "_text": text,
        }))
    return _dedupe(out)


# ── Captured-JSON extraction ──────────────────────────────────────────────────
def _items_from_captured(captured: Iterable[Any]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    for blob in captured:
        for d in _iter_record_dicts(blob):
            recs.append(_normalize_one(d))
    return _dedupe(recs)


def _iter_record_dicts(obj: Any) -> Iterable[Dict[str, Any]]:
    """Yield every dict anywhere in a JSON structure that looks like an intel record."""
    if isinstance(obj, dict):
        if _looks_like_record(obj):
            yield obj
        for v in obj.values():
            yield from _iter_record_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_record_dicts(v)


def _looks_like_record(d: Dict[str, Any]) -> bool:
    keys = {k.lower() for k in d.keys()}
    title = keys & {"title", "name", "headline"}
    body = keys & {"summary", "description", "abstract", "excerpt", "content", "body"}
    sig = keys & {"techniques", "mitretechniques", "attack", "actors", "adversaries", "tags"}
    return bool(title and (body or sig))


# ── Normalization ─────────────────────────────────────────────────────────────
def _normalize_one(d: Dict[str, Any]) -> Dict[str, Any]:
    title = _first(d, "title", "name", "headline")
    desc = _first(d, "summary", "description", "abstract", "excerpt", "content", "body")
    ext_id = _first(d, "id", "slug", "uuid", "_id", "externalId", "publicId")
    slug = _first(d, "slug") or ext_id
    url = _first(d, "url", "link", "permalink", "canonicalUrl")
    if not url:
        url = f"{BASE}/intel-exchange/{slug}" if slug else None
    reference = url or (f"{BASE}/intel-exchange#{title}" if title else None)

    author = _author(d)
    date = _iso_date(_first(d, "publishedAt", "createdAt", "postedAt", "date", "published", "updatedAt"))
    views = _int(_first(d, "views", "viewCount", "engagement", "engagements", "reads"))

    blob = json.dumps(d, default=str)  # search structured + free text for ids
    techniques = _names(d, "techniques", "mitreTechniques", "attack", "ttps") or []
    attack_ids = _uniq(_ATTACK_RE.findall(" ".join(techniques)) + _ATTACK_RE.findall(blob))
    cves = _uniq([c.upper() for c in (_names(d, "cves", "vulnerabilities", "cve")
                                      + _CVE_RE.findall(blob))])
    actors = _names(d, "actors", "adversaries", "groups", "threatActors")
    malware = _names(d, "malware", "tools", "software", "families")
    tags = _names(d, "tags", "labels", "categories")

    return {
        "name": (title or "").strip() or None,
        "description": (desc or "").strip() or None,
        "reference": reference,
        "external_id": str(ext_id) if ext_id is not None else None,
        "author": author,
        "date": date,
        "views": views,
        "attack_tags": ", ".join(attack_ids) or None,
        "cve_tags": ", ".join(cves) or None,
        "actor_tags": ", ".join(actors) or None,
        "malware_tags": ", ".join(malware) or None,
        "tags": ", ".join(tags) or None,
    }


def _author(d: Dict[str, Any]) -> Optional[str]:
    a = d.get("author") or d.get("createdBy") or d.get("user")
    if isinstance(a, dict):
        name = a.get("name") or a.get("displayName") or a.get("username")
        handle = a.get("handle") or a.get("username")
        if name and handle and handle not in name:
            return f"{name} (@{str(handle).lstrip('@')})"
        return name or (f"@{handle}" if handle else None)
    if isinstance(a, str):
        return a or None
    return _first(d, "authorName", "byline")


# ── Small helpers ─────────────────────────────────────────────────────────────
def _first(d: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return None


def _names(d: Dict[str, Any], *keys: str) -> List[str]:
    """Collect display strings from any of the given keys (list of str or list of dict)."""
    out: List[str] = []
    for k in keys:
        v = d.get(k)
        if v is None:
            continue
        for item in (v if isinstance(v, list) else [v]):
            if isinstance(item, str):
                s = item.strip()
            elif isinstance(item, dict):
                s = str(item.get("id") or item.get("name") or item.get("technique")
                        or item.get("value") or "").strip()
            else:
                s = str(item).strip()
            if s:
                out.append(s)
    return _uniq(out)


def _uniq(seq: Iterable[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for s in seq:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _int(v: Any) -> Optional[int]:
    try:
        return int(str(v).replace(",", "").strip()) if v not in (None, "") else None
    except (ValueError, TypeError):
        return None


def _iso_date(s: Any) -> Optional[str]:
    if not s:
        return None
    s = str(s)
    m = re.search(r"\d{4}-\d{2}-\d{2}", s)
    return m.group(0) if m else None


def _dedupe(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key: Dict[str, Dict[str, Any]] = {}
    for it in items:
        key = it.get("reference") or it.get("external_id") or it.get("name")
        if not key:
            continue
        # Keep the richer record if a duplicate key appears.
        prev = by_key.get(key)
        if prev is None or _richness(it) > _richness(prev):
            by_key[key] = it
    return list(by_key.values())


def _richness(it: Dict[str, Any]) -> int:
    return sum(1 for v in it.values() if v)


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── Standalone CLI (offline import test / dry run) ────────────────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="detections.ai Intel Exchange scraper (dry run)")
    ap.add_argument("--file", help="Parse a saved BFF JSON payload instead of scraping")
    ap.add_argument("--max-items", type=int, default=60)
    ap.add_argument("--headful", action="store_true", help="Visible browser window")
    a = ap.parse_args()
    res = run({"file": a.file, "max_items": a.max_items, "headful": a.headful},
              tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[detections-ai] {len(res['intel'])} item(s) normalized", flush=True)
