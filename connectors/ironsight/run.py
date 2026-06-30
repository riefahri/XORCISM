"""run.py — Import IRONSIGHT's OSINT feeds into XORCISM (CTI).

IRONSIGHT (https://github.com/NoblerWorks-HQ/IRONSIGHT, by Nobler Works) is an open-source,
real-time OSINT command center monitoring the Middle East conflict — it aggregates 50+ free,
no-API-key public sources (20+ RSS news feeds, 27 Telegram channels, conflict/strike events,
per-country regional threat levels, military aircraft & naval tracking, missile alerts, satellite
thermal detection, defense/energy/crypto/prediction markets) into a single dashboard. Next.js, MIT.

This connector maps IRONSIGHT's *intelligence* feeds (news, Telegram, conflicts, strikes,
regional alerts) to XORCISM threat-intel records (XTHREAT.INTELEXCHANGE):

  * headline / Telegram post / event title  -> IntelName
  * summary + classification metadata        -> IntelDescription
  * source link / permalink                  -> IntelReference (the idempotency key)
  * feed / source / region / category / severity -> IntelTags
  * conflict actors (IDF/IRGC/Hezbollah/Hamas/Houthi…) -> ActorTags
  * any CVE referenced in the text           -> CveTags

Config (worker environment / params, never live offensive access):
    params["file"]          an IRONSIGHT feed export in JSON — an array of items, OR an object keyed by
                            feed: {news|telegram|conflicts|strikes|regionalAlerts: [...]}.  OR
    IRONSIGHT_URL           base URL of a running IRONSIGHT instance; the read-only OSINT API routes
                            (/api/news, /api/telegram, /api/conflicts, /api/strikes, /api/regional-alerts)
                            are GET-fetched.
    params["kinds"]         comma-separated feeds to import (default: news,telegram,conflicts,strikes,regional-alerts)
    params["limit"]         max items across all feeds (default 500)
    params["min_severity"]  low|guarded|elevated|high|critical — minimum severity for *event* feeds that
                            carry one (conflicts/strikes/regional alerts); news & Telegram have none and
                            are always kept. Default: import all.

Worker-safe: reads an exported file or read-only GET API routes; no DB access, no offensive action.
Field names vary between IRONSIGHT versions, so extraction is defensive (multiple fallbacks).

Normalized result: {assets:[], services:[], cpes:[], vulns:[], intel:[...], source:"IRONSIGHT"}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/NoblerWorks-HQ/IRONSIGHT"

# IRONSIGHT read-only OSINT API routes (Next.js app, src/app/api/*). Markets/crypto/oil/flights/ships/
# fires are situational-awareness only — the intelligence feeds below are what map to CTI.
_ENDPOINTS = {
    "news": "/api/news",
    "telegram": "/api/telegram",
    "conflicts": "/api/conflicts",
    "strikes": "/api/strikes",
    "regional-alerts": "/api/regional-alerts",
}
_DEFAULT_KINDS = ["news", "telegram", "conflicts", "strikes", "regional-alerts"]
# accept several spellings when reading a combined export file
_FILE_KEY_ALIASES = {
    "news": "news", "telegram": "telegram", "conflicts": "conflicts", "conflict": "conflicts",
    "strikes": "strikes", "strike": "strikes",
    "regional-alerts": "regional-alerts", "regionalalerts": "regional-alerts",
    "regional_alerts": "regional-alerts", "regionalAlerts": "regional-alerts", "regional": "regional-alerts",
}

# IRONSIGHT ThreatLevel scale (LOW|GUARDED|ELEVATED|HIGH|CRITICAL) + generic synonyms.
_SEV_RANK = {
    "info": 0, "low": 1, "guarded": 2, "elevated": 3, "moderate": 3, "medium": 3,
    "high": 4, "severe": 4, "critical": 5,
}
# conflict actors worth surfacing as ActorTags (case-insensitive whole-ish matches)
_ACTORS = [
    "IDF", "IRGC", "Hezbollah", "Hamas", "Houthi", "Houthis", "Quds Force", "Mossad",
    "Iran", "Israel", "Lebanon", "Yemen", "Syria", "Iraq", "Gaza", "Hizbullah",
    "Pasdaran", "Basij", "CENTCOM", "Pentagon", "Kataib Hezbollah", "PMF", "Fatemiyoun",
]
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


# ── Public entry point ────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    min_rank = _SEV_RANK.get(str(params.get("min_severity") or "").lower(), 0)
    kinds = _parse_kinds(params.get("kinds"))
    by_kind = _load(params, kinds, limit)

    intel: List[Dict[str, Any]] = []
    seen = set()
    for kind in kinds:
        for it in by_kind.get(kind, []):
            if len(intel) >= limit:
                break
            rec = _to_intel(it, kind, min_rank)
            if not rec:
                continue
            ref = rec["reference"]
            if ref in seen:
                continue
            seen.add(ref)
            intel.append(rec)
    return {"assets": [], "services": [], "cpes": [], "vulns": [], "intel": intel, "source": "IRONSIGHT"}


def _parse_kinds(raw: Any) -> List[str]:
    if not raw:
        return list(_DEFAULT_KINDS)
    out = []
    for part in str(raw).replace(";", ",").split(","):
        k = _FILE_KEY_ALIASES.get(part.strip(), _FILE_KEY_ALIASES.get(part.strip().lower(), part.strip().lower()))
        if k in _ENDPOINTS and k not in out:
            out.append(k)
    return out or list(_DEFAULT_KINDS)


# ── Load (offline file or read-only API) ──────────────────────────────────────
def _load(params: Dict[str, Any], kinds: List[str], limit: int) -> Dict[str, List[Dict[str, Any]]]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return _split_file(data, kinds, limit)
    return {k: _fetch_route(k, limit) for k in kinds}


def _split_file(data: Any, kinds: List[str], limit: int) -> Dict[str, List[Dict[str, Any]]]:
    # An export can be a bare array (treated as 'news'), or an object keyed by feed.
    if isinstance(data, list):
        return {"news": [x for x in data if isinstance(x, dict)][:limit]}
    out: Dict[str, List[Dict[str, Any]]] = {}
    if isinstance(data, dict):
        # keyed-by-feed export
        for key, val in data.items():
            kind = _FILE_KEY_ALIASES.get(str(key)) or _FILE_KEY_ALIASES.get(str(key).lower())
            if kind and kind in kinds and isinstance(val, list):
                out[kind] = [x for x in val if isinstance(x, dict)][:limit]
        if out:
            return out
        # otherwise a single-feed payload wrapped in items/data/results/articles
        items = _items_of(data)
        if items:
            return {"news": items[:limit]}
    return out


def _fetch_route(kind: str, limit: int) -> List[Dict[str, Any]]:
    import requests

    base = os.getenv("IRONSIGHT_URL")
    if not base:
        raise RuntimeError("Provide an IRONSIGHT feed JSON via params['file'] or set IRONSIGHT_URL (worker env)")
    url = base.rstrip("/") + _ENDPOINTS[kind]
    r = requests.get(url, headers={"Accept": "application/json"}, timeout=120)
    r.raise_for_status()
    return _items_of(r.json())[:limit]


def _items_of(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("items", "data", "results", "articles", "news", "events", "alerts", "messages", "feed"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
            if isinstance(v, dict):
                for kk in ("items", "data", "results", "articles"):
                    if isinstance(v.get(kk), list):
                        return [x for x in v[kk] if isinstance(x, dict)]
    return []


# ── Map one feed item → INTELEXCHANGE record ──────────────────────────────────
def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def _detect_actors(text: str) -> str:
    low = text.lower()
    found = []
    for a in _ACTORS:
        if a.lower() in low and a not in found:
            found.append(a)
    return ", ".join(found[:8])


def _to_intel(it: Dict[str, Any], kind: str, min_rank: int) -> Optional[Dict[str, Any]]:
    # Telegram posts carry content in text/message; news/events in title/headline.
    title = _first(it, "title", "headline", "name", "text", "message", "summary", "description")
    if not title:
        return None
    title = str(title).strip()

    severity = str(_first(it, "severity", "threatLevel", "threat_level", "level", "magnitude", "threat") or "").strip()
    # severity filter applies only to items that actually carry a level (events); news/telegram pass through
    if min_rank and severity and _SEV_RANK.get(severity.lower(), 0) < min_rank:
        return None

    summary = str(_first(it, "summary", "description", "content", "body", "text", "message", "excerpt") or "").strip()
    if summary == title:
        summary = ""
    category = str(_first(it, "category", "type", "eventType", "event_type", "classification") or "").strip()
    region = str(_first(it, "country", "region", "location", "area", "geo") or "").strip()
    channel = str(_first(it, "channel", "channelName", "channel_name") or "").strip()
    source_name = str(_first(it, "source", "publisher", "outlet", "author") or channel or "").strip()
    link = _first(it, "link", "url", "sourceUrl", "permalink", "href", "messageLink", "postUrl")
    ext_id = _first(it, "id", "_id", "guid", "uuid", "messageId")
    date = str(_first(it, "pubDate", "date", "publishedAt", "published", "timestamp", "time", "createdAt") or "").strip()[:25]
    lat = it.get("lat")
    lng = it.get("lng") if it.get("lng") is not None else it.get("lon")
    coords = f"{lat},{lng}" if isinstance(lat, (int, float)) and isinstance(lng, (int, float)) else ""

    ref = str(link or "").strip() or f"ironsight://{kind}/{ext_id or _slug(title)}"

    meta = " · ".join(filter(None, [
        f"Feed: {kind}",
        f"Severity: {severity}" if severity else "",
        f"Category: {category}" if category else "",
        f"Region: {region}" if region else "",
        f"Channel: {channel}" if channel else "",
        f"Coords: {coords}" if coords else "",
    ]))
    description = ((summary + ("\n\n[" + meta + "]" if meta else "")).strip())[:4000]

    tags = ", ".join(filter(None, [
        "osint", "ironsight", "middle-east", f"feed:{kind}",
        f"source:{source_name}" if source_name else "",
        f"category:{category.lower()}" if category else "",
        f"severity:{severity.lower()}" if severity else "",
        f"region:{region}" if region else "",
    ]))

    blob = f"{title} {summary}"
    actors = _detect_actors(blob)
    cves = sorted({m.upper() for m in _CVE_RX.findall(blob)})

    rec: Dict[str, Any] = {
        "name": title[:300], "description": description, "reference": ref,
        "source": source_name or "IRONSIGHT", "tags": tags,
    }
    if ext_id:
        rec["external_id"] = str(ext_id)[:120]
    if date:
        rec["date"] = date
    if actors:
        rec["actor_tags"] = actors[:300]
    if cves:
        rec["cve_tags"] = ", ".join(cves)
    return rec


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "item"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="IRONSIGHT connector (offline dry run)")
    ap.add_argument("--file", help="IRONSIGHT feed JSON export")
    ap.add_argument("--kinds", default=None, help="comma-separated feeds (default: all intel feeds)")
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--min-severity", default="")
    a = ap.parse_args()
    if not a.file:
        sample = {
            "news": [
                {"title": "IDF strikes IRGC missile depot near Isfahan", "link": "https://example.com/n1",
                 "source": "Times of Israel", "category": "strike", "pubDate": "2026-06-29T08:00:00Z"},
                {"title": "Unrelated business headline", "link": "https://example.com/n2", "source": "WSJ"},
            ],
            "telegram": [
                {"id": "tg-1", "text": "Hezbollah claims responsibility for rocket barrage on northern Israel.",
                 "channel": "@warfareanalysis", "link": "https://t.me/warfareanalysis/123", "date": "2026-06-29"},
            ],
            "conflicts": [
                {"id": "c-1", "title": "Naval incident in Strait of Hormuz", "type": "naval", "severity": "elevated",
                 "location": "Strait of Hormuz", "lat": 26.57, "lng": 56.25, "source": "Reuters", "date": "2026-06-29"},
            ],
            "strikes": [
                {"id": "s-1", "title": "Houthi drone intercepted over Red Sea", "severity": "high",
                 "location": "Red Sea", "source": "CENTCOM", "link": "https://example.com/s1"},
            ],
            "regionalAlerts": [
                {"id": "ra-1", "country": "Lebanon", "threatLevel": "CRITICAL", "title": "Lebanon threat level raised to CRITICAL"},
                {"id": "ra-2", "country": "Jordan", "threatLevel": "GUARDED", "title": "Jordan threat level GUARDED"},
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "ironsight.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "kinds": a.kinds, "limit": a.limit, "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[ironsight] {len(res['intel'])} intel item(s) (tool: {TOOL_URL})", flush=True)
