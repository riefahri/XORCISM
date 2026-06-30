"""run.py — Import RedRoom's classified intelligence feed into XORCISM (CTI).

RedRoom (https://github.com/Owlinkai/redroom, by Owlink.ai) is an open-source real-time news
OSINT platform — a command-and-control-style intelligence dashboard for geopolitical analysis
(live feed with sentiment + threat classification, 3D threat globe, RSS crawler, satellite/SIGINT
tracking, AI-assisted narrative detection for information operations).

This connector maps each RedRoom feed item to an XORCISM threat-intel record (XTHREAT.INTELEXCHANGE):

  * headline / title            -> IntelName
  * summary + classification    -> IntelDescription
  * source link / permalink     -> IntelReference (the idempotency key)
  * sentiment / threat-level / region / narrative -> IntelTags
  * any CVE referenced in the text -> CveTags

Config (worker environment / params, never live offensive access):
    params["file"]     a RedRoom feed export in JSON (array, or {items|feed|data|articles|results:[...]}), OR
    REDROOM_URL        the RedRoom feed API URL (read-only GET; a base URL gets /api/feed appended)
    REDROOM_API_KEY    optional bearer token for that API
    params["limit"]        max items (default 500)
    params["min_threat"]   low|medium|high|critical — minimum threat level to import (default low)

Worker-safe: reads an exported file or a read-only feed API; no DB access. Field names vary, so
extraction is defensive (multiple fallbacks).

Normalized result: {assets:[], services:[], cpes:[], vulns:[], intel:[...]}.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

TOOL_URL = "https://github.com/Owlinkai/redroom"
_THREAT_RANK = {"info": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4, "severe": 4}
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


# ── Public entry point ────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    limit = int(params.get("limit", 500) or 500)
    min_rank = _THREAT_RANK.get(str(params.get("min_threat") or "low").lower(), 0)
    items = _load(params, limit)
    intel: List[Dict[str, Any]] = []
    seen = set()
    for it in items:
        rec = _to_intel(it, min_rank)
        if not rec:
            continue
        ref = rec["reference"]
        if ref in seen:
            continue
        seen.add(ref)
        intel.append(rec)
    return {"assets": [], "services": [], "cpes": [], "vulns": [], "intel": intel, "source": "RedRoom"}


# ── Load (offline file or read-only API) ──────────────────────────────────────
def _load(params: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = _fetch_api(limit)
    return _items_of(data)[:limit]


def _fetch_api(limit: int) -> Any:
    import requests

    url = os.getenv("REDROOM_URL")
    if not url:
        raise RuntimeError("Provide a RedRoom feed JSON via params['file'] or set REDROOM_URL (worker env)")
    if "/api/" not in url and "?" not in url:
        url = url.rstrip("/") + "/api/feed"
    headers = {"Accept": "application/json"}
    token = os.getenv("REDROOM_API_KEY")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(url, headers=headers, params={"limit": limit}, timeout=120)
    r.raise_for_status()
    return r.json()


def _items_of(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("items", "feed", "data", "articles", "results", "signals", "intel"):
            v = data.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
            if isinstance(v, dict):  # e.g. {"data": {"items": [...]}}
                for kk in ("items", "feed", "results", "articles"):
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


def _to_intel(it: Dict[str, Any], min_rank: int) -> Optional[Dict[str, Any]]:
    title = _first(it, "title", "headline", "name", "summary")
    if not title:
        return None
    title = str(title).strip()
    threat = str(_first(it, "threatLevel", "threat_level", "threat", "classification", "severity", "risk") or "").strip()
    if min_rank and _THREAT_RANK.get(threat.lower(), 0) < min_rank:
        return None
    summary = str(_first(it, "summary", "description", "content", "body", "excerpt") or "").strip()
    sentiment = str(_first(it, "sentiment", "tone") or "").strip()
    region = str(_first(it, "region", "country", "location", "geo") or "").strip()
    narrative = _first(it, "narrative", "narrativeTag", "narratives", "campaign")
    if isinstance(narrative, list):
        narrative = ", ".join(str(x) for x in narrative)
    narrative = str(narrative or "").strip()
    source_name = str(_first(it, "sourceName", "publisher", "outlet", "source") or "RedRoom").strip()
    link = _first(it, "url", "link", "sourceUrl", "permalink", "href")
    ext_id = _first(it, "id", "_id", "uuid", "guid")
    ref = str(link or "").strip() or f"redroom://item/{ext_id or _slug(title)}"
    date = str(_first(it, "publishedAt", "published_at", "date", "timestamp", "createdAt", "time") or "").strip()[:25]

    # description = summary + the analyst classification metadata
    meta = " · ".join(filter(None, [
        f"Threat: {threat}" if threat else "",
        f"Sentiment: {sentiment}" if sentiment else "",
        f"Region: {region}" if region else "",
        f"Narrative: {narrative}" if narrative else "",
    ]))
    description = (summary + ("\n\n[" + meta + "]" if meta else "")).strip()[:4000]

    tags = ", ".join(filter(None, [
        "osint", "redroom",
        f"threat:{threat.lower()}" if threat else "",
        f"sentiment:{sentiment.lower()}" if sentiment else "",
        f"region:{region}" if region else "",
        "narrative" if narrative else "",
    ]))
    # CVEs mentioned anywhere in the item → CveTags
    blob = f"{title} {summary} {narrative}"
    cves = sorted({m.upper() for m in _CVE_RX.findall(blob)})

    rec: Dict[str, Any] = {
        "name": title[:300], "description": description, "reference": ref,
        "source": source_name or "RedRoom", "tags": tags,
    }
    if ext_id:
        rec["external_id"] = str(ext_id)[:120]
    if date:
        rec["date"] = date
    if cves:
        rec["cve_tags"] = ", ".join(cves)
    if narrative:
        rec["actor_tags"] = narrative[:300]  # info-ops narratives ~ campaign/actor context
    return rec


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "item"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="RedRoom connector (offline dry run)")
    ap.add_argument("--file", help="RedRoom feed JSON export")
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--min-threat", default="low")
    a = ap.parse_args()
    if not a.file:
        sample = {"items": [
            {"id": "rr-1", "title": "Coordinated influence campaign targets election infrastructure", "summary": "Network of inauthentic accounts amplifies a divisive narrative ahead of the vote.",
             "threatLevel": "high", "sentiment": "negative", "region": "Eastern Europe", "narrative": "election-distrust",
             "sourceName": "Wire", "url": "https://example.com/rr-1", "publishedAt": "2026-06-29T08:00:00Z"},
            {"id": "rr-2", "headline": "Exploitation of CVE-2026-0001 reported in the wild", "summary": "OSINT chatter indicates active exploitation against edge devices.",
             "threatLevel": "critical", "sentiment": "neutral", "region": "Global", "url": "https://example.com/rr-2", "date": "2026-06-29"},
            {"id": "rr-3", "title": "Low-signal market rumor", "summary": "Unverified.", "threatLevel": "low", "url": "https://example.com/rr-3"},
        ]}
        fp = os.path.join(tempfile.mkdtemp(), "redroom.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "limit": a.limit, "min_threat": a.min_threat}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[redroom] {len(res['intel'])} intel item(s) (tool: {TOOL_URL})", flush=True)
