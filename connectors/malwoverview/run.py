"""run.py - XORCISM connector: malwoverview malware triage -> XMALWARE.MALWARESCAN (+ engines) + CTI.

malwoverview (github.com/alexandreborges/malwoverview) is a Python CLI for initial malware triage and
threat hunting that aggregates ~18 TI/sandbox services (VirusTotal, Hybrid Analysis, Triage, Polyswarm,
MalwareBazaar, URLhaus, ThreatFox, Malshare, Malpedia, AlienVault OTX, …) and can emit JSON. This connector
ingests that JSON and normalizes it into the XORCISM malware store (same backend as the /malware-scan page):

  each sample           -> one MALWARESCAN  (hashes, verdict, positives/total, summary, family in tags)
  each aggregated service-> one MALWARESCANENGINE row (per-service verdict / detection / link)
  the family + tags + ATT&CK techniques -> one INTELEXCHANGE item (cross-linked to the ATT&CK matrix)

Input ('file') is auto-detected:
  1. a malwoverview/normalized bundle: {samples:[{sha256,md5,verdict,services:[…],family,tags,attck,iocs}]}
     (or {malware:[…]}, a single sample dict, or a list of samples)
  2. a raw VirusTotal v3 file report  ({data:{attributes:{last_analysis_stats, last_analysis_results,…}}})
  3. a raw MalwareBazaar hash query   ({query_status:"ok", data:[{sha256_hash, signature, vendor_intel,…}]})

Read-only (no live API, no DB access here - worker-safe). The runner imports the result into XMALWARE.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "malwoverview"
_VERD = {"malicious": "malicious", "malware": "malicious", "phishing": "malicious", "suspicious": "suspicious",
         "harmless": "clean", "clean": "clean", "undetected": "clean", "unknown": "unknown"}


def _verd(v: Any) -> str:
    return _VERD.get(str(v or "").strip().lower(), "unknown")


def _i(v: Any):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _attck(text: str) -> List[str]:
    return sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", str(text or ""))))


def _aslist(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x]
    if isinstance(v, str):
        return [t.strip() for t in re.split(r"[,;]", v) if t.strip()]
    return []


def _sample_from_vt(data: Dict[str, Any]) -> Dict[str, Any]:
    attr = (data.get("data") or {}).get("attributes") or data.get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    mal = _i(stats.get("malicious")) or 0
    susp = _i(stats.get("suspicious")) or 0
    total = sum(_i(x) or 0 for x in stats.values()) or None
    engines = []
    for name, r in (attr.get("last_analysis_results") or {}).items():
        if not isinstance(r, dict):
            continue
        engines.append({"engine": name, "verdict": _verd(r.get("category")), "detection": r.get("result"),
                        "category": r.get("category"), "live": True})
    fam = ""
    ptc = attr.get("popular_threat_classification") or {}
    if isinstance(ptc, dict):
        fam = ptc.get("suggested_threat_label") or ""
    tags = _aslist(attr.get("tags"))
    return {"sha256": attr.get("sha256"), "sha1": attr.get("sha1"), "md5": attr.get("md5"),
            "target": attr.get("sha256") or attr.get("meaningful_name") or "sample", "type": "hash",
            "verdict": "malicious" if mal else "suspicious" if susp else ("clean" if total else "unknown"),
            "positives": mal + susp, "total": total, "family": fam, "tags": tags,
            "summary": ("VirusTotal: %d/%s · %s" % (mal + susp, total or "?", attr.get("type_description") or "")).strip(" ·"),
            "engines": engines, "attck": []}


def _samples_from_bazaar(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for d in (data.get("data") or []):
        if not isinstance(d, dict):
            continue
        engines = [{"engine": "MalwareBazaar", "verdict": "malicious", "detection": d.get("signature"),
                    "category": "malicious", "link": "https://bazaar.abuse.ch/sample/%s/" % (d.get("sha256_hash") or ""), "live": True}]
        for vi_name, vi in (d.get("vendor_intel") or {}).items():
            det = vi if isinstance(vi, str) else (vi.get("detection") or vi.get("malware_family") or vi.get("verdict") if isinstance(vi, dict) else None)
            engines.append({"engine": str(vi_name), "verdict": "malicious", "detection": str(det) if det else None, "category": "malicious", "live": True})
        tags = _aslist(d.get("tags"))
        out.append({"sha256": d.get("sha256_hash"), "sha1": d.get("sha1_hash"), "md5": d.get("md5_hash"),
                    "target": d.get("sha256_hash") or d.get("file_name") or "sample", "type": "hash",
                    "verdict": "malicious", "positives": len(engines), "total": len(engines),
                    "family": d.get("signature") or "", "tags": tags,
                    "summary": "MalwareBazaar: %s%s" % (d.get("signature") or "known sample", " · " + (d.get("file_type") or "") if d.get("file_type") else ""),
                    "engines": engines, "attck": _attck(json.dumps(d))})
    return out


def _norm_sample(s: Dict[str, Any]) -> Dict[str, Any]:
    engines = []
    for e in (s.get("engines") or s.get("services") or []):
        if isinstance(e, dict):
            engines.append({"engine": e.get("engine") or e.get("service") or "service", "verdict": _verd(e.get("verdict")),
                            "detection": e.get("detection") or e.get("result"), "category": e.get("category"),
                            "link": e.get("link"), "positives": _i(e.get("positives")), "total": _i(e.get("total")),
                            "live": bool(e.get("live", True)), "raw": e.get("raw")})
        elif isinstance(e, str):
            engines.append({"engine": e, "live": True})
    tags = _aslist(s.get("tags")) + ([s.get("family")] if s.get("family") else [])
    return {"sha256": (s.get("sha256") or "").lower() or None, "sha1": s.get("sha1"), "md5": s.get("md5"),
            "target": s.get("target") or s.get("sha256") or s.get("md5") or "sample", "type": s.get("type") or s.get("targetType") or ("hash" if s.get("sha256") else "file"),
            "verdict": _verd(s.get("verdict")) if s.get("verdict") else ("malicious" if (_i(s.get("positives")) or 0) > 0 else "unknown"),
            "positives": _i(s.get("positives")), "total": _i(s.get("total")), "score": _i(s.get("score")),
            "family": s.get("family") or "", "tags": [t for t in tags if t],
            "summary": s.get("summary") or "", "engines": engines,
            "attck": _aslist(s.get("attck")) or _aslist(s.get("mitre")) or _attck(json.dumps(s))}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("malwoverview: provide a 'file' (malwoverview JSON, or a VirusTotal / MalwareBazaar report)")
    with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    samples: List[Dict[str, Any]] = []
    if isinstance(data, list):
        samples = [_norm_sample(x) for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        if data.get("samples") or data.get("malware"):
            samples = [_norm_sample(x) for x in (data.get("samples") or data.get("malware")) if isinstance(x, dict)]
        elif data.get("query_status") is not None and data.get("data") is not None:  # MalwareBazaar
            samples = _samples_from_bazaar(data)
        elif (data.get("data") or {}).get("attributes") or data.get("attributes"):  # VirusTotal v3
            samples = [_sample_from_vt(data)]
        else:
            samples = [_norm_sample(data)]
    if not samples:
        raise RuntimeError("malwoverview: no malware samples found in the file")

    # CTI: surface each sample's family + tags + ATT&CK as an INTELEXCHANGE item (feeds the ATT&CK matrix)
    intel = []
    for s in samples:
        key = s.get("sha256") or s.get("md5") or s.get("target")
        if not key:
            continue
        intel.append({
            "name": (s.get("family") or "Malware sample") + " — " + str(key)[:16],
            "reference": "malwoverview:" + str(key), "external_id": s.get("sha256") or s.get("md5"),
            "source": SOURCE, "malware_tags": s.get("family") or "", "tags": ",".join(s.get("tags") or []),
            "attack_tags": ",".join(s.get("attck") or []), "description": s.get("summary") or "",
        })

    return {"source": SOURCE, "malware": samples, "intel": intel}


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    r = run({"file": sys.argv[1]}, ".")
    print("malwoverview: %d sample(s), %d intel item(s)" % (len(r["malware"]), len(r["intel"])))
    for s in r["malware"][:10]:
        print("  %-9s %-12s %s (%d engines)" % (s["verdict"], (s.get("family") or "")[:12], (s.get("sha256") or s.get("md5") or s["target"])[:50], len(s["engines"])))
