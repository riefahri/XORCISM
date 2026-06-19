"""
ssvc.py — CISA SSVC (Stakeholder-Specific Vulnerability Categorization).
Jerome Athias - XORCISM

Implements the CISA SSVC decision model
(https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc),
"CISA Coordinator" decision table v2.0.3 (CERTCC/SSVC, verbatim 36-row lookup).

Four decision points -> one CISA-level decision:
    Exploitation        : none | public poc | active
    Automatable         : no | yes
    Technical Impact    : partial | total
    Mission & Well-being: low | medium | high
                       -> Track | Track* | Attend | Act

The four inputs are *derived* from the data XORCISM already holds on each
VULNERABILITY (CISA KEV flag, EPSS, CVSS metrics); Mission & Well-being is the
only stakeholder-specific point and defaults to "medium" (kept if an analyst has
already set it). The computed decision + an SSVC vector are written back to
VULNERABILITY (SsvcExploitation / SsvcAutomatable / SsvcTechnicalImpact /
SsvcMissionWellbeing / SsvcDecision / SsvcVector / SsvcDecisionDate).

Usable two ways:
    from ssvc import decide, derive_inputs, ssvc_vector, recompute_ssvc
    python ssvc.py [--all] [--limit N]        # recompute over XVULNERABILITY.db
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ── The CISA Coordinator v2.0.3 decision table (verbatim, 36 rows) ───────────
# key = (exploitation, automatable, technical_impact, mission_wellbeing) -> level
EXPLOITATION = ("none", "public poc", "active")
AUTOMATABLE = ("no", "yes")
TECHNICAL_IMPACT = ("partial", "total")
MISSION_WELLBEING = ("low", "medium", "high")
DECISIONS = ("Track", "Track*", "Attend", "Act")

# Decision per (exploitation, automatable, technical_impact, mission_wellbeing).
_TABLE: Dict[tuple, str] = {
    ("none", "no", "partial", "low"): "Track",
    ("none", "no", "partial", "medium"): "Track",
    ("none", "no", "partial", "high"): "Track",
    ("none", "no", "total", "low"): "Track",
    ("none", "no", "total", "medium"): "Track",
    ("none", "no", "total", "high"): "Track*",
    ("none", "yes", "partial", "low"): "Track",
    ("none", "yes", "partial", "medium"): "Track",
    ("none", "yes", "partial", "high"): "Attend",
    ("none", "yes", "total", "low"): "Track",
    ("none", "yes", "total", "medium"): "Track",
    ("none", "yes", "total", "high"): "Attend",
    ("public poc", "no", "partial", "low"): "Track",
    ("public poc", "no", "partial", "medium"): "Track",
    ("public poc", "no", "partial", "high"): "Track*",
    ("public poc", "no", "total", "low"): "Track",
    ("public poc", "no", "total", "medium"): "Track*",
    ("public poc", "no", "total", "high"): "Attend",
    ("public poc", "yes", "partial", "low"): "Track",
    ("public poc", "yes", "partial", "medium"): "Track",
    ("public poc", "yes", "partial", "high"): "Attend",
    ("public poc", "yes", "total", "low"): "Track",
    ("public poc", "yes", "total", "medium"): "Track*",
    ("public poc", "yes", "total", "high"): "Attend",
    ("active", "no", "partial", "low"): "Track",
    ("active", "no", "partial", "medium"): "Track",
    ("active", "no", "partial", "high"): "Attend",
    ("active", "no", "total", "low"): "Track",
    ("active", "no", "total", "medium"): "Attend",
    ("active", "no", "total", "high"): "Act",
    ("active", "yes", "partial", "low"): "Attend",
    ("active", "yes", "partial", "medium"): "Attend",
    ("active", "yes", "partial", "high"): "Act",
    ("active", "yes", "total", "low"): "Attend",
    ("active", "yes", "total", "medium"): "Act",
    ("active", "yes", "total", "high"): "Act",
}

_ALIASES = {  # tolerate common synonyms / casings
    "poc": "public poc", "public-poc": "public poc", "p": "public poc",
    "n": "none", "a": "active", "exploited": "active",
    "y": "yes", "true": "yes", "1": "yes", "no": "no", "false": "no", "0": "no",
    "t": "total", "complete": "total", "full": "total", "partial": "partial",
    "l": "low", "m": "medium", "h": "high",
}


def _norm(v: Any, allowed: tuple, default: str) -> str:
    s = str(v or "").strip().lower()
    s = _ALIASES.get(s, s)
    return s if s in allowed else default


def decide(exploitation: str, automatable: str, technical_impact: str, mission_wellbeing: str) -> str:
    """CISA SSVC decision (Track / Track* / Attend / Act) for the four points."""
    key = (
        _norm(exploitation, EXPLOITATION, "none"),
        _norm(automatable, AUTOMATABLE, "no"),
        _norm(technical_impact, TECHNICAL_IMPACT, "partial"),
        _norm(mission_wellbeing, MISSION_WELLBEING, "medium"),
    )
    return _TABLE.get(key, "Track")


# ── SSVC vector (compact, self-documenting; SSVCv2-style) ────────────────────
_E = {"none": "N", "public poc": "P", "active": "A"}
_A = {"no": "N", "yes": "Y"}
_T = {"partial": "P", "total": "T"}
_M = {"low": "L", "medium": "M", "high": "H"}


def ssvc_vector(exploitation: str, automatable: str, technical_impact: str,
                mission_wellbeing: str, decision: str, date: Optional[str] = None) -> str:
    e = _norm(exploitation, EXPLOITATION, "none")
    a = _norm(automatable, AUTOMATABLE, "no")
    t = _norm(technical_impact, TECHNICAL_IMPACT, "partial")
    m = _norm(mission_wellbeing, MISSION_WELLBEING, "medium")
    d = (date or datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    return f"SSVCv2/E:{_E[e]}/Au:{_A[a]}/T:{_T[t]}/M:{_M[m]}/D:{decision}/{d}/"


# ── Derive the four decision points from XORCISM's VULNERABILITY data ─────────

def _is_high_impact(v: Any) -> bool:
    return str(v or "").strip().upper() in ("HIGH", "COMPLETE")


def _truthy(v: Any) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "y", "t")


def derive_inputs(row: Dict[str, Any]) -> Dict[str, str]:
    """Best-effort SSVC decision points from KEV / EPSS / CVSS. The caller keeps
    any analyst-set Mission & Well-being; otherwise it defaults to 'medium'."""
    # Exploitation: KEV / Exploited => active ; known PoC/exploit => public poc ; else none.
    if _truthy(row.get("KEV")) or _truthy(row.get("Exploited")):
        exploitation = "active"
    elif _truthy(row.get("EasilyExploitable")) or _truthy(row.get("VULExploitable")):
        exploitation = "public poc"
    else:
        exploitation = "none"

    # Technical Impact: total if C+I+A all High/Complete, or base score >= 9.0 ; else partial.
    conf, integ, avail = row.get("CVSSMetricConfImpact"), row.get("CVSSMetricIntegImpact"), row.get("CVSSMetricAvailImpact")
    try:
        base = float(row.get("CVSSBaseScore")) if row.get("CVSSBaseScore") not in (None, "") else None
    except (TypeError, ValueError):
        base = None
    if (_is_high_impact(conf) and _is_high_impact(integ) and _is_high_impact(avail)) or (base is not None and base >= 9.0):
        technical_impact = "total"
    else:
        technical_impact = "partial"

    # Automatable: yes if remotely reachable + low complexity + no auth, or EPSS high.
    av = str(row.get("CVSSMetricAccessVector") or "").strip().upper()
    ac = str(row.get("CVSSMetricAccessComplexity") or "").strip().upper()
    auth = str(row.get("CVSSMetricAuthentication") or "").strip().upper()
    try:
        epss = float(row.get("EPSS")) if row.get("EPSS") not in (None, "") else 0.0
    except (TypeError, ValueError):
        epss = 0.0
    network = av in ("NETWORK", "N")
    low_complexity = ac in ("LOW", "L")
    no_auth = auth in ("NONE", "N")
    automatable = "yes" if (network and low_complexity and no_auth) or epss >= 0.5 else "no"

    mission = _norm(row.get("SsvcMissionWellbeing"), MISSION_WELLBEING, "medium")
    return {
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "mission_wellbeing": mission,
    }


def assess(row: Dict[str, Any]) -> Dict[str, str]:
    """Full SSVC assessment (inputs + decision + vector) for one VULNERABILITY row."""
    pts = derive_inputs(row)
    dec = decide(**pts)
    return {
        "SsvcExploitation": pts["exploitation"],
        "SsvcAutomatable": pts["automatable"],
        "SsvcTechnicalImpact": pts["technical_impact"],
        "SsvcMissionWellbeing": pts["mission_wellbeing"],
        "SsvcDecision": dec,
        "SsvcVector": ssvc_vector(pts["exploitation"], pts["automatable"], pts["technical_impact"],
                                  pts["mission_wellbeing"], dec),
    }


# ── Bulk recompute over XVULNERABILITY.db ────────────────────────────────────

_READ_COLS = [
    "VulnerabilityID", "KEV", "Exploited", "EasilyExploitable", "VULExploitable", "EPSS",
    "CVSSBaseScore", "CVSSMetricAccessVector", "CVSSMetricAccessComplexity",
    "CVSSMetricAuthentication", "CVSSMetricConfImpact", "CVSSMetricIntegImpact",
    "CVSSMetricAvailImpact", "SsvcMissionWellbeing", "SsvcDecision",
]
_SSVC_COLS = {
    "SsvcExploitation": "TEXT", "SsvcAutomatable": "TEXT", "SsvcTechnicalImpact": "TEXT",
    "SsvcMissionWellbeing": "TEXT", "SsvcDecision": "TEXT", "SsvcVector": "TEXT", "SsvcDecisionDate": "DATE",
}


def _ensure_columns(conn) -> None:
    from sqlalchemy import text
    have = {r[1] for r in conn.execute(text('PRAGMA table_info("VULNERABILITY")'))}
    for name, typ in _SSVC_COLS.items():
        if name not in have:
            conn.execute(text(f'ALTER TABLE "VULNERABILITY" ADD COLUMN "{name}" {typ}'))


def recompute_ssvc(session, where: Optional[str] = None, limit: Optional[int] = None) -> int:
    """Recompute SSVC for VULNERABILITY rows (optionally filtered by a SQL `where`
    fragment, e.g. "SsvcDecision IS NULL OR KEV = 1"). Returns the number updated.
    Mission & Well-being already set by an analyst is preserved."""
    from sqlalchemy import text
    conn = session.connection()
    _ensure_columns(conn)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Read + update by rowid: VulnerabilityID is NOT indexed (only VULReferentialID
    # is), so updating on it would full-scan the 300k+-row table for every row.
    sql = f'SELECT rowid AS _rid, {", ".join(_READ_COLS)} FROM "VULNERABILITY"'
    if where:
        sql += f" WHERE {where}"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = [dict(r._mapping) for r in conn.execute(text(sql))]

    upd = text(
        'UPDATE "VULNERABILITY" SET '
        '"SsvcExploitation"=:e, "SsvcAutomatable"=:a, "SsvcTechnicalImpact"=:t, '
        '"SsvcMissionWellbeing"=:m, "SsvcDecision"=:d, "SsvcVector"=:v, "SsvcDecisionDate"=:dt '
        'WHERE rowid=:rid'
    )
    n = 0
    for row in rows:
        a = assess(row)
        conn.execute(upd, {
            "e": a["SsvcExploitation"], "a": a["SsvcAutomatable"], "t": a["SsvcTechnicalImpact"],
            "m": a["SsvcMissionWellbeing"], "d": a["SsvcDecision"], "v": a["SsvcVector"],
            "dt": today, "rid": row["_rid"],
        })
        n += 1
    session.commit()
    return n


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from xorcism_python.models.base import session_scope
    from xorcism_python.utils import log

    ap = argparse.ArgumentParser(description="Recompute CISA SSVC for XVULNERABILITY.db")
    ap.add_argument("--all", action="store_true", help="Recompute every row (default: only rows missing an SSVC decision)")
    ap.add_argument("--limit", type=int, default=None, help="Process at most N rows")
    args = ap.parse_args()

    where = None if args.all else "SsvcDecision IS NULL OR SsvcDecision = ''"
    with session_scope("XVULNERABILITY") as s:
        n = recompute_ssvc(s, where=where, limit=args.limit)
    log("SSVC", f"SSVC recomputed for {n} vulnerability row(s).")


if __name__ == "__main__":
    main()
