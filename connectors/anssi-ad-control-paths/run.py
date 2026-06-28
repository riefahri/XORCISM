"""run.py - XORCISM connector: ANSSI AD Control Paths CSV -> AD objects + identity attack-path findings.

ANSSI's AD-control-paths (github.com/ANSSI-FR/AD-control-paths) maps the Active Directory access-control
graph to surface hidden privilege-escalation / takeover paths to high-value objects. This connector
ingests a relationship CSV: each row is a control edge `source -(right)-> target`. Columns are
auto-detected (case-insensitive): source ~ source/from/node1/grantee/trustee; target ~ target/to/node2/object;
right ~ right/relation/type/edge/permission. Output (runner-ingestible, no DB access):
  - assets : the distinct AD objects (tagged ad/identity)
  - vulns  : one finding per control edge (ref ADCP-<n>) on the target object, severity raised when the
             target looks high-value (admin / domain root / enterprise).
"""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

_SRC = ("source", "from", "node1", "grantee", "trustee", "controller", "src")
_DST = ("target", "to", "node2", "object", "controlled", "dst", "dest")
_RIGHT = ("right", "relation", "relationship", "type", "edge", "permission", "access", "label")
_HIGH = ("domain admins", "enterprise admins", "administrators", "domain controllers", "krbtgt",
         "schema admins", "dc=", "adminsdholder", "gpo")


def _pick(header: List[str], names) -> int:
    low = [h.strip().lower() for h in header]
    for n in names:
        for i, h in enumerate(low):
            if h == n:
                return i
    for n in names:
        for i, h in enumerate(low):
            if n in h:
                return i
    return -1


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("anssi-ad-control-paths: provide a 'file' (relationship CSV)")
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        text = fh.read()
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except Exception:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        return {"assets": [], "vulns": []}
    header = rows[0]
    si, ti, ri = _pick(header, _SRC), _pick(header, _DST), _pick(header, _RIGHT)
    # If no recognisable header, assume positional: source,right,target or source,target,right.
    data = rows[1:] if (si >= 0 or ti >= 0) else rows
    if si < 0 or ti < 0:
        si, ti, ri = 0, (2 if len(header) > 2 else 1), (1 if len(header) > 2 else -1)

    objects: Dict[str, None] = {}
    vulns: List[Dict[str, Any]] = []
    seen = set()
    n = 0
    for r in data:
        if len(r) <= max(si, ti):
            continue
        src = (r[si] or "").strip()
        dst = (r[ti] or "").strip()
        right = (r[ri].strip() if 0 <= ri < len(r) else "controls") or "controls"
        if not src or not dst:
            continue
        objects[src] = None
        objects[dst] = None
        key = (src, right, dst)
        if key in seen:
            continue
        seen.add(key)
        n += 1
        high = any(h in dst.lower() or h in src.lower() for h in _HIGH)
        vulns.append({
            "asset": dst[:200], "ref": "ADCP-%d" % n,
            "name": ("AD control path: %s -[%s]-> %s" % (src, right, dst))[:240],
            "severity": "high" if high else "medium",
            "detail": "%s can take control of %s via %s" % (src, dst, right),
        })
        if n >= 20000:
            break
    assets = [{"name": o[:200], "tags": ["ad", "identity", "control-path"]} for o in objects]
    return {"assets": assets, "vulns": vulns}
