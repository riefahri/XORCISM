"""
_sarif.py — Shared OASIS SARIF parser for XORCISM connectors.

SARIF 2.1.0 (Static Analysis Results Interchange Format,
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) is the standard
JSON output of static-analysis / security tools: CodeQL, Semgrep, Bandit, ESLint,
Trivy, Grype, Checkov, gitleaks, nuclei -sarif, and many more.

`parse_sarif()` converts a SARIF document into the XORCISM normalized findings
result `{assets, services, cpes, vulns}` consumed by the runner's import_findings:
the analyzed project/repository becomes an ASSET and each SARIF result becomes a
finding (VULNERABILITY / ASSETVULNERABILITY). When a rule/result references a CVE
it is used as the finding reference; otherwise a stable `SARIF-<rule>` ref is
derived (using the result fingerprint or file:line). Severity comes from the
`security-severity` property (CVSS-like 0-10) when present, else the SARIF level.

Stdlib only; defensive against partial / older SARIF documents.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SEV_FROM_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info", "info": "info"}


def load_sarif(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_sarif(data: Any, default_project: Optional[str] = None) -> Dict[str, Any]:
    """SARIF document (dict or path) -> normalized {assets, services, cpes, vulns}."""
    if isinstance(data, str):
        data = load_sarif(data)
    runs = (data or {}).get("runs") or []
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen: set = set()

    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = _tool_name(run)
        rules = _rule_index(run)
        project = ((default_project or _project_of(run, tool)) or "SARIF import").strip()
        assets.setdefault(project, {"hostname": project, "key": project})

        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule_id, rule = _resolve_rule(res, rules)
            level = _level(res, rule)
            sev = _severity(res, rule, level)
            msg = _message(res)
            loc = _location(res)
            cve = _first_cve(rule_id, msg, _rule_tags(rule), res)
            ref = (cve or _ref(tool, rule_id, res, loc))[:120]
            if ref in seen:
                continue
            seen.add(ref)
            rname = _rule_name(rule) or rule_id or "finding"
            name = f"[{tool}] {rname}"
            if msg:
                name += f": {msg}"
            if loc:
                name += f" ({loc})"
            vulns.append({"asset": project, "ref": ref, "name": name[:240], "severity": sev})

    return {"assets": list(assets.values()), "services": [], "cpes": [], "vulns": vulns}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _driver(run: Dict[str, Any]) -> Dict[str, Any]:
    return (run.get("tool") or {}).get("driver") or {}


def _tool_name(run: Dict[str, Any]) -> str:
    return str(_driver(run).get("name") or "SARIF").strip() or "SARIF"


def _rule_index(run: Dict[str, Any]) -> Dict[str, Any]:
    """Map ruleId -> rule object, plus __index__N -> rule for ruleIndex lookups."""
    idx: Dict[str, Any] = {}
    d = _driver(run)
    for i, r in enumerate(d.get("rules") or []):
        if isinstance(r, dict):
            idx[f"__index__{i}"] = r
            rid = r.get("id") or r.get("name")
            if rid:
                idx.setdefault(str(rid), r)
    for ext in (d.get("extensions") or []):
        for r in (ext.get("rules") or []) if isinstance(ext, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                idx.setdefault(str(r["id"]), r)
    return idx


def _resolve_rule(res: Dict[str, Any], rules: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    rid = res.get("ruleId") or (res.get("rule") or {}).get("id")
    rule = rules.get(str(rid)) if rid is not None else None
    if rule is None and "ruleIndex" in res:
        rule = rules.get(f"__index__{res['ruleIndex']}")
    if rule is None and isinstance(res.get("rule"), dict) and "index" in res["rule"]:
        rule = rules.get(f"__index__{res['rule']['index']}")
    if rule and not rid:
        rid = rule.get("id") or rule.get("name")
    return (str(rid) if rid is not None else None), (rule or {})


def _level(res: Dict[str, Any], rule: Dict[str, Any]) -> str:
    lvl = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return str(lvl or "warning").lower()


def _severity(res: Dict[str, Any], rule: Dict[str, Any], level: str) -> str:
    ss = _security_severity(res.get("properties"))
    if ss is None:
        ss = _security_severity(rule.get("properties"))
    if ss is not None:
        if ss >= 9.0:
            return "critical"
        if ss >= 7.0:
            return "high"
        if ss >= 4.0:
            return "medium"
        return "low" if ss > 0 else "info"
    return _SEV_FROM_LEVEL.get(level, "medium")


def _security_severity(props: Any) -> Optional[float]:
    if isinstance(props, dict):
        v = props.get("security-severity", props.get("security_severity"))
        try:
            return float(v) if v not in (None, "") else None
        except (ValueError, TypeError):
            return None
    return None


def _message(res: Dict[str, Any]) -> str:
    m = res.get("message")
    if isinstance(m, dict):
        return str(m.get("text") or m.get("markdown") or m.get("id") or "").strip()
    return str(m or "").strip()


def _location(res: Dict[str, Any]) -> Optional[str]:
    locs = res.get("locations") or []
    if not locs or not isinstance(locs[0], dict):
        return None
    pl = locs[0].get("physicalLocation") or {}
    uri = (pl.get("artifactLocation") or {}).get("uri")
    line = (pl.get("region") or {}).get("startLine")
    if uri and line:
        return f"{uri}:{line}"
    return str(uri) if uri else None


def _rule_name(rule: Dict[str, Any]) -> Optional[str]:
    if not isinstance(rule, dict):
        return None
    return rule.get("name") or (rule.get("shortDescription") or {}).get("text") or rule.get("id")


def _rule_tags(rule: Dict[str, Any]) -> List[Any]:
    return ((rule.get("properties") or {}).get("tags") or []) if isinstance(rule, dict) else []


def _first_cve(*parts: Any) -> Optional[str]:
    blob = " ".join(p if isinstance(p, str) else json.dumps(p, default=str) for p in parts if p)
    m = _CVE_RE.search(blob)
    return m.group(0).upper() if m else None


def _project_of(run: Dict[str, Any], tool: str) -> str:
    vcs = run.get("versionControlProvenance") or []
    if vcs and isinstance(vcs[0], dict) and vcs[0].get("repositoryUri"):
        p = re.sub(r"^[a-z]+://", "", str(vcs[0]["repositoryUri"])).rstrip("/")
        p = re.sub(r"\.git$", "", p)
        segs = [s for s in p.split("/") if s]
        return "/".join(segs[-2:]) if len(segs) >= 2 else (segs[-1] if segs else p)
    ad = (run.get("automationDetails") or {}).get("id")
    if ad:
        return str(ad).split("/")[0]
    return f"{tool} findings"


def _ref(tool: str, rule_id: Optional[str], res: Dict[str, Any], loc: Optional[str]) -> str:
    fp = res.get("fingerprints") or res.get("partialFingerprints")
    if isinstance(fp, dict) and fp:
        return f"SARIF-{rule_id or 'rule'}-{str(next(iter(fp.values())))[:16]}"
    base = f"SARIF-{_slug(tool)}-{rule_id or 'rule'}"
    return f"{base}@{loc}" if loc else base


def _slug(s: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(s)).strip("-")[:40]
