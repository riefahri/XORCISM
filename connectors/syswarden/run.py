"""run.py — Import a SysWarden host security posture export.

SysWarden (https://github.com/duggytuxy/syswarden, https://syswarden.io) is an
open-source, enterprise-grade Host Intrusion Detection & Prevention System /
security orchestrator for critical Linux infrastructure: hardware-level network
filtering (L2-L4 via nftables/pf), OWASP ModSecurity WAF (L7), WireGuard SSH /
admin cloaking and automated CIS Level 2 hardening.

This connector parses a SysWarden status/report export (JSON) and maps it to the
XORCISM findings model:

  * the protected host                          -> ASSET (hostname, ip, os)
  * each CIS hardening control NOT applied/failed -> finding (ref SYSWARDEN-CIS-<id>)
  * each disabled defensive component (nftables / ModSecurity / WireGuard)
                                                -> posture finding (ref SYSWARDEN-COMP-<name>)
  * each source IP blocked by nftables / ModSecurity -> threat-intel IOC (INTELEXCHANGE)

Config (worker environment / params, never the live host):
    params["file"]      a SysWarden status export in JSON, OR
    SYSWARDEN_STATUS    path to that JSON on the worker
                        (produce with e.g. `syswarden --status --json > status.json`)
    params["min_severity"]  low|medium|high — minimum hardening-finding severity (default low)

Worker-safe: only reads an exported file. No live host access, no DB writes.
Field names vary between SysWarden versions, so extraction is defensive.

Normalized result: {assets, services, cpes:[], vulns, intel}.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Public entry point ────────────────────────────────────────────────────────
def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    data = _load(params)
    min_sev = _SEV_RANK.get(str(params.get("min_severity") or "low").lower(), 1)

    host = _host(data)
    key = host["key"]
    assets = [host]

    vulns: List[Dict[str, Any]] = []
    vulns += _hardening_findings(data, key, min_sev)
    vulns += _component_findings(data, key, min_sev)
    intel = _blocked_intel(data, host)

    return {"assets": assets, "services": [], "cpes": [], "vulns": vulns, "intel": intel}


# ── Load ──────────────────────────────────────────────────────────────────────
def _load(params: Dict[str, Any]) -> Dict[str, Any]:
    path = params.get("file") or os.getenv("SYSWARDEN_STATUS")
    if not path:
        raise RuntimeError("Provide a SysWarden status JSON via params['file'] or SYSWARDEN_STATUS (worker env)")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {"items": data}


# ── Host -> ASSET ─────────────────────────────────────────────────────────────
def _host(data: Dict[str, Any]) -> Dict[str, Any]:
    h = data.get("host") if isinstance(data.get("host"), dict) else data
    hostname = str(h.get("hostname") or h.get("name") or data.get("hostname") or "syswarden-host").strip()
    ip = h.get("ip") or h.get("ip_address") or data.get("ip")
    os_ = h.get("os") or h.get("platform") or data.get("os")
    hard = _hardening(data)
    note_bits = []
    if hard.get("cis_level") is not None:
        note_bits.append(f"CIS Level {hard['cis_level']}")
    if hard.get("score") is not None:
        note_bits.append(f"hardening score {hard['score']}")
    return {
        "hostname": hostname, "key": hostname,
        "ip": str(ip) if ip else None,
        "os": str(os_) if os_ else None,
        "notes": ("SysWarden HIDS/IPS — " + ", ".join(note_bits)) if note_bits else "SysWarden HIDS/IPS protected host",
    }


def _hardening(data: Dict[str, Any]) -> Dict[str, Any]:
    h = data.get("hardening")
    return h if isinstance(h, dict) else {}


# ── CIS hardening controls -> findings ────────────────────────────────────────
def _hardening_findings(data: Dict[str, Any], key: str, min_sev: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    hard = _hardening(data)
    controls = hard.get("controls") or hard.get("checks") or data.get("controls") or []
    for c in controls if isinstance(controls, list) else []:
        if not isinstance(c, dict):
            continue
        status = str(c.get("status") or c.get("state") or "").lower()
        applied = c.get("applied")
        # a finding when explicitly not applied / failed
        is_finding = status in ("not-applied", "not_applied", "notapplied", "failed", "fail", "non-compliant", "noncompliant") or applied is False
        if not is_finding:
            continue
        cid = str(c.get("id") or c.get("control") or c.get("rule") or "?")
        sev = _norm_sev(c.get("severity") or c.get("risk") or ("high" if status in ("failed", "fail") else "medium"))
        if _SEV_RANK.get(sev, 1) < min_sev:
            continue
        title = str(c.get("title") or c.get("name") or cid)
        out.append({"asset": key, "ref": f"SYSWARDEN-CIS-{cid}", "name": f"CIS hardening not applied: {title}"[:200], "severity": sev})
    return out


# ── Disabled defensive components -> posture findings ─────────────────────────
_COMPONENTS = {
    "nftables": ("Network filtering (nftables L2-L4) disabled", "high"),
    "pf": ("Network filtering (pf L2-L4) disabled", "high"),
    "modsecurity": ("OWASP ModSecurity WAF (L7) disabled", "high"),
    "waf": ("Web application firewall disabled", "high"),
    "wireguard": ("WireGuard SSH/admin cloaking disabled", "medium"),
    "ips": ("Intrusion prevention disabled", "high"),
}


def _component_findings(data: Dict[str, Any], key: str, min_sev: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    comps = data.get("components")
    if not isinstance(comps, dict):
        return out
    for name, val in comps.items():
        meta = _COMPONENTS.get(str(name).lower())
        if not meta:
            continue
        if _is_active(val):
            continue
        label, sev = meta
        if _SEV_RANK.get(sev, 1) < min_sev:
            continue
        out.append({"asset": key, "ref": f"SYSWARDEN-COMP-{str(name).lower()}", "name": label, "severity": sev})
    return out


def _is_active(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, dict):
        return _is_active(val.get("status") if "status" in val else val.get("enabled", val.get("active")))
    s = str(val).strip().lower()
    return s in ("active", "enabled", "on", "running", "true", "ok", "up", "1")


# ── Blocked source IPs -> threat-intel IOCs ───────────────────────────────────
def _blocked_intel(data: Dict[str, Any], host: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    sources: List[Any] = []
    for k in ("blocked", "blocked_ips", "blocks"):
        v = data.get(k)
        if isinstance(v, list):
            sources += v
    for grp in ("firewall", "waf", "ips"):
        g = data.get(grp)
        if isinstance(g, dict):
            for k in ("blocked", "blocked_ips", "blocks"):
                if isinstance(g.get(k), list):
                    sources += g[k]
    hostname = host.get("hostname") or "host"
    for b in sources:
        ip = b.get("ip") or b.get("source") or b.get("src") if isinstance(b, dict) else b
        if not ip:
            continue
        ip = str(ip).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        reason = (b.get("reason") or b.get("rule") or b.get("category") or "blocked by SysWarden") if isinstance(b, dict) else "blocked by SysWarden"
        count = b.get("count") if isinstance(b, dict) else None
        desc = f"Source {ip} blocked by SysWarden on {hostname} — {reason}" + (f" ({count} events)" if count else "")
        out.append({
            "name": f"SysWarden blocked {ip}",
            "description": desc[:500],
            "reference": f"syswarden://{hostname}/blocked/{ip}",
            "source": "SysWarden",
            "tags": "syswarden, blocked-ip, hids, ioc",
        })
    return out


def _norm_sev(v: Any) -> str:
    s = str(v or "").strip().lower()
    if s in _SEV_RANK:
        return "high" if s == "critical" else s
    if s in ("crit",):
        return "high"
    if s in ("med", "moderate"):
        return "medium"
    if s in ("info", "informational"):
        return "low"
    return "medium"


# ── Standalone CLI (offline dry run, with a built-in sample) ───────────────────
if __name__ == "__main__":
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="SysWarden connector (offline dry run)")
    ap.add_argument("--file", help="SysWarden status JSON export")
    ap.add_argument("--min-severity", default="low")
    a = ap.parse_args()
    if not a.file:
        # write a tiny sample so the scaffold is runnable out of the box
        sample = {
            "host": {"hostname": "edge01.example.com", "ip": "203.0.113.10", "os": "Debian 12"},
            "hardening": {"cis_level": 2, "score": 88, "controls": [
                {"id": "1.1.1", "title": "Ensure mounting of cramfs is disabled", "status": "applied"},
                {"id": "5.2.10", "title": "Ensure SSH root login is disabled", "status": "failed", "severity": "high"},
                {"id": "3.5.1", "title": "Ensure nftables default deny policy", "status": "not-applied", "severity": "medium"},
            ]},
            "components": {"nftables": "active", "modsecurity": "active", "wireguard": "inactive"},
            "blocked": [
                {"ip": "198.51.100.7", "reason": "volumetric DDoS (NIC drop)", "count": 91234},
                {"ip": "192.0.2.55", "reason": "ModSecurity 942100 SQLi", "count": 12},
            ],
        }
        fp = os.path.join(tempfile.mkdtemp(), "syswarden.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(sample, fh)
        a.file = fp
    res = run({"file": a.file, "min_severity": a.min_severity}, tempfile.mkdtemp())
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"\n[syswarden] {len(res['assets'])} asset(s), {len(res['vulns'])} hardening finding(s), "
          f"{len(res['intel'])} blocked-IP IOC(s)", flush=True)
