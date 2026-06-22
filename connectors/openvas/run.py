"""run.py — XORCISM connector: OpenVAS / Greenbone (GVM) → assets / vulns.

Imports Greenbone Vulnerability Management (GVM / OpenVAS) findings.

Offline: parse a GMP XML report export (`gvm-cli … get_reports` / the web-UI export).
Live:    drive gvmd over GMP (python-gvm): create a target, run a scan task, wait for
         completion, fetch the report XML, parse it. Connection + credentials via the
         worker env: GVM_HOST (or GVM_SOCKET), GVM_PORT (default 9390), GVM_USER, GVM_PASSWORD.

Mapping → {assets, vulns}:
  - scanned host                 -> ASSET (host/ip)
  - each result (NVT + severity) -> VULNERABILITY (CVE refs, else NVT:<oid>; severity from threat/CVSS)

No DB access (worker-safe). The XML is parsed defensively (offline files and live exports share
the same <report><results><result> shape).
"""
from __future__ import annotations

import json
import os
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

# Well-known GVM UUIDs (overridable via env): "Full and fast" config + the OpenVAS scanner.
_SCAN_CONFIG = os.environ.get("GVM_SCAN_CONFIG", "daba56c8-73ec-11df-a475-002264764cea")
_SCANNER = os.environ.get("GVM_SCANNER", "08b69003-5fc2-4037-a479-93b440211c73")


def _sev_label(cvss: float, threat: str) -> str:
    if threat:
        t = threat.lower()
        if t in ("critical", "high", "medium", "low"):
            return t
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _parse(root: ET.Element, min_cvss: float, default_target: str = "") -> Dict[str, Any]:
    assets: Dict[str, Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    for result in root.iter("result"):
        host_el = result.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        if not host:
            host = default_target.strip()
        if not host:
            continue
        try:
            cvss = float((result.findtext("severity") or "0").strip() or 0)
        except ValueError:
            cvss = 0.0
        if cvss < min_cvss:
            continue
        assets.setdefault(host, {"hostname": host, "ip": host, "key": host})
        name = (result.findtext("name") or "OpenVAS finding").strip()
        threat = (result.findtext("threat") or "").strip()
        nvt = result.find("nvt")
        cves: List[str] = []
        oid = ""
        if nvt is not None:
            oid = nvt.get("oid") or ""
            for ref in nvt.findall("./refs/ref"):
                if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
                    cves.append(ref.get("id"))
        refs = cves or ([f"NVT:{oid}"] if oid else [f"OPENVAS:{name}"])
        for ref in refs:
            vulns.append({"asset": host, "ref": ref, "name": name, "severity": _sev_label(cvss, threat)})
    if not assets and default_target:
        assets[default_target] = {"hostname": default_target, "ip": default_target, "key": default_target}
    return {"assets": list(assets.values()), "vulns": vulns, "services": [], "cpes": []}


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    min_cvss = float(params.get("min_cvss", 0.1) or 0.0)
    if params.get("file"):
        root = ET.parse(params["file"]).getroot()
        return _parse(root, min_cvss)
    target = str(params.get("target") or "").strip()
    if target:
        xml = _run_live(target, workdir)
        return _parse(ET.fromstring(xml), min_cvss, default_target=target)
    raise ValueError("openvas: provide a 'file' (GMP XML report) or a 'target' (live GMP scan)")


def _run_live(target: str, workdir: str) -> str:
    """Drive gvmd via GMP to scan `target` and return the report XML. Best-effort:
    raises a clear error (pointing to offline mode) if python-gvm or gvmd is unavailable."""
    try:
        from gvm.connections import TLSConnection, UnixSocketConnection  # type: ignore
        from gvm.protocols.gmp import Gmp  # type: ignore
        from gvm.transforms import EtreeTransform  # type: ignore
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            "openvas live mode needs python-gvm (`pip install python-gvm`). "
            f"Import failed: {e}. Export the report to XML and import it via the 'file' parameter instead."
        )

    user = os.environ.get("GVM_USER", "")
    password = os.environ.get("GVM_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("openvas live mode needs GVM_USER + GVM_PASSWORD in the worker env")
    socket = os.environ.get("GVM_SOCKET", "")
    if socket:
        connection = UnixSocketConnection(path=socket)
    else:
        connection = TLSConnection(hostname=os.environ.get("GVM_HOST", "127.0.0.1"),
                                   port=int(os.environ.get("GVM_PORT", "9390")))
    poll_interval = int(os.environ.get("GVM_POLL_SECONDS", "20"))
    timeout = int(os.environ.get("GVM_TIMEOUT", "10800"))  # 3h default

    with Gmp(connection, transform=EtreeTransform()) as gmp:
        gmp.authenticate(user, password)
        suffix = str(int(time.time()))
        tgt = gmp.create_target(name=f"xorcism-{target}-{suffix}", hosts=[target])
        target_id = tgt.get("id")
        task = gmp.create_task(name=f"xorcism-scan-{target}-{suffix}", config_id=_SCAN_CONFIG,
                               target_id=target_id, scanner_id=_SCANNER)
        task_id = task.get("id")
        gmp.start_task(task_id)
        deadline = time.time() + timeout
        report_id = ""
        while time.time() < deadline:
            t = gmp.get_task(task_id)
            status = t.findtext(".//status") or ""
            if status in ("Done", "Stopped", "Interrupted"):
                last = t.find(".//last_report/report")
                report_id = last.get("id") if last is not None else ""
                break
            time.sleep(poll_interval)
        if not report_id:
            raise RuntimeError("openvas: scan did not finish within GVM_TIMEOUT")
        rep = gmp.get_report(report_id, details=True, ignore_pagination=True)
        out = os.path.join(workdir, "openvas-report.xml")
        xml = ET.tostring(rep, encoding="unicode")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(xml)
        return xml


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="OpenVAS/Greenbone import (dry run)")
    ap.add_argument("--file")
    ap.add_argument("--target", default="")
    ap.add_argument("--min-cvss", default="0.1")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "target": a.target, "min_cvss": a.min_cvss}, "."), indent=2, ensure_ascii=False))
