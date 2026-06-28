"""run.py - XORCISM connector: agentless / offline host scan -> asset + software inventory + hardening.

A Cyberwatch-style *credentialed agentless* host scan: instead of an agent, an admin session (SSH / WinRM)
or an air-gapped collector reads the host's OS, installed software and a few security-baseline checks into a
JSON snapshot (see collect.sh / collect.ps1). This connector ingests that snapshot and maps it to XORCISM
(no live access, no DB access here - worker-safe):

  host                       -> ASSET  (key = hostname; tags agentless / host / <os family> / <os name>)
  OS + each installed package -> a CPE linked to that asset (emitted as `services[{asset, cpe}]`), so the
                                 platform's own CVE matcher (cvematch) detects the affected CVEs after import
                                 -- agentless vulnerability detection with no active probing.
  listening ports            -> service facts
  failed baseline checks      -> hardening VULNs + a per-host "hardening level" summary (Compliance Manager)
  any CVEs already in the snapshot -> VULNs directly.

Input ('file') is a snapshot for one host ({hostname, os, packages, ...}) or many ({"hosts":[ ... ]}).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

SOURCE = "Agentless host scan"

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "med": "medium",
        "moderate": "medium", "low": "low", "info": "info", "informational": "info"}

# package/product -> NVD CPE vendor (best-effort; unknown -> vendor = product).
_PKG_VENDOR = {
    "openssh": "openbsd", "openssh-server": "openbsd", "openssh-client": "openbsd", "ssh": "openbsd",
    "openssl": "openssl", "libssl": "openssl",
    "nginx": "nginx", "apache2": "apache", "httpd": "apache", "apache": "apache",
    "mysql": "oracle", "mysql-server": "oracle", "mariadb": "mariadb", "mariadb-server": "mariadb",
    "postgresql": "postgresql", "postgres": "postgresql",
    "bash": "gnu", "glibc": "gnu", "libc6": "gnu", "gnutls": "gnu",
    "sudo": "sudo_project", "curl": "haxx", "libcurl": "haxx", "wget": "gnu",
    "python3": "python", "python": "python", "python2": "python",
    "openjdk": "oracle", "java": "oracle", "tomcat": "apache",
    "php": "php", "nodejs": "nodejs", "node": "nodejs", "redis": "redis",
    "vim": "vim", "git": "git", "samba": "samba", "bind9": "isc", "bind": "isc",
    "dnsmasq": "thekelleys", "ntp": "ntp", "chrony": "chrony", "rsync": "samba",
    "docker": "docker", "docker-ce": "docker", "containerd": "linuxfoundation", "kubelet": "kubernetes",
}
# package name normalisation (strip distro suffixes) -> canonical product
_PKG_PRODUCT = {
    "openssh-server": "openssh", "openssh-client": "openssh", "libssl3": "openssl", "libssl1.1": "openssl",
    "apache2": "http_server", "httpd": "http_server", "mysql-server": "mysql", "mariadb-server": "mariadb",
    "libc6": "glibc", "python3": "python", "python2": "python", "openjdk-17-jre": "jre", "docker-ce": "docker",
    "nodejs": "node.js", "bind9": "bind",
}
# OS id -> (vendor, product)
_OS_CPE = {
    "ubuntu": ("canonical", "ubuntu_linux"), "debian": ("debian", "debian_linux"),
    "rhel": ("redhat", "enterprise_linux"), "centos": ("centos", "centos"),
    "rocky": ("rocky", "rocky_linux"), "almalinux": ("almalinux", "almalinux"),
    "fedora": ("fedoraproject", "fedora"), "amzn": ("amazon", "amazon_linux"),
    "sles": ("suse", "linux_enterprise_server"), "opensuse": ("opensuse", "leap"),
    "alpine": ("alpinelinux", "alpine_linux"),
    "windows": ("microsoft", "windows"), "windows_server": ("microsoft", "windows_server"),
}


def _sev(v: Any, d: str = "medium") -> str:
    return _SEV.get(str(v or "").strip().lower(), d)


def _short(v: Any, n: int) -> str:
    return str(v if v is not None else "")[:n]


def _norm(tok: Any) -> str:
    return re.sub(r"[^a-z0-9._]+", "_", str(tok or "").strip().lower()).strip("_")


def _cpe(part: str, vendor: str, product: str, version: str = "*") -> str:
    v = _norm(vendor) or "*"
    p = _norm(product) or "*"
    ver = re.sub(r"[\s:]+", "_", str(version or "*").strip()) or "*"
    return "cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*" % (part, v, p, ver)


def _pkg_cpe(name: str, version: str) -> str:
    raw = str(name or "").strip().lower()   # keeps hyphens, e.g. "openssh-server"
    base = _norm(name)                       # "openssh_server"
    product = _PKG_PRODUCT.get(raw) or _PKG_PRODUCT.get(base) or base
    vendor = (_PKG_VENDOR.get(raw) or _PKG_VENDOR.get(base)
              or _PKG_VENDOR.get(product) or product)
    return _cpe("a", vendor, product, version)


def _os_cpe(os_obj: Dict[str, Any]) -> str:
    name = _norm(os_obj.get("name") or os_obj.get("id") or os_obj.get("family") or "")
    ver = os_obj.get("version") or os_obj.get("version_id") or "*"
    vendor, product = _OS_CPE.get(name, ("", name or "linux"))
    if not vendor and (os_obj.get("family") or "").lower().startswith("win"):
        vendor, product = "microsoft", "windows"
    return _cpe("o", vendor or product, product, ver)


def _hosts(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [h for h in data if isinstance(h, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("hosts"), list):
            return [h for h in data["hosts"] if isinstance(h, dict)]
        return [data]
    return []


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    path = params.get("file")
    if not path:
        raise RuntimeError("agentless-scan: provide a 'file' (a host snapshot JSON from collect.sh / collect.ps1)")
    with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    hosts = _hosts(data)
    if not hosts:
        raise RuntimeError("agentless-scan: no host snapshot found in the file")

    assets: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    cpes: List[str] = []
    vulns: List[Dict[str, Any]] = []
    n = 0

    for h in hosts:
        key = str(h.get("hostname") or h.get("ip") or h.get("name") or "host").strip() or "host"
        os_obj = h.get("os") if isinstance(h.get("os"), dict) else {"name": h.get("os")}
        fam = _norm(os_obj.get("family") or ("windows" if "win" in _norm(os_obj.get("name")) else "linux"))
        tags = ["agentless", "host"]
        if fam:
            tags.append(fam)
        if os_obj.get("name"):
            tags.append(_norm(os_obj.get("name"))[:40])
        a = {"hostname": _short(key, 200), "key": key, "tags": tags}
        if h.get("ip"):
            a["ip"] = _short(h.get("ip"), 60)
        if os_obj.get("name") or os_obj.get("version"):
            a["os"] = _short("%s %s" % (os_obj.get("name") or "", os_obj.get("version") or ""), 120).strip()
        assets.append(a)

        # OS CPE -> asset
        oc = _os_cpe(os_obj)
        cpes.append(oc)
        services.append({"asset": key, "cpe": oc, "port": 0, "proto": "", "service": "os",
                         "version": _short(os_obj.get("version") or "", 60)})

        # installed software -> CPE per asset
        for pkg in (h.get("packages") or h.get("software") or []):
            if isinstance(pkg, str):
                m = re.match(r"^(.*?)[ =@]+([0-9][\w.\-+:~]*)$", pkg.strip())
                name, ver = (m.group(1), m.group(2)) if m else (pkg.strip(), "*")
            elif isinstance(pkg, dict):
                name = pkg.get("name") or pkg.get("package") or ""
                ver = pkg.get("version") or pkg.get("ver") or "*"
            else:
                continue
            if not name:
                continue
            pc = _pkg_cpe(name, ver)
            cpes.append(pc)
            services.append({"asset": key, "cpe": pc, "port": 0, "proto": "", "service": _short(name, 60),
                             "version": _short(ver, 60)})

        # listening ports -> service facts
        for sp in (h.get("listening") or h.get("ports") or []):
            if not isinstance(sp, dict):
                continue
            try:
                port = int(sp.get("port"))
            except (TypeError, ValueError):
                continue
            services.append({"asset": key, "port": port, "proto": _short(sp.get("proto") or "tcp", 8),
                             "service": _short(sp.get("service") or "", 60), "name": _short(sp.get("service") or "", 60),
                             "version": _short(sp.get("version") or "", 80)})

        # security-baseline (hardening) checks -> VULNs + per-host hardening level
        checks = h.get("checks") or h.get("baseline") or []
        passed = total = 0
        for ck in checks:
            if not isinstance(ck, dict):
                continue
            res = str(ck.get("result") or ck.get("status") or "").strip().lower()
            if res in ("pass", "passed", "ok", "true"):
                passed += 1
                total += 1
                continue
            if res in ("na", "n/a", "skip", "not_applicable", "notapplicable"):
                continue
            total += 1
            n += 1
            vulns.append({"asset": key, "ref": "AGENTLESS-CIS-%d" % n, "severity": _sev(ck.get("severity"), "medium"),
                          "name": _short("Hardening: %s" % (ck.get("title") or ck.get("id") or "baseline check failed"), 240),
                          "description": _short("%s Baseline %s failed on %s%s. %s"
                                                % (ck.get("description") or "", ck.get("id") or "check", key,
                                                   (" (%s)" % ck.get("ref")) if ck.get("ref") else "",
                                                   "Remediate to meet the security baseline (CIS/ANSSI/STIG).") , 1600)})
        if total:
            score = round(100 * passed / total)
            sev = "info" if score >= 90 else "low" if score >= 70 else "medium" if score >= 50 else "high"
            n += 1
            vulns.append({"asset": key, "ref": "AGENTLESS-HARDEN-%s" % _norm(key), "severity": sev,
                          "name": _short("Hardening level: %d%% (%d/%d baseline checks passed)" % (score, passed, total), 240),
                          "description": "Security-baseline hardening level for %s computed from the agentless scan: %d of %d checks passed (%d%%). Cyberwatch-style Compliance Manager baseline." % (key, passed, total, score)})

        # CVEs already present in the snapshot (if the collector ran a local checker)
        for cv in (h.get("cves") or h.get("vulns") or []):
            if isinstance(cv, str):
                cve_id, sev, title = cv, "medium", cv
            elif isinstance(cv, dict):
                cve_id = cv.get("cve") or cv.get("id") or cv.get("ref") or ""
                sev = _sev(cv.get("severity"), "medium")
                title = cv.get("title") or cv.get("name") or cve_id
            else:
                continue
            if not cve_id:
                continue
            n += 1
            rec = {"asset": key, "ref": "AGENTLESS-%s-%d" % (_norm(cve_id), n), "severity": sev,
                   "name": _short(title, 240), "description": _short("%s detected on %s by the agentless scan." % (cve_id, key), 1600)}
            if str(cve_id).upper().startswith("CVE-"):
                rec["cve"] = str(cve_id).upper()[:40]
            vulns.append(rec)

    # de-dup cpe catalog
    cpes = sorted(set(c for c in cpes if c))
    return {"source": SOURCE, "project": None, "assets": assets, "services": services, "cpes": cpes, "vulns": vulns}


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    r = run({"file": sys.argv[1]}, ".")
    print("agentless-scan: %d assets, %d services (CPE-linked sw + ports), %d cpes, %d findings"
          % (len(r["assets"]), len(r["services"]), len(r["cpes"]), len(r["vulns"])))
    for v in r["vulns"][:12]:
        print("  %-9s %-22s %s" % (v["severity"], v["ref"], v["name"][:60]))
