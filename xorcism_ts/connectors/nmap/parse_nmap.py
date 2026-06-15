"""
parse_nmap.py — Nmap XML (-oX) output parser for the XORCISM connector.

Parser contract:
    parse(path_or_text, params) -> normalized dict:
      {
        "assets":   [ {ip, hostname, mac, os, os_accuracy} ],
        "services": [ {asset, port, protocol, state, name, product, version, cpe} ],
        "cpes":     [ "cpe:/...", ... ],
        "vulns":    [ {asset, port, ref, source} ],   # via NSE scripts (vulners…)
      }

Pure (no database access) — the import into XORCISM (ASSET, services, CPE, CPEFORASSET,
VULNERABILITY/ASSETVULNERABILITY) is performed by the runner from this result.

Usable standalone:
    python parse_nmap.py scan.xml
"""

from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _load(path_or_text: str) -> ET.Element:
    if os.path.exists(path_or_text):
        return ET.parse(path_or_text).getroot()
    return ET.fromstring(path_or_text)


def parse(path_or_text: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    root = _load(path_or_text)
    assets: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    cpes: set = set()
    vulns: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") not in (None, "up"):
            continue

        ip = mac = None
        for addr in host.findall("address"):
            at = addr.get("addrtype")
            if at in ("ipv4", "ipv6") and not ip:
                ip = addr.get("addr")
            elif at == "mac":
                mac = addr.get("addr")
        if not ip:
            continue

        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else None

        os_name = os_acc = None
        osm = host.find("os/osmatch")
        if osm is not None:
            os_name = osm.get("name")
            os_acc = osm.get("accuracy")
            for c in host.findall("os/osmatch/osclass/cpe"):
                if c.text:
                    cpes.add(c.text.strip())

        assets.append({"ip": ip, "hostname": hostname, "mac": mac,
                       "os": os_name, "os_accuracy": os_acc})

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol")
            svc = port.find("service")
            name = product = version = cpe = None
            if svc is not None:
                name = svc.get("name")
                product = svc.get("product")
                version = svc.get("version")
                c = svc.find("cpe")
                if c is not None and c.text:
                    cpe = c.text.strip()
                    cpes.add(cpe)
            services.append({
                "asset": ip, "port": int(portid) if portid else None,
                "protocol": proto, "state": "open", "name": name,
                "product": product, "version": version, "cpe": cpe,
            })

            # NSE scripts (e.g. vulners) → CVE references
            for script in port.findall("script"):
                out = script.get("output") or ""
                for cve in set(_CVE.findall(out)):
                    vulns.append({"asset": ip, "port": int(portid) if portid else None,
                                  "ref": cve.upper(), "source": script.get("id")})

    return {
        "assets": assets,
        "services": services,
        "cpes": sorted(cpes),
        "vulns": vulns,
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python parse_nmap.py scan.xml", file=sys.stderr)
        sys.exit(2)
    result = parse(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\n# {len(result['assets'])} hôtes, "
          f"{len(result['services'])} services, "
          f"{len(result['cpes'])} CPE, "
          f"{len(result['vulns'])} vulns", file=sys.stderr)


if __name__ == "__main__":
    main()
