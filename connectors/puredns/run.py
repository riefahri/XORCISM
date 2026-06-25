"""run.py -- XORCISM connector: puredns -> assets (resolved subdomains).

puredns (https://github.com/d3mondev/puredns) is a fast domain resolver and
subdomain brute-forcing tool built on massdns. It brute-forces a wordlist against
a domain (or resolves a candidate list), filters DNS wildcards and validates the
answers against trusted resolvers, leaving the set of live, resolvable subdomains.

Offline: parse a puredns results file (`puredns ... -w resolved.txt`), one resolved
         domain per line, OR a massdns "-o S" simple export (`name. A 1.2.3.4`).
Live:    if `target` is set and the `puredns` binary is on PATH, run it and parse stdout.

Mapping into the normalized XORCISM findings model {assets, services, cpes, vulns}:
  - each resolved subdomain -> ASSET (host); its A/AAAA record -> the asset's ip.

No DB access (worker-safe). Stdlib only. ASCII output.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any, Dict, List

# massdns "-o S" simple line:  "api.example.com. A 1.2.3.4"  (also AAAA / CNAME)
_MASSDNS = re.compile(r"^(?P<name>[^\s]+?)\.?\s+(?P<type>A|AAAA|CNAME)\s+(?P<val>[^\s]+?)\.?$", re.I)
_HOST = re.compile(r"^(?:[a-z0-9_-]+\.)+[a-z]{2,}$", re.I)  # rejects wildcard "*." entries


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    target = str(params.get("target") or "").strip().lower()
    if params.get("file"):
        with open(params["file"], "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        if not target:
            raise RuntimeError("puredns: provide a 'file' (results export) or a 'target' domain for live mode")
        text = _run_puredns(params, target, workdir)
    return _parse(text, target)


def _run_puredns(params: Dict[str, Any], target: str, workdir: str) -> str:
    exe = shutil.which("puredns")
    if not exe:
        raise RuntimeError("puredns binary not found on PATH; use the 'file' parameter (offline results export) instead")
    wordlist = str(params.get("wordlist") or "").strip()
    if not wordlist or not os.path.exists(wordlist):
        raise RuntimeError("puredns live mode needs a 'wordlist' path on the worker (subdomain list, or candidate-domains file for resolve mode)")
    mode = str(params.get("mode") or "bruteforce").strip().lower()
    out = os.path.join(workdir, "puredns.txt")
    if mode == "resolve":
        argv = [exe, "resolve", wordlist, "-w", out, "-q"]
    else:
        argv = [exe, "bruteforce", wordlist, target, "-w", out, "-q"]
    resolvers = str(params.get("resolvers") or "").strip()
    if resolvers and os.path.exists(resolvers):
        argv += ["-r", resolvers]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=3600, check=False)  # noqa: S603
    if os.path.exists(out):
        with open(out, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    # fall back to stdout if -w produced nothing
    return proc.stdout or ""


def _parse(text: str, target: str) -> Dict[str, Any]:
    by_host: Dict[str, str] = {}   # hostname -> ip ("" if unknown)
    for raw in (text or "").splitlines():
        line = raw.strip().rstrip(".")
        if not line or line.startswith((";", "#")):
            continue
        m = _MASSDNS.match(raw.strip())
        if m:
            name = m.group("name").strip().rstrip(".").lower()
            ip = m.group("val").strip().rstrip(".") if m.group("type").upper() in ("A", "AAAA") else ""
            if _HOST.match(name):
                if name not in by_host or (ip and not by_host[name]):
                    by_host[name] = ip
            continue
        # plain "one domain per line"
        host = line.split()[0].lower()
        if _HOST.match(host):
            by_host.setdefault(host, "")

    # keep only hosts within the target domain when a target is known (defensive scoping)
    hosts = sorted(by_host)
    if target:
        scoped = [h for h in hosts if h == target or h.endswith("." + target)]
        if scoped:
            hosts = scoped

    assets: List[Dict[str, str]] = []
    for h in hosts:
        a: Dict[str, str] = {"hostname": h}
        if by_host.get(h):
            a["ip"] = by_host[h]
        assets.append(a)
    return {
        "assets": assets,
        "hosts": hosts,
        "services": [],
        "cpes": [],
        "vulns": [],
        "summary": "puredns: %d resolved subdomain(s)%s" % (len(hosts), (" for " + target) if target else ""),
    }


if __name__ == "__main__":
    import json
    import sys
    p: Dict[str, Any] = {}
    for arg in sys.argv[1:]:
        if "=" in arg:
            k, v = arg.split("=", 1)
            p[k] = v
    print(json.dumps(run(p, os.getcwd()), indent=2))
