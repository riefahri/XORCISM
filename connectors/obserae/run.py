"""run.py — XORCISM connector: Obserae (NetFlow/IPFIX collector) -> ASSET discovery + services + sessions.

Parses an Obserae cartography + sessions export (YAML or JSON) and normalizes it into the netflow
shape the runner imports (runner.import_netflow):

  {"netflow": {assets:[...], services:[...], sessions:[...]}}

  - each host (cartography)        -> ASSET (network discovery, by name/ip/hostname)
  - each listening service          -> ASSETSERVICE (asset <-> service: protocol/port/service)
  - each reconstructed flow/session -> NETWORKSESSION (src<->dst asset/ip/port, bytes/packets, seen)

Expected YAML (see README.md):
  assets:   [{name, ip, hostname, os, zone, tags}]
  services: [{asset, protocol, port, service, banner, first_seen, last_seen, flows}]
  sessions: [{src, dst, protocol, src_port, dst_port, service, bytes, packets, flows,
              first_seen, last_seen, state, direction}]

Worker-safe: no DB, no network. Prefers PyYAML; falls back to json. ASCII-only output.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        return json.loads(text)  # YAML is a JSON superset for simple/flow-style docs


def _int(v: Any):
    try:
        return int(v)
    except Exception:
        return None


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise RuntimeError("obserae: provide a 'file' (Obserae YAML/JSON cartography + sessions export)")
    proto_default = str(params.get("default_protocol") or "tcp").lower()
    data = _load(path) or {}
    if not isinstance(data, dict):
        raise RuntimeError("obserae: unexpected export shape (expected a mapping with assets/services/sessions)")

    raw_assets = data.get("assets") or data.get("hosts") or data.get("cartography") or []
    raw_services = data.get("services") or data.get("ports") or []
    raw_sessions = data.get("sessions") or data.get("flows") or data.get("netflow") or []

    assets: List[Dict[str, Any]] = []
    for a in raw_assets:
        if not isinstance(a, dict):
            continue
        assets.append({"name": a.get("name") or a.get("hostname") or a.get("ip"),
                       "ip": a.get("ip") or a.get("address"), "hostname": a.get("hostname"),
                       "os": a.get("os") or a.get("os_name"), "zone": a.get("zone") or a.get("network"),
                       "tags": a.get("tags") or a.get("labels")})

    services: List[Dict[str, Any]] = []
    for s in raw_services:
        if not isinstance(s, dict):
            continue
        services.append({"asset": s.get("asset") or s.get("host") or s.get("ip") or s.get("name"),
                         "protocol": str(s.get("protocol") or s.get("proto") or proto_default).lower(),
                         "port": _int(s.get("port")), "service": s.get("service") or s.get("name") or s.get("app"),
                         "banner": s.get("banner"), "first_seen": s.get("first_seen"), "last_seen": s.get("last_seen"),
                         "flows": _int(s.get("flows") or s.get("flow_count"))})

    sessions: List[Dict[str, Any]] = []
    for f in raw_sessions:
        if not isinstance(f, dict):
            continue
        src = f.get("src") or f.get("source") or f.get("src_ip") or f.get("client")
        dst = f.get("dst") or f.get("destination") or f.get("dst_ip") or f.get("server")
        if not src or not dst:
            continue
        sessions.append({"src": src, "dst": dst,
                         "protocol": str(f.get("protocol") or f.get("proto") or proto_default).lower(),
                         "src_port": _int(f.get("src_port") or f.get("sport")),
                         "dst_port": _int(f.get("dst_port") or f.get("dport") or f.get("port")),
                         "service": f.get("service") or f.get("app") or f.get("name"),
                         "bytes": _int(f.get("bytes") or f.get("octets")), "packets": _int(f.get("packets") or f.get("pkts")),
                         "flows": _int(f.get("flows") or f.get("flow_count")) or 1,
                         "first_seen": f.get("first_seen") or f.get("start"), "last_seen": f.get("last_seen") or f.get("end"),
                         "state": f.get("state") or f.get("tcp_state"), "direction": f.get("direction")})

    return {"source": "Obserae",
            "netflow": {"assets": [a for a in assets if a.get("name")], "services": services, "sessions": sessions},
            "summary": {"assets": len([a for a in assets if a.get('name')]), "services": len(services), "sessions": len(sessions)}}


if __name__ == "__main__":
    import argparse
    import tempfile
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--default-protocol", default="tcp")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "default_protocol": a.default_protocol}, tempfile.mkdtemp()), indent=2))
