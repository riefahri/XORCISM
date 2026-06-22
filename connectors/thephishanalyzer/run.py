"""run.py — XORCISM connector: ThePhishAnalyzer → phishing IOCs (XTHREAT.INTELEXCHANGE).

Parses a phishing email (.eml / RFC822) and extracts indicators of compromise:
  - sender, return-path, reply-to
  - SPF / DKIM / DMARC results (from Authentication-Results / Received-SPF)
  - every URL found in the body + the domains/IPs they reference
  - SHA-256 of each attachment

Each IOC becomes a normalized "intel" item (runner.import_threat_intel → XTHREAT.INTELEXCHANGE),
tagged with `label` (default 'phishing'); the email itself is one summary report item. Worker-safe:
stdlib only, no DB, no network. ASCII-only output.

The input `file` is typically a DOCUMENT exported from XORCISM (around DOCUMENT integration).
"""
from __future__ import annotations

import email
import hashlib
import json
import re
from email import policy
from typing import Any, Dict, List

_URL = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)", re.I)


def _bodies(msg) -> str:
    out = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    out.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        out.append(payload.decode("utf-8", "replace"))
    else:
        try:
            out.append(msg.get_content())
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                out.append(payload.decode("utf-8", "replace"))
    return "\n".join(str(x) for x in out)


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:
    path = params.get("file")
    if not path:
        raise RuntimeError("thephishanalyzer: provide a 'file' (.eml / RFC822 email)")
    label = str(params.get("label") or "phishing").strip() or "phishing"
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    subject = str(msg.get("Subject", "") or "")[:300]
    sender = str(msg.get("From", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    auth_results = " ".join(str(msg.get_all(h, []) and "; ".join(str(v) for v in msg.get_all(h, [])) or "")
                            for h in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results"))
    auth = {k.lower(): v.lower() for k, v in _AUTH.findall(auth_results)}

    body = _bodies(msg)
    urls = sorted(set(m.group(0).rstrip(".,);") for m in _URL.finditer(body + " " + subject)))
    domains, ips = set(), set()
    for u in urls:
        m = re.match(r"https?://([^/:\s]+)", u, re.I)
        if m:
            host = m.group(1)
            (ips if _IPV4.fullmatch(host) else domains).add(host.lower())
    # sender domain
    m = re.search(r"@([a-z0-9.-]+)", sender, re.I)
    sender_domain = m.group(1).lower() if m else None
    if sender_domain:
        domains.add(sender_domain)

    attachments = []
    for part in (msg.walk() if msg.is_multipart() else []):
        fn = part.get_filename()
        if fn:
            payload = part.get_payload(decode=True) or b""
            attachments.append({"name": fn, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)})

    intel: List[Dict[str, Any]] = []

    def add(name, kind, value, desc):
        intel.append({"name": name[:200], "reference": "phish:%s:%s" % (kind, value),
                      "external_id": value, "description": desc[:500], "tags": label, "date": str(msg.get("Date", ""))[:40]})

    # summary report item
    verdict = "suspicious"
    if auth.get("spf") == "fail" or auth.get("dkim") == "fail" or auth.get("dmarc") == "fail":
        verdict = "malicious"
    add("Phishing email: " + (subject or "(no subject)"), "email", subject or sender,
        "From=%s; verdict=%s; SPF=%s DKIM=%s DMARC=%s; %d URL(s), %d attachment(s)" % (
            sender, verdict, auth.get("spf", "?"), auth.get("dkim", "?"), auth.get("dmarc", "?"), len(urls), len(attachments)))
    if sender:
        add("Sender " + sender, "sender", sender, "Phishing sender / From header")
    if return_path and return_path != sender:
        add("Return-Path " + return_path, "sender", return_path, "Phishing return-path")
    for u in urls:
        add("URL " + u, "url", u, "URL found in phishing email")
    for d in sorted(domains):
        add("Domain " + d, "domain", d, "Domain referenced by phishing email")
    for ip in sorted(ips):
        add("IP " + ip, "ip", ip, "IP referenced by phishing email")
    for a in attachments:
        add("Attachment " + a["name"], "file", a["sha256"], "Attachment %s (%d bytes)" % (a["name"], a["size"]))

    return {"source": "ThePhishAnalyzer", "intel": intel,
            "summary": {"subject": subject, "sender": sender, "verdict": verdict, "urls": len(urls),
                        "domains": len(domains), "ips": len(ips), "attachments": len(attachments), "indicators": len(intel)}}


if __name__ == "__main__":
    import argparse
    import tempfile
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--label", default="phishing")
    a = ap.parse_args()
    print(json.dumps(run({"file": a.file, "label": a.label}, tempfile.mkdtemp()), indent=2))
