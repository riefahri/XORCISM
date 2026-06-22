"""run.py — XORCISM outbound connector for Microsoft Teams.

Posts a XORCISM alert / incident / message to a Microsoft Teams channel through an incoming
webhook. Supports both Teams payloads, auto-detected from the webhook host:
  * Adaptive Card  — modern Power Automate / Workflows webhooks (default).
  * MessageCard    — legacy Office 365 "Incoming Webhook" connector (*.webhook.office.com).

This is the connector (manual / attack-chain) counterpart to the in-app distribution in
xorcism_ts/server/teams.ts, which fans alerts & notifications out to Teams automatically.

Modes:
    live    : TEAMS_WEBHOOK_URL (or param `webhook`) set, dry_run off -> POSTs and returns {"notify":1}.
    dry-run : no webhook, or dry_run=true -> builds and returns the payload WITHOUT sending.

The runner treats the "notify" key as an outbound action (runner.import_result short-circuits to a
no-op count) — this connector never reads/writes the database. Worker-safe: stdlib only, secrets
via env, ASCII-only output.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List

_THEME = {"critical": "b91c1c", "high": "ea580c", "medium": "ca8a04", "low": "16a34a", "info": "2563eb"}
_ADAPTIVE = {"critical": "Attention", "high": "Attention", "medium": "Warning", "low": "Good", "info": "Accent"}
_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F7E2", "info": "\U0001F535"}


def _norm_sev(s: str) -> str:
    v = (s or "").strip().lower()
    if v.startswith("crit"):
        return "critical"
    if v.startswith("high"):
        return "high"
    if v.startswith("med") or v in ("warn", "warning"):
        return "medium"
    if v.startswith("low"):
        return "low"
    return "info"


def _detect_format(url: str, explicit: str) -> str:
    f = (explicit or "auto").strip().lower()
    if f in ("adaptivecard", "messagecard"):
        return f
    host = urllib.parse.urlparse(url).hostname or ""
    return "messagecard" if any(h in host for h in ("webhook.office.com", "outlook.office.com", "office365.com")) else "adaptivecard"


def _build(params: Dict[str, Any], fmt: str) -> Dict[str, Any]:
    text = str(params.get("text") or "").strip()
    title = str(params.get("title") or "").strip()
    if not text and not title:
        raise RuntimeError("teams: provide at least `text` or `title`.")
    sev = _norm_sev(str(params.get("severity") or ""))
    link = str(params.get("link") or "").strip()
    head = f"{_EMOJI[sev]} {title or 'XORCISM alert'}"
    facts: List[Dict[str, str]] = []
    if params.get("severity"):
        facts.append({"name": "Severity", "value": str(params["severity"])})

    if fmt == "messagecard":
        card: Dict[str, Any] = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "themeColor": _THEME[sev], "summary": (title or "XORCISM alert")[:250], "title": head,
            "sections": [{"text": text or title, "facts": facts}],
        }
        if link.startswith("http"):
            card["potentialAction"] = [{"@type": "OpenUri", "name": "Open in XORCISM",
                                        "targets": [{"os": "default", "uri": link}]}]
        return card

    body: List[Dict[str, Any]] = [
        {"type": "TextBlock", "text": head, "weight": "Bolder", "size": "Large", "color": _ADAPTIVE[sev], "wrap": True},
    ]
    if text:
        body.append({"type": "TextBlock", "text": text, "wrap": True})
    if facts:
        body.append({"type": "FactSet", "facts": [{"title": f["name"], "value": f["value"]} for f in facts]})
    content: Dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
        "version": "1.4", "body": body, "msteams": {"width": "Full"},
    }
    if link.startswith("http"):
        content["actions"] = [{"type": "Action.OpenUrl", "title": "Open in XORCISM", "url": link}]
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}]}


def _post(url: str, payload: Dict[str, Any]) -> bool:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (operator-supplied URL)
        resp.read()
        return 200 <= resp.status < 300


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    webhook = (str(params.get("webhook") or "").strip() or os.environ.get("TEAMS_WEBHOOK_URL", "").strip())
    fmt = _detect_format(webhook, str(params.get("format") or "auto"))
    payload = _build(params, fmt)
    dry = str(params.get("dry_run") or "").lower() in ("1", "true", "yes") or not webhook
    if dry:
        return {"source": "Microsoft Teams", "notify": 0, "dry_run": True, "format": fmt, "payload": payload}
    ok = _post(webhook, payload)
    return {"source": "Microsoft Teams", "notify": 1 if ok else 0, "format": fmt}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({"title": "Ransomware note on SRV-FS-02", "text": "Mass .lockbit rename across 3 shares.",
                          "severity": "critical", "link": "https://xorcism.local/?db=XINCIDENT&table=ALERT",
                          "dry_run": True}, tempfile.mkdtemp()), indent=2))
