"""run.py — XORCISM outbound ChatOps connector for Slack / Mattermost.

The OUTBOUND counterpart to the inbound SOC-tool connectors (TheHive, ServiceNow, PagerDuty,
Opsgenie, Zammad). It POSTs a XORCISM alert / incident / message to a Slack or Mattermost
channel through an incoming webhook. Mattermost's incoming webhook intentionally mirrors Slack's
payload ({text, attachments:[{color,title,title_link,text,fields,footer}]}), so one connector
serves both.

Modes:
    live    : SLACK_WEBHOOK_URL / MATTERMOST_WEBHOOK_URL (or param `webhook`) set, dry_run off
              -> POSTs the message and returns {"notify": 1}.
    dry-run : no webhook, or dry_run=true -> builds and returns the payload WITHOUT sending
              (so it is safe to test and inspect).

The runner treats the "notify" key as an outbound action (runner.import_result short-circuits to
a no-op count) — this connector never reads or writes the database, so it is worker-safe.
Config (worker environment variables, never entered in the UI):
    SLACK_WEBHOOK_URL       Slack incoming-webhook URL          (live)
    MATTERMOST_WEBHOOK_URL  Mattermost incoming-webhook URL     (live)
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List

# Severity -> attachment colour (hex). Mirrors XORCISM's Defender-style severity palette.
_COLOR = {
    "critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#16a34a", "info": "#2563eb", "informational": "#2563eb",
}
_EMOJI = {"critical": ":rotating_light:", "high": ":fire:", "medium": ":warning:",
          "low": ":large_green_circle:", "info": ":information_source:"}


def _build_payload(params: Dict[str, Any]) -> Dict[str, Any]:
    text = str(params.get("text") or "").strip()
    title = str(params.get("title") or "").strip()
    sev = str(params.get("severity") or "").strip().lower()
    link = str(params.get("link") or "").strip()
    if not text and not title:
        raise RuntimeError("chatops: provide at least `text` or `title`.")

    fields: List[Dict[str, Any]] = []
    if sev:
        fields.append({"title": "Severity", "value": sev.capitalize(), "short": True})

    emoji = _EMOJI.get(sev, ":satellite_antenna:")
    header = f"{emoji} {title}" if title else f"{emoji} XORCISM alert"
    attachment: Dict[str, Any] = {
        "color": _COLOR.get(sev, "#475569"),
        "title": header,
        "text": text or title,
        "fields": fields,
        "footer": "XORCISM",
        "mrkdwn_in": ["text", "pretext"],
    }
    if link:
        attachment["title_link"] = link

    payload: Dict[str, Any] = {
        "username": str(params.get("username") or "XORCISM"),
        "text": (f"*{title}*" if title else "XORCISM notification"),
        "attachments": [attachment],
    }
    if params.get("channel"):
        payload["channel"] = str(params["channel"])
    return payload


def _post(webhook: str, payload: Dict[str, Any]) -> int:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (operator-supplied URL)
        resp.read()
        return 200 <= resp.status < 300


def run(params: Dict[str, Any], workdir: str) -> Dict[str, Any]:  # noqa: ARG001
    payload = _build_payload(params)
    webhook = (str(params.get("webhook") or "").strip()
               or os.environ.get("SLACK_WEBHOOK_URL", "").strip()
               or os.environ.get("MATTERMOST_WEBHOOK_URL", "").strip()
               or os.environ.get("CHATOPS_WEBHOOK_URL", "").strip())
    target = "Mattermost" if (os.environ.get("MATTERMOST_WEBHOOK_URL") and not os.environ.get("SLACK_WEBHOOK_URL")) else "Slack"
    dry = str(params.get("dry_run") or "").lower() in ("1", "true", "yes") or not webhook

    if dry:
        return {"source": target, "notify": 0, "dry_run": True, "payload": payload}
    ok = _post(webhook, payload)
    return {"source": target, "notify": 1 if ok else 0, "channel": payload.get("channel")}


if __name__ == "__main__":
    import tempfile
    print(json.dumps(run({"title": "Ransomware note on SRV-FS-02", "text": "Mass .lockbit rename across 3 shares.",
                          "severity": "critical", "link": "https://xorcism.local/?db=XINCIDENT&table=ALERT",
                          "dry_run": True}, tempfile.mkdtemp()), indent=2))
