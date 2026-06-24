# Zero Trust posture push (ZTNA / IdP enforcement plane)

Outbound (action) connector. Ships the XORCISM **device-trust feed** to your enforcement plane so
access decisions can gate on the XORCISM-computed device trust — making XORCISM part of the Zero
Trust decision loop (NIST SP 800-207) without being the enforcement point itself.

## The feed

XORCISM computes a per-device trust score (`100 − asset risk`) from the asset inventory
(vulnerabilities, KEV, exposure, backup, ownership…). Export it:

```
GET /api/zero-trust/device-trust            # threshold 60 by default
GET /api/zero-trust/device-trust?minTrust=70
```

```json
{
  "source": "XORCISM Zero Trust", "schema": "device-trust/1", "threshold": 60,
  "count": 21, "compliant": 17, "nonCompliant": 4,
  "devices": [
    { "hostname": "prod-web-ec2", "trust": 12, "tier": "Untrusted", "compliant": false,
      "reasons": ["actively-exploited (KEV) vulnerability", "Internet-facing crown jewel"] }
  ]
}
```

A ZTNA/IdP can **poll that endpoint** directly (Cloudflare Access / Zscaler device posture, Okta
device trust, Entra Conditional Access). This connector is the **push** alternative.

## Usage

```bash
# 1) export the feed
curl -s "$XORCISM/api/zero-trust/device-trust?minTrust=60" -o devices.json
# 2) push the non-compliant devices to your enforcement plane (dry-run shown)
python connectors/runner.py --connector zt-posture-push --param file=devices.json --param format=cloudflare --param dry_run=true
```

| Param | Meaning |
|---|---|
| `webhook` | Your enforcement-plane posture endpoint (or env `ZT_POSTURE_WEBHOOK`) |
| `token` | Bearer/API token (or env `ZT_POSTURE_TOKEN`) |
| `format` | `generic` (default) `cloudflare` `zscaler` `okta` `entra` — shapes per-device field names |
| `file` / `feed` | The exported JSON (path or inline). A demo feed is used if omitted. |
| `min_trust` | Only push devices below this trust (the non-compliant set); `0` = all |
| `dry_run` | Build the payload but do not send |

**Safe by default:** with no webhook, or `dry_run=true`, it returns the built payload **without
sending**. The exact endpoint and schema are vendor-specific — point `webhook` at your posture API
and pick the closest `format`. Stdlib only; secrets via env; never reads or writes the database.
