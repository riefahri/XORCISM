/**
 * webhook.ts — outbound webhooks. On platform events (incident.created, …) the
 * registered URLs receive a signed JSON POST. Fire-and-forget, timeout-bounded.
 *
 * Security: payloads are signed with HMAC-SHA256 of the per-hook secret
 * (`X-XORCISM-Signature: sha256=…`). URLs are SSRF-guarded — only public http/https
 * hosts (no localhost / private / link-local / cloud-metadata ranges).
 */
import crypto from "crypto";
import * as xid from "./xid";

export const WEBHOOK_EVENTS = ["incident.created", "incident.updated", "asset.updated"] as const;

export function generateWebhookSecret(): string {
  return "whsec_" + crypto.randomBytes(24).toString("base64url");
}

/** SSRF guard: only public http/https hosts. Blocks localhost + private/loopback/link-local literals.
 *  Set WEBHOOK_ALLOW_LOOPBACK=1 to permit loopback targets (dev/testing only — default deny). */
export function isSafeWebhookUrl(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  let host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = host.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i); // IPv4-mapped IPv6
  if (mapped) host = mapped[1];
  const loopback = host === "localhost" || /^127\./.test(host) || host === "::1";
  if (loopback) return process.env.WEBHOOK_ALLOW_LOOPBACK === "1"; // dev/test escape hatch
  if (host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) return false;
  // IPv4 literal ranges
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((x) => x > 255)) return false;
    if (o[0] === 127 || o[0] === 10 || o[0] === 0) return false;            // loopback / private / this-host
    if (o[0] === 169 && o[1] === 254) return false;                          // link-local (incl. 169.254.169.254 metadata)
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;              // private
    if (o[0] === 192 && o[1] === 168) return false;                          // private
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false;            // CGNAT
  }
  // IPv6 literal: block loopback / ULA / link-local
  if (host.includes(":")) {
    const h = host.replace(/[[\]]/g, "");
    if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return false;
  }
  return true;
}

async function send(url: string, secret: string, event: string, body: string): Promise<number> {
  const sig = "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "XORCISM-Webhook/1.0",
        "X-XORCISM-Event": event,
        "X-XORCISM-Signature": sig,
      },
      body,
      signal: AbortSignal.timeout(8000),
    });
    return res.status;
  } catch {
    return 0; // network error / timeout / blocked
  }
}

function envelope(event: string, payload: unknown): string {
  return JSON.stringify({ event, sentAt: new Date().toISOString(), data: payload });
}

/** Dispatch an event to every subscribed, tenant-matching webhook (async, non-blocking). */
export function dispatchWebhook(event: string, payload: unknown, tenant: number | null): void {
  let hooks: (xid.WebhookRow & { Secret: string })[];
  try { hooks = xid.webhooksForEvent(event, tenant); } catch { return; }
  if (!hooks.length) return;
  const body = envelope(event, payload);
  for (const h of hooks) {
    if (!isSafeWebhookUrl(h.Url)) { try { xid.recordWebhookDelivery(h.WebhookID, 0); } catch { /* */ } continue; }
    void send(h.Url, h.Secret, event, body).then((status) => {
      try { xid.recordWebhookDelivery(h.WebhookID, status); } catch { /* */ }
    });
  }
}

/** Send a one-off test delivery to a single hook; returns the HTTP status (0 = blocked/error). */
export async function testWebhook(url: string, secret: string): Promise<number> {
  if (!isSafeWebhookUrl(url)) return 0;
  return send(url, secret, "test.ping", envelope("test.ping", { message: "XORCISM webhook test" }));
}
