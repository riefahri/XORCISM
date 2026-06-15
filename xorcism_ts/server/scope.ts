/**
 * scope.ts — Verifies that a target is within an engagement's scope (ROE).
 * First-line check (the Python runner re-validates authoritatively).
 * Handles plain IPv4 / CIDR / range a.b.c.d-e.f.g.h, and host/domain names
 * (equality or sub-domain). IPv6 → string equality.
 */

function ipv4ToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

// Returns [start, end] (IPv4 integers) for ip / cidr / range, otherwise null.
function ipv4Range(s: string): [number, number] | null {
  s = s.trim();
  if (s.includes("/")) {
    const [ip, bitsS] = s.split("/");
    const base = ipv4ToInt(ip);
    const bits = Number(bitsS);
    if (base == null || !(bits >= 0 && bits <= 32)) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const start = (base & mask) >>> 0;
    const end = (start + (2 ** (32 - bits) - 1)) >>> 0;
    return [start, end];
  }
  if (s.includes("-")) {
    const [a, b] = s.split("-");
    const sa = ipv4ToInt(a.trim());
    const sb = ipv4ToInt(b.trim());
    if (sa == null || sb == null) return null;
    return sa <= sb ? [sa, sb] : [sb, sa];
  }
  const one = ipv4ToInt(s);
  return one == null ? null : [one, one];
}

function isHost(s: string): boolean {
  return /^[A-Za-z0-9.\-]+$/.test(s) && !/^\d+\.\d+\.\d+\.\d+$/.test(s);
}

function matchEntry(target: string, entry: string): boolean {
  if (target === entry) return true;
  const t = ipv4Range(target);
  const e = ipv4Range(entry);
  if (t && e) return t[0] >= e[0] && t[1] <= e[1]; // target ⊆ entry
  if (isHost(target) && isHost(entry)) {
    return target === entry || target.endsWith("." + entry); // sub-domain
  }
  return false;
}

/** Is the target covered by at least one scope entry? */
export function targetInScope(target: string, scope: string[]): boolean {
  if (!target) return false;
  return scope.some((e) => e && matchEntry(target.trim(), String(e).trim()));
}
