/**
 * logging.ts — prefixes every tagged server log line with a local date+time.
 *
 * Imported FIRST in index.ts so the patch is installed before any other module logs. Only lines whose
 * first argument is a string starting with "[" (the codebase's "[tag] message" convention, e.g.
 * [monitor] / [feeds] / [cvematch] / [scheduler] / [db] / [seed] / [riskscore] / [orchestrator]) are
 * timestamped — the ASCII startup banner, blank lines and the multi-line credential box are left as-is.
 *
 * Format: `[YYYY-MM-DD HH:MM:SS] [tag] message…` in local time. Set XOR_LOG_UTC=1 for UTC instead.
 */
const c = console as unknown as { __xorTimestamped?: boolean };

function ts(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  if (process.env.XOR_LOG_UTC === "1") {
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
      `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`;
  }
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

if (!c.__xorTimestamped) {
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    const orig = console[method].bind(console);
    console[method] = (...args: unknown[]): void => {
      if (typeof args[0] === "string" && args[0].startsWith("[")) orig(`[${ts()}]`, ...args);
      else orig(...args);
    };
  }
  c.__xorTimestamped = true;
}

export {};
