/**
 * cron.ts — Minimal cron evaluator (5 fields: minute hour day-of-month month day-of-week).
 * Supports "*", lists "a,b", ranges "a-b", steps "* / n" and "a-b/n".
 * Day-of-week: 0–6 (Sunday = 0; 7 also accepted as Sunday).
 * Standard rule: if both day-of-month AND day-of-week are restricted, either one matches.
 */

interface FieldSpec { values: Set<number>; restricted: boolean }

function parseField(expr: string, min: number, max: number): FieldSpec | null {
  const values = new Set<number>();
  let restricted = true;
  for (const part of expr.split(",")) {
    const p = part.trim();
    if (p === "") return null;
    // step: "<range>/<step>"
    let step = 1;
    let rangePart = p;
    if (p.includes("/")) {
      const [r, s] = p.split("/");
      step = Number(s);
      if (!Number.isInteger(step) || step < 1) return null;
      rangePart = r;
    }
    let lo = min;
    let hi = max;
    if (rangePart === "*") {
      restricted = restricted && step !== 1 ? true : restricted && expr === "*" ? false : restricted;
      // "*" is unrestricted unless a step (*/n) — for the DOM/DOW rule we treat "*" as unrestricted
      if (p === "*") restricted = false;
    } else if (rangePart.includes("-")) {
      const [a, b] = rangePart.split("-");
      lo = Number(a); hi = Number(b);
    } else {
      lo = hi = Number(rangePart);
    }
    if (!Number.isInteger(lo) || !Number.isInteger(hi)) return null;
    if (lo < min || hi > max || lo > hi) return null;
    for (let v = lo; v <= hi; v += step) values.add(v);
  }
  return { values, restricted };
}

export function validateCron(expr: string): boolean {
  const f = (expr || "").trim().split(/\s+/);
  if (f.length !== 5) return false;
  const ranges: [number, number][] = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]];
  return f.every((part, i) => parseField(part, ranges[i][0], ranges[i][1]) !== null);
}

/** Does the cron match the minute of `date` (server local time)? */
export function cronMatches(expr: string, date: Date): boolean {
  const f = (expr || "").trim().split(/\s+/);
  if (f.length !== 5) return false;
  const minute = parseField(f[0], 0, 59);
  const hour = parseField(f[1], 0, 23);
  const dom = parseField(f[2], 1, 31);
  const month = parseField(f[3], 1, 12);
  const dowRaw = parseField(f[4], 0, 7);
  if (!minute || !hour || !dom || !month || !dowRaw) return false;

  // Normalize Sunday (7 → 0)
  const dow: FieldSpec = { restricted: dowRaw.restricted, values: new Set([...dowRaw.values].map((v) => (v === 7 ? 0 : v))) };

  if (!minute.values.has(date.getMinutes())) return false;
  if (!hour.values.has(date.getHours())) return false;
  if (!month.values.has(date.getMonth() + 1)) return false;

  const domMatch = dom.values.has(date.getDate());
  const dowMatch = dow.values.has(date.getDay());
  // Cron rule: if both day fields are restricted → OR; otherwise classic AND.
  if (dom.restricted && dow.restricted) return domMatch || dowMatch;
  return domMatch && dowMatch;
}

/** Friendly labels → cron expression (UI presets). */
export function presetToCron(preset: string): string | null {
  switch (preset) {
    case "every15": return "*/15 * * * *";
    case "every30": return "*/30 * * * *";
    case "hourly": return "0 * * * *";
    case "daily": return "0 2 * * *";        // 02:00
    case "weekly": return "0 3 * * 1";       // Monday 03:00
    case "monthly": return "0 4 1 * *";      // 1st at 04:00
    default: return null;
  }
}
