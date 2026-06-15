/**
 * scheduler.ts — Loop that fires scheduled tasks (XSCHEDULE).
 * Every ~30 s: for each enabled schedule whose cron matches the current
 * minute (and which has not already run this minute), a job is queued
 * (XJOB), after re-validating the engagement scope. The runner remains the
 * authoritative guard (re-checks the scope before executing).
 */
import {
  listEnabledSchedules, markScheduleRun, createJob, getEngagement, minuteOf, sqlNow,
  Schedule,
} from "./jobs";
import { cronMatches } from "./cron";
import { targetInScope } from "./scope";
import * as xid from "./xid";

function scopeHost(target: string): string {
  try {
    const u = new URL(target);
    return u.hostname || target;
  } catch {
    return target;
  }
}

function fireSchedule(s: Schedule, nowMin: string): void {
  // Anti-duplicate: already fired during this minute?
  if (minuteOf(s.last_run_at) === nowMin) return;

  // Re-validate the scope if the schedule targets something with an engagement.
  if (s.target) {
    if (!s.engagement_id) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : cible sans engagement`);
      return;
    }
    const eng = getEngagement(s.engagement_id);
    if (!eng || !eng.active) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : engagement inactif/introuvable`);
      return;
    }
    let scope: string[] = [];
    try { scope = JSON.parse(eng.scope || "[]"); } catch { scope = []; }
    if (!targetInScope(scopeHost(s.target), scope)) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} ignoré : cible hors périmètre`);
      xid.addAudit({ userId: s.created_by, action: "schedule_out_of_scope", resourceType: "connector",
        resourceKey: s.connector, detail: `schedule=${s.ScheduleID} target=${s.target}` });
      return;
    }
  }

  let params: unknown = {};
  try { params = JSON.parse(s.params || "{}"); } catch { params = {}; }
  const jobId = createJob(s.connector, params, s.target, s.created_by ?? 0, s.engagement_id, s.worker);
  markScheduleRun(s.ScheduleID, jobId, sqlNow());
  xid.addAudit({ userId: s.created_by, action: "schedule_fire", resourceType: "connector",
    resourceKey: s.connector, detail: `schedule=${s.ScheduleID} job=${jobId} cron=${s.cron}` });
  console.log(`[scheduler] schedule ${s.ScheduleID} (${s.connector}) → job ${jobId}`);
}

export function tickSchedules(now = new Date()): void {
  const nowMin = sqlNow().slice(0, 16);
  for (const s of listEnabledSchedules()) {
    try {
      if (cronMatches(s.cron, now)) fireSchedule(s, nowMin);
    } catch (e) {
      console.warn(`[scheduler] schedule ${s.ScheduleID} erreur : ${(e as Error).message}`);
    }
  }
}

let timer: NodeJS.Timeout | null = null;

export function startScheduler(): void {
  if (timer) return;
  // Every 30 s (cron has a one-minute granularity; the anti-duplicate check avoids
  // double firing between two ticks within the same minute).
  timer = setInterval(() => {
    try { tickSchedules(); } catch (e) { console.warn(`[scheduler] tick: ${(e as Error).message}`); }
  }, 30_000);
  if (typeof timer.unref === "function") timer.unref();
  console.log("[scheduler] démarré (tick 30s)");
}
