-- ============================================================================
-- XJOB_sqlite.sql — canonical SQLite schema for the XJOB database.
--
-- XJOB is a SQLite-native XORCISM database (no SQL Server source model): its tables are
-- created at runtime by the server's ensure*() functions. This script is generated from the
-- live schema so a fresh XJOB.db can be provisioned identically (the server's ensure*()
-- functions still run at boot and reconcile idempotently). Reference data is seeded at boot.
-- Generated 2026-06-29 from the live schema. Schema only (no data).
-- ============================================================================

BEGIN TRANSACTION;

-- Tables (4)
CREATE TABLE IF NOT EXISTS XJOB( JobID INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT NOT NULL, params TEXT, target TEXT, engagement_id INTEGER, status TEXT NOT NULL DEFAULT 'queued', user_id INTEGER, created_at TEXT, started_at TEXT, finished_at TEXT, exit_code INTEGER, log TEXT, result_summary TEXT, error TEXT, worker TEXT, result_json TEXT);
CREATE TABLE IF NOT EXISTS XENGAGEMENT( EngagementID INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, scope TEXT, active INTEGER DEFAULT 1, roe TEXT, created_at TEXT, created_by INTEGER);
CREATE TABLE IF NOT EXISTS XWORKER( WorkerID INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, kind TEXT DEFAULT 'remote', capabilities TEXT, status TEXT DEFAULT 'idle', last_seen TEXT, created_at TEXT, created_by INTEGER);
CREATE TABLE IF NOT EXISTS XSCHEDULE( ScheduleID INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT NOT NULL, params TEXT, target TEXT, engagement_id INTEGER, worker TEXT, cron TEXT NOT NULL, enabled INTEGER DEFAULT 1, created_at TEXT, created_by INTEGER, last_run_at TEXT, last_job_id INTEGER, run_count INTEGER DEFAULT 0);

COMMIT;
