-- ============================================================================
-- XAGENT_sqlite.sql — canonical SQLite schema for the XAGENT database.
--
-- XAGENT is a SQLite-native XORCISM database (no SQL Server source model): its tables are
-- created at runtime by the server's ensure*() functions. This script is generated from the
-- live schema so a fresh XAGENT.db can be provisioned identically (the server's ensure*()
-- functions still run at boot and reconcile idempotently). Reference data is seeded at boot.
-- Generated 2026-06-29 from the live schema. Schema only (no data).
-- ============================================================================

BEGIN TRANSACTION;

-- Tables (14)
CREATE TABLE IF NOT EXISTS XAGENT( AgentID INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL, asset_name TEXT, os TEXT, platform TEXT, version TEXT, ip TEXT, fqdn TEXT, status TEXT DEFAULT 'enrolled', enrolled_at TEXT, last_seen TEXT, intel_seen INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS XAGENTEVENT( EventID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT, type TEXT, severity TEXT, title TEXT, detail TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS XAGENTJOB( AgentJobID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, kind TEXT NOT NULL, params TEXT, status TEXT DEFAULT 'pending', created_at TEXT, started_at TEXT, finished_at TEXT, result_summary TEXT, created_by INTEGER);
CREATE TABLE IF NOT EXISTS XIOC( IOCID INTEGER PRIMARY KEY AUTOINCREMENT, ioc_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT, threat TEXT, created_at TEXT, UNIQUE(ioc_type, value));
CREATE TABLE IF NOT EXISTS FORENSICTRIAGE( TriageID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT, asset_name TEXT, host_os TEXT, collected_at TEXT, summary TEXT, artifacts TEXT, flag_count INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS HONEYPOTHIT( HitID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, src_ip TEXT, src_port INTEGER, dst_port INTEGER, service TEXT, banner TEXT, hit_at TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS MEMORYDUMP( DumpID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, asset_name TEXT, host_os TEXT, tool TEXT, status TEXT, path TEXT, size_bytes INTEGER, sha256 TEXT, ram_total_bytes INTEGER, started_at TEXT, finished_at TEXT, duration_sec INTEGER, error TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS LOGHUNT( LogHuntID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, asset_name TEXT, host_os TEXT, source TEXT, event_count INTEGER, severity TEXT, summary TEXT, findings TEXT, techniques TEXT, model TEXT, ai_used INTEGER DEFAULT 0, hunt_id INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS ENDPOINTQUESTION ( QuestionID INTEGER PRIMARY KEY, QuestionGUID TEXT, SensorID TEXT, SensorName TEXT, Text TEXT, Filter TEXT, AskedByUserID INTEGER, AskedByName TEXT, TargetCount INTEGER, Status TEXT, AskedAt TEXT, TenantID INTEGER);
CREATE TABLE IF NOT EXISTS ENDPOINTANSWER ( AnswerID INTEGER PRIMARY KEY, QuestionID INTEGER, Agent TEXT, Value TEXT, CreatedAt TEXT);
CREATE TABLE IF NOT EXISTS XSEQ (SeqName TEXT PRIMARY KEY, Val INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS AIAGENT( AiAgentID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, host TEXT, host_os TEXT, name TEXT, framework TEXT, model TEXT, endpoint TEXT, pid INTEGER, uses_tools INTEGER, autonomous INTEGER, has_memory INTEGER, external_data INTEGER, guardrail_tools TEXT, secrets_exposed INTEGER, mcp_servers INTEGER, logging INTEGER, sandboxed INTEGER, model_pinned INTEGER, score INTEGER, coverage INTEGER, gaps TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS AIGUARDRAILRESULT( ResultID INTEGER PRIMARY KEY AUTOINCREMENT, ai_agent_id INTEGER, agent TEXT, name TEXT, control_id TEXT, status TEXT, evidence TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS AIGUARDRAILVIOLATION( ViolationID INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT, host TEXT, ai_agent TEXT, technique TEXT, name TEXT, severity TEXT, evidence TEXT, source TEXT, ai_used INTEGER DEFAULT 0, hunt_id INTEGER, created_at TEXT);

-- Indexes (11)
CREATE INDEX IF NOT EXISTS ix_agentevent_agent ON XAGENTEVENT(agent);
CREATE INDEX IF NOT EXISTS ix_agentjob_agent ON XAGENTJOB(agent, status);
CREATE INDEX IF NOT EXISTS ix_forensictriage_agent ON FORENSICTRIAGE(agent);
CREATE INDEX IF NOT EXISTS ix_honeypothit_agent ON HONEYPOTHIT(agent, HitID);
CREATE INDEX IF NOT EXISTS ix_memorydump_agent ON MEMORYDUMP(agent, DumpID);
CREATE INDEX IF NOT EXISTS ix_loghunt_agent ON LOGHUNT(agent, LogHuntID);
CREATE INDEX IF NOT EXISTS ix_epanswer_q ON ENDPOINTANSWER(QuestionID);
CREATE INDEX IF NOT EXISTS ix_epquestion_tenant ON ENDPOINTQUESTION(TenantID);
CREATE INDEX IF NOT EXISTS ix_aiagent_agent ON AIAGENT(agent, AiAgentID);
CREATE INDEX IF NOT EXISTS ix_aigrresult_agent ON AIGUARDRAILRESULT(ai_agent_id);
CREATE INDEX IF NOT EXISTS ix_aigrviol_agent ON AIGUARDRAILVIOLATION(agent, ViolationID);

COMMIT;
