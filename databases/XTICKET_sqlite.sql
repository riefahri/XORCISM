-- ============================================================================
-- XTICKET_sqlite.sql — canonical SQLite schema for the XTICKET database.
--
-- XTICKET is a SQLite-native XORCISM database (no SQL Server source model): its tables are
-- created at runtime by the server's ensure*() functions. This script is generated from the
-- live schema so a fresh XTICKET.db can be provisioned identically (the server's ensure*()
-- functions still run at boot and reconcile idempotently). Reference data is seeded at boot.
-- Generated 2026-06-29 from the live schema. Schema only (no data).
-- ============================================================================

BEGIN TRANSACTION;

-- Tables (4)
CREATE TABLE IF NOT EXISTS TICKET ( TicketID INTEGER PRIMARY KEY, TicketGUID TEXT, TicketNumber TEXT, Subject TEXT, Description TEXT, Status TEXT, Priority TEXT, Severity TEXT, TicketType TEXT, CategoryID INTEGER, RequesterName TEXT, RequesterEmail TEXT, AssigneeName TEXT, Tags TEXT, CreatedDate TEXT, UpdatedDate TEXT, DueDate TEXT, ResolvedDate TEXT, ClosedDate TEXT, Resolution TEXT);
CREATE TABLE IF NOT EXISTS TICKETCOMMENT ( TicketCommentID INTEGER PRIMARY KEY, TicketCommentGUID TEXT, TicketID INTEGER, Author TEXT, Body TEXT, IsInternal INTEGER, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS TICKETCATEGORY ( TicketCategoryID INTEGER PRIMARY KEY, TicketCategoryName TEXT, Description TEXT, CreatedDate TEXT);
CREATE TABLE IF NOT EXISTS TICKETATTACHMENT ( TicketAttachmentID INTEGER PRIMARY KEY, TicketID INTEGER, FileName TEXT, FilePath TEXT, CreatedDate TEXT);

-- Indexes (2)
CREATE INDEX IF NOT EXISTS ix_ticketcomment_ticket ON TICKETCOMMENT(TicketID);
CREATE INDEX IF NOT EXISTS ix_ticketattachment_ticket ON TICKETATTACHMENT(TicketID);

COMMIT;
