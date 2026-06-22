# CTI storage — lossless STIX retention, full-text search & object storage

XORCISM normalizes CTI into relational tables (great for the cross-domain joins the platform lives
on) but a relational schema is **lossy** for STIX/IOC data and a poor home for **large files**. This
document explains the storage layer added to fix both — *without* bolting on a separate document
database — and how to point the object store at **S3/MinIO**.

## The problem

| Symptom | Why |
|---|---|
| STIX round-trips lose data | STIX 2.1 objects are heterogeneous, extensible JSON. Normalizing into columns drops any property/extension you didn't model; bundles are *reconstructed* on export. |
| Semi-structured fields get crammed into `TEXT` | e.g. `INTELEXCHANGE.AttackTags`, `OBSERVABLE.Labels` — multi-valued data flattened to comma strings. |
| Large blobs bloat the DB | Multi-MB STIX bundles / PCAPs / malware samples sitting in row `BLOB` columns slow every query that doesn't need the bytes and inflate backups. |

## The design — "store the original, index what you query"

Keep the relational model for entities and relationships (joins are a feature), and add two layers
beside it:

1. **Lossless retention + search** — keep the *original* STIX object verbatim, and index it for
   full-text search. The normalized columns remain the query/join surface; the raw object is the
   source of truth for export and for anything unmodeled.
2. **Content-addressed object storage** — large files live outside row storage, addressed by their
   SHA-256; the DB row holds only a **hash pointer**.

This is the conclusion of the *"do we need a document database (AWS DocumentDB / MongoDB)?"*
evaluation: **no** — a separate document store would break the embedded single-stack deploy and the
cheap cross-DB joins. SQLite **JSON1 + FTS5** covers it today; the same columns become **JSONB + GIN**
(or `pg_documentdb`) when the Node layer reaches the Postgres backend — see
[docs/DATABASE_BACKENDS.md](DATABASE_BACKENDS.md).

---

## Layer 1 — lossless STIX/IOC store + FTS

`server/stixstore.ts`, schema in `ensureStixObjectStore()` (XTHREAT).

- **`STIXOBJECT`** — the central store, keyed by `StixID`: `RawJson` (the full original object),
  `StixType`, `SpecVersion`, `Name`, `Source`, `TenantID`.
- **`RawJson` columns** on `OBSERVABLE` / `IOC` / `INTELEXCHANGE` — inline retention on the source row
  (mirrored from the store, populated even when the row's `StixID` is `NULL`).
- **`STIXOBJECT_FTS`** — an FTS5 index over `name` / `value` / the whole payload, so an IOC value or
  any nested field is searchable. The query builder is IOC-aware: punctuation-bearing input
  (IP / domain / hash / URL) becomes a phrase match, words become prefix matches.

**How objects get in:**

| Path | Mechanism |
|---|---|
| Malware scanner | `malscan.ts` calls `syncObservableById()` right after creating an `OBSERVABLE` (live). |
| CTI connectors (Python) | `runner.py import_threat_intel` writes the original normalized item to `INTELEXCHANGE.RawJson`. |
| Forms / any writer | A boot + **10-minute reconciler** (`startStixStoreSync`, `XOR_STIX_SYNC=0` to disable) sweeps `OBSERVABLE` / `IOC` / `INTELEXCHANGE` into the store incrementally. |
| External STIX | `POST /api/stix/ingest` stores a bundle/object losslessly (and offloads the raw bundle to the object store — see Layer 2). |
| Pre-existing rows | `POST /api/stix/backfill` reconstructs `STIXOBJECT` from existing rows (`Source='reconstructed'`). |

**API** (session auth; read = `XTHREAT.OBSERVABLE`, write = update):

```
GET  /api/stix/object/:stixId     # the original STIX object (lossless)
GET  /api/stix/search?q=&limit=   # full-text search (IOC-aware) → [{stixId,type,name,snippet}]
GET  /api/stix/stats              # store size by source + FTS availability
POST /api/stix/ingest             # store a bundle/object losslessly (body = STIX JSON)
POST /api/stix/backfill           # (re)build STIXOBJECT from existing rows
```

---

## Layer 2 — content-addressed object store

`server/blobstore.ts`, registry in `ensureBlobStore()` (XORCISM).

- Bytes are stored **once per unique content**, addressed by SHA-256 and sharded `ab/cd/<sha256>`.
- **`FILEBLOB`** registry: `Sha256` (unique), `Size`, `ContentType`, `OriginalName`, `RefCount`,
  `Pinned`, `StoragePath`.
- A DB row references a blob by its **`BlobSha256` hash pointer** instead of an in-row `BLOB`.

**API** (read = `XORCISM.DOCUMENT`):

```
POST /api/blob                    # upload {filename,contentType,dataBase64} → {sha256,size,dedup}  (pinned)
GET  /api/blob/:sha256            # stream the bytes (ETag = sha256)
GET  /api/blob/stats              # {blobs,totalBytes,pinned,backend,dir}
POST /api/blob/migrate            # offload in-row BLOBs → store         (superadmin)
POST /api/blob/gc                 # mark-and-sweep reclaim               (superadmin, dryRun default)
```

In the explorer form, any **`BlobSha256`** column renders a file-upload widget that pushes to
`/api/blob` and keeps the returned hash.

### Migrating existing in-row BLOBs

`POST /api/blob/migrate` moves `OVALDEFINITION.BLOB` and `DOCUMENT.BLOB` into the store and records
the `BlobSha256` pointer. **Non-destructive by default**; `{ "reclaim": true }` nulls the in-row BLOB
**only after** the stored copy reads back byte-identical. The read paths (`/oval-xml`, the malware-scan
document read) are CAS-aware — they serve from the store when a pointer is set, else the in-row BLOB.

### Lifecycle / garbage collection

`POST /api/blob/gc` is **mark-and-sweep**: a blob is *referenced* if a `BlobSha256` column still names
it. **Pinned** blobs (uploads + ingested STIX bundles) and referenced blobs always survive; everything
else older than a grace window (default 24 h, protecting freshly-uploaded-not-yet-wired blobs) is
reclaimed. `dryRun` (the default) reports without deleting.

---

## Object-store backend — filesystem or S3/MinIO

The byte storage is swappable behind the same hash-pointer interface; only the bytes move.

| `XORCISM_BLOB_BACKEND` | Storage |
|---|---|
| *(unset)* / `fs` | Local filesystem under `XORCISM_BLOB_DIR` (default `DB_DIR/blobstore`). |
| `s3` | S3 / MinIO (any S3-compatible endpoint), path-style `endpoint/bucket/ab/cd/<sha256>`. |

The S3 backend uses **`curl`'s built-in SigV4 signer** (`--aws-sigv4`) — **no `aws-sdk` dependency**,
and it stays synchronous like the rest of the data layer. `curl` (7.75+) must be on `PATH`.

```bash
export XORCISM_BLOB_BACKEND=s3
export XORCISM_S3_ENDPOINT=https://s3.eu-central-1.amazonaws.com   # or http://minio:9000
export XORCISM_S3_BUCKET=xorcism-blobs
export XORCISM_S3_REGION=eu-central-1                              # any region for MinIO
export XORCISM_S3_ACCESS_KEY=•••
export XORCISM_S3_SECRET_KEY=•••
```

The `FILEBLOB` registry, dedup, pinning and GC are backend-independent (`StoragePath` records the
object URL for `s3`). Migrating between backends is a re-`putBlob` of each blob's bytes.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `XOR_STIX_SYNC` | `1` | `0` disables the boot/10-min STIX-store reconciler. |
| `XORCISM_BLOB_BACKEND` | `fs` | `fs` or `s3`. |
| `XORCISM_BLOB_DIR` | `DB_DIR/blobstore` | Local store directory (fs backend). |
| `XORCISM_S3_ENDPOINT` / `_BUCKET` / `_REGION` / `_ACCESS_KEY` / `_SECRET_KEY` | — | S3/MinIO connection (s3 backend). |

## Current state & next steps

- ✅ Lossless STIX/IOC retention + FTS5 search; live capture + reconciler; ingest/backfill.
- ✅ Content-addressed object store (fs + S3/MinIO), dedup, pinning, mark-and-sweep GC, BLOB migration,
  upload UI.
- ⏳ A live MinIO smoke test of the S3 backend; scheduling GC; promoting the `RawJson` columns to
  **JSONB + GIN** (or `pg_documentdb`) once the Node layer reaches the Postgres backend
  ([docs/DATABASE_BACKENDS.md](DATABASE_BACKENDS.md), *Stage 2*).
