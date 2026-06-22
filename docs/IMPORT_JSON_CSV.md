# Importing data into tables — JSON & CSV

XORCISM lets you bulk-load rows into **any** table from a **JSON** or **CSV** file, directly from
the table (explorer) view. This guide explains where to find it, how the file must be shaped, how
column/field names work, and the rules the importer applies.

---

## 1. Where it is

1. Open a table in the explorer (e.g. `?db=XORCISM&table=ASSET`, or pick a table from the landing
   page / the database+table selectors).
2. In the table toolbar, click **⬆ Import JSON/CSV**.
3. Pick a `.json` or `.csv` file. The import runs immediately (after a confirmation dialog).

Next to the button is a **Replace** checkbox (see [§6](#6-replace-mode)).

The importer is **schema-driven**: it reads the table's live columns and accepts any file whose
keys/headers match those columns. There is no per-table configuration — it works the same on every
table, including tables you have just created or altered.

---

## 2. Field names = the table's column names

**The keys in your file must be the table's column names, spelled exactly** (they are
case-sensitive). The importer keeps only the keys that match a real column and silently ignores the
rest. Nothing is guessed or remapped.

The easiest way to get the exact column names is to **export the table first** and use that file as
your template:

- Toolbar **⬇ Export Excel** (or the CSV/JSON export) produces a file whose headers/keys are the
  exact column names. Edit it, then re-import. This **round-trip is the recommended workflow**:
  *export → edit/add rows → import*.

You can also see the columns by opening the "New row" form (every field label corresponds to a
column) or via the public API: `GET /api/columns?db=<DB>&table=<TABLE>`.

> Tip: you do **not** need to provide every column. Omit the primary key (it is auto-assigned),
> omit `TenantID` (it is stamped automatically), and omit anything that has a sensible default. Only
> the columns you include are written.

---

## 3. JSON format

The file may be any of the following shapes:

**a) An array of row objects** (most common):

```json
[
  { "AssetName": "web-prod-01", "AssetType": "Server", "IPAddress": "10.0.0.21", "Criticality": "High" },
  { "AssetName": "db-prod-01",  "AssetType": "Database", "IPAddress": "10.0.0.22", "Criticality": "Critical" }
]
```

**b) An object wrapping the array** under any of these keys: `rows`, `objects`, `data`, `records`,
`items`:

```json
{ "rows": [ { "AssetName": "web-prod-01", "AssetType": "Server" } ] }
```

**c) A single row object** — imported as one row:

```json
{ "AssetName": "web-prod-01", "AssetType": "Server" }
```

Each row is an object of `"ColumnName": value` pairs.

### Value types in JSON

| In your JSON          | Stored as                                                |
|-----------------------|----------------------------------------------------------|
| string                | text                                                     |
| number                | number                                                   |
| `true` / `false`      | `1` / `0` (XORCISM uses integer booleans)                |
| `null`                | `NULL`                                                    |
| array or object       | serialized to **JSON text** (e.g. tag/label columns)     |
| `undefined` / missing | column left to its default                               |

---

## 4. CSV format

- The **first line is the header row** and must contain the column names.
- One row per line; values are comma-separated. **Quote** any value containing a comma, quote or
  newline (standard CSV quoting, e.g. `"Acme, Inc."`). The parser (SheetJS) handles quotes and
  escaping.
- **Empty cells are skipped** (the column keeps its default rather than being written as an empty
  string).
- The file is detected as CSV when it has a `.csv` extension, a CSV MIME type, or its content does
  not start with `[` or `{`.

Example (`ASSET.csv`):

```csv
AssetName,AssetType,IPAddress,Criticality
web-prod-01,Server,10.0.0.21,High
db-prod-01,Database,10.0.0.22,Critical
"lab gateway, dmz",Network,10.0.9.1,Medium
```

> Values import as text/numbers as written. For columns that expect a specific vocabulary
> (e.g. a status or severity), use the exact values the form's dropdown offers.

---

## 5. What the importer does to each row (rules)

Every imported row goes through the **same insert path as the app's "New row" form**, so it behaves
identically:

- **Unknown keys are dropped** — only real columns are written.
- **`rowid` is ignored** (SQLite's internal id; never import it).
- **Primary key**: omit it — it is auto-assigned. (If a table's PK is a natural key you control,
  provide it; otherwise leave it out.)
- **`TenantID`** is stamped automatically from your session — you normally should **not** include it
  (non-admins cannot write another tenant's data).
- **Defaults & timestamps** (e.g. `CreatedDate`, GUIDs) are filled in when omitted.
- **Computed values** are recomputed server-side (e.g. an asset's `RiskScore`, a risk register
  entry's inherent/residual risk level) — don't try to set them by hand.
- **Field-level permissions** apply: any column you are not allowed to write is dropped from your
  row.
- **Encrypted columns** are encrypted on the way in (transparent).

### Permissions

- Importing requires the **Create** right on the target table.
- **Replace** mode additionally requires the **Delete** right (it empties the table first).

---

## 6. Replace mode

Tick **Replace** before importing to **empty the table first**, then load your file — i.e. the file
becomes the new full contents (within your tenant scope). Without it, rows are **appended**.

Replace asks for an extra confirmation and is **not reversible** — export a backup first. It is handy
for re-syncing a reference/lookup table from a source of truth.

---

## 7. After the import

A toast reports the outcome: `inserted/total imported` (and, in replace mode, how many rows were
cleared). If some rows failed, the count is shown and the first few error messages are logged to the
browser console (open DevTools → Console). The grid reloads automatically.

Every import is written to the **audit log** (`import` or `import_replace`, with the row counts).

---

## 8. Quick recipes

**Bulk-add assets** — export `XORCISM.ASSET` to Excel, add rows in the new lines (keep the header),
save as CSV or `.xlsx`→CSV, import. Omit `AssetID` (auto), `TenantID` (auto) and `RiskScore`
(computed).

**Load a reference list** — prepare a CSV with just the columns you have, tick **Replace**, import.

**Migrate from a spreadsheet** — rename your spreadsheet's header cells to the XORCISM column names
(export a sample first to get them), then save as CSV and import.

---

## 9. Troubleshooting

| Symptom                              | Cause / fix                                                                 |
|--------------------------------------|----------------------------------------------------------------------------|
| "0/N imported"                       | None of your keys match real columns — check the header spelling/case (export a template). |
| Some columns are empty after import  | Those headers don't match a column, or the cells were empty (skipped).     |
| "X failed"                           | Constraint/type errors on those rows — see the first errors in the console; fix the values. |
| A value imported as `[object]`/JSON  | You passed an array/object for a plain-text column — pass a string, or use the column that expects JSON (tags/labels). |
| "Replace" greyed out / forbidden     | You lack the Delete right on the table.                                     |
| Can't import at all                  | You lack the Create right on the table.                                     |

---

## 10. For power users — the API

The button calls a public, schema-driven endpoint you can script:

```
POST /api/import
Content-Type: application/json

{
  "db":    "XORCISM",
  "table": "ASSET",
  "rows":  [ { "AssetName": "web-prod-01", "AssetType": "Server" } ],
  "replace": false
}
```

Response: `{ "inserted": 1, "total": 1, "failed": 0, "errors": [], "cleared": 0 }`.

The matching export endpoint is `GET /api/export?db=<DB>&table=<TABLE>` (returns `SELECT *`), so
export→edit→import is fully scriptable. The programmatic REST API (`/api/v1`, API-key auth) is
documented at **/api-docs**.

> Invariant: the importer is intentionally **not** aware of any specific table or column. It is
> driven entirely by the live schema (`PRAGMA table_info`), so it automatically supports new tables,
> new columns, tenant isolation, PK auto-increment, defaults, computed values and encryption with no
> code changes.
