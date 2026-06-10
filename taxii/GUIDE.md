# TAXII 2.1 Server & Python Client — User Guide

A simple, step-by-step guide to running the TAXII 2.1 server and using the
Python client to share cyber threat intelligence (STIX 2.1).

Based on the OASIS specifications:
- TAXII 2.1: <https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html>
- STIX 2.1: <https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html>

---

## 1. What is this, in one minute?

- **STIX** is the *format* for threat intelligence (indicators, malware, threat
  actors, vulnerabilities, relationships…). Each item is a JSON object with a
  `type` and an `id`.
- **TAXII** is the *transport*: a small REST API to **publish** and **fetch**
  those STIX objects, grouped into **collections**.
- This project gives you three tools:
  1. `taxii_server.py` — the TAXII server,
  2. `taxii_client.py` — a command-line client,
  3. `manager.py` — a web console to start/stop/monitor the server.

You do not need to understand STIX deeply to follow this guide.

---

## 2. Install (once)

You need Python 3 and two packages:

```bash
pip install flask requests
```

All commands below are run from the `taxii/` folder:

```bash
cd taxii
```

---

## 3. Start the server (step by step)

```bash
python taxii_server.py
```

You should see:

```
  TAXII 2.1 server -> http://127.0.0.1:5000/taxii2/   (auth=off, store=sqlite:...\taxii.db)
```

The server is now running on **port 5000** with two demo collections.
Leave it running and open a **second terminal** for the client.

> Stop the server anytime with `Ctrl+C`.

### Quick check (browser or curl)

Open <http://127.0.0.1:5000/taxii2/> in a browser, or:

```bash
curl -H "Accept: application/taxii+json;version=2.1" http://127.0.0.1:5000/taxii2/
```

The `Accept` header is **required** by TAXII — every request must ask for
`application/taxii+json;version=2.1`. The client below sets it for you.

---

## 4. The 5 ideas you need

| Term | What it is | Endpoint |
|------|-----------|----------|
| **Discovery** | Server info + where the API lives | `/taxii2/` |
| **API Root** | A grouping of collections (here: `api1`) | `/api1/` |
| **Collection** | A named bucket of STIX objects | `/api1/collections/{id}/` |
| **Objects** | The STIX content (returned in an *envelope*) | `/api1/collections/{id}/objects/` |
| **Manifest** | A lightweight index (ids + dates, no content) | `/api1/collections/{id}/manifest/` |

The client hides these URLs behind simple commands.

---

## 5. Use the client (the easy way)

Every client command starts with the server URL. Tip: save it in a variable.

```bash
U=http://127.0.0.1:5000
```

### Step 5.1 — Discover the server

```bash
python taxii_client.py --url $U discovery
```

### Step 5.2 — List collections

```bash
python taxii_client.py --url $U collections
```

Example output:

```
  52892447-4d7e-4f70-b94d-d7f22742ff63  Sandbox (writable)      (read=True write=True)
  91a7b528-80eb-42ed-a74d-c6fbd5a26116  High-Value Indicators   (read=True write=False)
```

Copy a collection **id** — you will use it in the next steps. Save it:

```bash
C=91a7b528-80eb-42ed-a74d-c6fbd5a26116    # the read-only demo collection
```

### Step 5.3 — Read the objects in a collection

```bash
python taxii_client.py --url $U get --collection $C
```

You get a JSON envelope with a `count` and an `objects` list.

### Step 5.4 — Filter what you read

Filters are simple flags. You can combine them.

```bash
# Only indicators and malware
python taxii_client.py --url $U get --collection $C --type indicator,malware

# A specific object by its STIX id
python taxii_client.py --url $U get --collection $C --id malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c

# Only objects added after a date
python taxii_client.py --url $U get --collection $C --added-after 2024-01-01T00:00:00Z
```

### Step 5.5 — Object versions (STIX objects can change over time)

By default you get the **latest** version of each object. To see all versions:

```bash
python taxii_client.py --url $U get --collection $C --type indicator --version all
```

`--version` accepts: `last` (default), `first`, `all`, or an exact timestamp.

List the versions of one object:

```bash
python taxii_client.py --url $U versions --collection $C \
  --object indicator--cd981c25-8042-4166-8945-51178443bdac
```

### Step 5.6 — Save what you fetched to a file

```bash
python taxii_client.py --url $U get --collection $C --all -o my_intel.json
```

`--all` follows pagination automatically (fetches every page). The result is a
valid STIX **bundle** you can re-import later.

---

## 6. Publish STIX (add objects)

You can only add to a collection where `write=True` (the demo `Sandbox`).

### Step 6.1 — Pick the writable collection

```bash
W=52892447-4d7e-4f70-b94d-d7f22742ff63
```

### Step 6.2 — Add a ready-made example bundle

The `../stix/` folder contains valid STIX 2.1 example files.

```bash
python taxii_client.py --url $U add --collection $W \
  --file ../stix/bundle-threat-report.json --poll
```

Example output:

```
  envoyes=11  status=complete  success=11  fail=0  id=7c7a651e-...
```

`--poll` also prints the **Status** resource (TAXII's receipt for an upload).

### Step 6.3 — Read it back

```bash
python taxii_client.py --url $U get --collection $W --type threat-actor,malware
```

### Step 6.4 — Delete an object (writable collections only)

```bash
python taxii_client.py --url $U delete --collection $W \
  --object identity--7f8d2b1a-4c3e-4a6b-9f0d-2e1c3b4a5d6e
```

---

## 7. The manifest (a fast index)

When you only need *what is there* (ids, dates, versions) without downloading
the full content:

```bash
python taxii_client.py --url $U manifest --collection $C
```

---

## 8. Turning on authentication

Start the server requiring an HTTP Basic login:

```bash
TAXII_AUTH=1 TAXII_PASSWORD=s3cret python taxii_server.py
```

Then pass credentials to the client:

```bash
python taxii_client.py --url $U --user admin --password s3cret collections
```

(User is `admin`; the password is whatever you set in `TAXII_PASSWORD`,
default `taxii`.)

---

## 9. The web management console (no terminal needed)

```bash
python manager.py        # then open http://127.0.0.1:5050
```

In the browser you can:
- set the **host / port / backend / database / auth**,
- click **▶ Start** / **■ Stop**,
- watch **statistics** (collections, object counts, types),
- read the **logs** live.

This is the easiest way to run and watch the server.

---

## 10. Expose real project data as STIX (advanced)

Instead of the demo data, the server can publish the project's own databases
(vulnerabilities and incidents), **read-only**, as STIX:

```bash
TAXII_BACKEND=project python taxii_server.py
```

Two collections appear: *XORCISM Vulnerabilities (STIX)* and *XORCISM Incidents
(STIX)*. Fetch them exactly like any other collection:

```bash
python taxii_client.py --url $U collections
python taxii_client.py --url $U get --collection <vuln-collection-id> --limit 5
```

(`TAXII_PROJECT_MAX` caps how many rows are exposed; default 1000.)

---

## 11. Server options (cheat sheet)

| Variable | Default | Meaning |
|----------|---------|---------|
| `TAXII_HOST` | `127.0.0.1` | Bind address |
| `TAXII_PORT` | `5000` | Port |
| `TAXII_BACKEND` | `sqlite` | `sqlite` (persistent), `memory`, or `project` |
| `TAXII_DB` | `…/taxii.db` | SQLite file (sqlite backend) |
| `TAXII_AUTH` | `0` | `1` = require HTTP Basic |
| `TAXII_PASSWORD` | `taxii` | Basic password for user `admin` |
| `TAXII_PROJECT_MAX` | `1000` | Row cap for the `project` backend |

---

## 12. Troubleshooting

- **`406 Not Acceptable`** — you forgot the `Accept` header. Use the client, or
  add `-H "Accept: application/taxii+json;version=2.1"` to curl.
- **`415` on upload** — set `-H "Content-Type: application/taxii+json;version=2.1"`
  (the client does this for you).
- **`403` when adding/deleting** — the collection is read-only (`write=False`).
- **`curl` errors on `match[...]`** — curl treats `[` `]` as globbing; add `-g`,
  e.g. `curl -g "...?match[type]=indicator"`. The Python client is unaffected.
- **Nothing returned but `more: true`** — that is valid TAXII; ask for the next
  page (the client's `--all` does this automatically).

---

## 13. One-minute end-to-end example

```bash
cd taxii
pip install flask requests

# Terminal A — start the server
python taxii_server.py

# Terminal B — talk to it
U=http://127.0.0.1:5000
python taxii_client.py --url $U collections
W=52892447-4d7e-4f70-b94d-d7f22742ff63
python taxii_client.py --url $U add --collection $W --file ../stix/bundle-threat-report.json --poll
python taxii_client.py --url $U get --collection $W --type indicator --all -o out.json
```

You have now published and retrieved threat intelligence over TAXII 2.1. 🎉
