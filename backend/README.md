# FILEGUARD BACKEND

File integrity and tampering detection API for the FileGuard internship project.

The backend accepts a file, computes a SHA-256 fingerprint, stores that fingerprint with a little metadata, and later compares a new upload with the stored fingerprint. The file itself is not kept.

This folder is the API only. It does not contain the frontend.

## Overview

FileGuard answers one question:

**Do the current bytes of this file match the bytes that were registered earlier?**

It does **not** answer:

- who created the file
- who owns the file
- whether the content is true
- whether the file is free of malware

A matching fingerprint means the bytes are unchanged. A different fingerprint means the bytes are not the same as the registered bytes. That is file-integrity verification.

## Architecture

```
backend/
├── app.py              Flask routes, validation, JSON responses
├── database.py         SQLite tables and parameterized queries
├── hash_utils.py       Chunked SHA-256, size labels, type labels
├── config.py           Paths, size limit, host, CORS, debug flag
├── seed_demo.py        Optional demo rows (not run on startup)
├── test_api.py         unittest suite (temporary database)
├── requirements.txt
├── API_CONTRACT.md     Frontend integration contract
├── fileguard.db        Created automatically on first run
└── README.md
```

Request flow:

```
Browser / frontend
        |
        |  multipart/form-data  (field name: file)
        v
Flask route  (app.py)
        |
        |  secure_filename(), size check
        v
hash_utils.hash_stream()     reads 64 KB chunks, never the whole file at once
        |
        v
database.py                   stores metadata + SHA-256 only
        |
        v
JSON response                 upload is discarded
```

There is no uploads folder. `upload.save()` is never called. The bytes are not executed and not parsed as PDF, Office, or image data. Werkzeug may spool a large request into a temporary operating-system file for the duration of the request. That spool is not a stored copy of the file.

## SHA-256 explanation

SHA-256 is a hash function from Python's `hashlib`. It is **not encryption**.

| | Encryption | SHA-256 |
|---|---|---|
| Purpose | Hide data so it can be unlocked later | Fingerprint data |
| Reversible | Yes, with the key | No |
| Output | Ciphertext about as long as the input | Always 64 hex characters (256 bits) |

Properties used by FileGuard:

1. The same bytes always produce the same 64-character hex digest.
2. Changing any part of the file, even one byte, changes the digest.
3. The digest is much smaller than the file, so FileGuard can store the fingerprint without storing the file.

Detection is a comparison:

```
stored SHA-256   vs   SHA-256 of the file being checked now
```

- equal -> `VERIFIED` / integrity `INTACT`
- different -> `TAMPERED` / integrity `COMPROMISED`
- no stored fingerprint for that lookup -> `NOT_REGISTERED` / integrity `UNKNOWN`

`hash_utils.calculate_sha256(file_stream)` updates `hashlib.sha256()` with 64 KB chunks and then rewinds the stream when `seek` is available. The whole file is not loaded into RAM, and no custom cryptography is implemented.

## Database schema

SQLite file: `backend/fileguard.db`. Tables are created on startup if they are missing. The server does not insert sample rows by itself.

### registered_files

| Column | Meaning |
|---|---|
| id | Internal integer primary key. Not sent as the public id. |
| file_id | Public id, for example `FG-A82F91`. Random, unique. |
| filename | Sanitized filename (`werkzeug.utils.secure_filename`). |
| file_type | Uppercase extension label, or `UNKNOWN`. |
| file_size | Size in bytes. |
| sha256_hash | Lowercase SHA-256 hex digest. |
| registered_at | UTC timestamp, `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |

A unique index on `(filename, sha256_hash)` blocks duplicate fingerprints for the same sanitized name.

### verification_history

| Column | Meaning |
|---|---|
| id | Internal integer primary key. |
| verification_id | Public id, for example `VER-82AF31`. |
| file_id | Matching registration, or NULL when nothing was registered. |
| filename | Sanitized name of the file that was uploaded for the check. |
| stored_hash | Registered fingerprint, or NULL. |
| current_hash | Fingerprint of the upload. |
| status | `VERIFIED`, `TAMPERED`, or `NOT_REGISTERED`. |
| verified_at | UTC timestamp. |

`file_id` is **not** a foreign key. Deleting a registration leaves history rows in place so the audit trail remains.

## Duplicate registration behavior

Predictable rules:

1. **Same sanitized filename and same SHA-256.** No new row. The API returns the existing record with `already_registered: true` and HTTP 200.
2. **Same sanitized filename, different SHA-256.** A new File ID is created. This lets a newer version of a file be registered under the same name.
3. **Different filename, same SHA-256.** A separate registration. Lookup for the simple verify endpoint is by filename, not by hash alone.
4. **Verify by filename** (`POST /api/files/verify`) uses the **most recent** registration for that sanitized filename (`registered_at`, then internal id).
5. **Verify by File ID** (`POST /api/files/verify/<file_id>`) compares the upload with that one registration only. The uploaded filename does not have to match. Use this when two registrations share a name.

The comparison itself lives in `perform_verification()`. Both verify routes only choose which row is the baseline, so a future lookup key can be added without rewriting the check.

## API endpoints

Base URL: `http://127.0.0.1:5000`

| Method | URL | Purpose |
|---|---|---|
| GET | `/` | Dashboard UI (HTML) |
| GET | `/api` | API name, version, status (JSON) |
| GET | `/api/health` | Liveness check |
| POST | `/api/files/register` | Fingerprint an upload and store metadata |
| POST | `/api/files/verify` | Compare an upload with the newest registration of the same filename |
| POST | `/api/files/verify/<file_id>` | Compare an upload with one File ID |
| GET | `/api/files` | All registrations, newest first |
| GET | `/api/files/search?q=` | Search filename and file id |
| GET | `/api/files/<file_id>` | One registration plus recent checks |
| DELETE | `/api/files/<file_id>` | Remove a registration, keep history |
| GET | `/api/history` | All checks, optional `status` and `limit` |
| GET | `/api/history/<verification_id>` | One check |
| GET | `/api/dashboard` | Counts and recent activity |

Full request and response bodies, including JavaScript `fetch` examples, are in [API_CONTRACT.md](API_CONTRACT.md).

`VERIFIED`, `TAMPERED`, and `NOT_REGISTERED` are successful API calls. They return HTTP 200 and `"success": true`. The integrity result is the `status` field. HTTP 4xx/5xx means the request itself failed (missing file, unknown id on a GET, file too large, server error).

### Request examples

Register:

```bash
curl -s -X POST http://127.0.0.1:5000/api/files/register \
  -F "file=@sample.txt"
```

Verify by filename:

```bash
curl -s -X POST http://127.0.0.1:5000/api/files/verify \
  -F "file=@sample.txt"
```

Verify by File ID:

```bash
curl -s -X POST http://127.0.0.1:5000/api/files/verify/FG-A82F91 \
  -F "file=@sample.txt"
```

List, search, history, dashboard:

```bash
curl -s http://127.0.0.1:5000/api/files
curl -s "http://127.0.0.1:5000/api/files/search?q=certificate"
curl -s "http://127.0.0.1:5000/api/history?status=TAMPERED&limit=20"
curl -s http://127.0.0.1:5000/api/dashboard
```

### Response examples

New registration (HTTP 201):

```json
{
  "success": true,
  "already_registered": false,
  "message": "File registered successfully",
  "file": {
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf",
    "file_type": "PDF",
    "file_size": 2516582,
    "file_size_formatted": "2.4 MB",
    "sha256_hash": "8d7c0c1e0b5a9f0e6c4a2b1d0e9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f",
    "registered_at": "2026-10-28T18:00:00Z"
  }
}
```

Unchanged file:

```json
{
  "success": true,
  "status": "VERIFIED",
  "integrity": "INTACT",
  "message": "File integrity verified. No modification detected.",
  "verification_id": "VER-82AF31",
  "file": {
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf"
  },
  "stored_hash": "...",
  "current_hash": "...",
  "registered_at": "2026-10-28T18:00:00Z",
  "verified_at": "2026-10-28T18:05:00Z"
}
```

Changed file:

```json
{
  "success": true,
  "status": "TAMPERED",
  "integrity": "COMPROMISED",
  "message": "File fingerprint does not match the registered fingerprint."
}
```

Nothing registered under that filename:

```json
{
  "success": true,
  "status": "NOT_REGISTERED",
  "integrity": "UNKNOWN",
  "message": "No registered fingerprint was found for this file.",
  "verification_id": "VER-10AA01",
  "filename": "notes.txt",
  "current_hash": "...",
  "verified_at": "2026-10-28T18:06:00Z"
}
```

Error shape (HTTP 400, 404, 413, or 500):

```json
{
  "success": false,
  "error": "Human readable error"
}
```

## File size and file types

Maximum upload size is 50 MB (`config.MAX_FILE_SIZE`, applied as Flask `MAX_CONTENT_LENGTH`). Over-size uploads return HTTP 413 and a JSON error. They are not registered.

`format_file_size` examples: `824 B`, `2.0 KB`, `2.4 MB`.

Any normal file can be fingerprinted: PDF, DOCX, TXT, JPG, PNG, ZIP, CSV, source code, and other types. Integrity checking uses raw bytes. The type field is only the uppercase extension. A file with no extension is `UNKNOWN`. The server does not open those formats.

## Public IDs

File IDs look like `FG-A82F91`. Verification IDs look like `VER-82AF31`.

The six characters come from `uuid.uuid4()`, so they are not a predictable 1, 2, 3 sequence. SQLite still uses an integer primary key internally. That integer is not part of the API.

## Installation

From the `backend` directory:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Dependencies: Flask, Flask-Cors, and Gunicorn (production WSGI server). `hashlib`, `sqlite3`, `uuid`, `datetime`, and `unittest` are in the Python standard library. `werkzeug` is installed with Flask.

## RUN COMPLETE FILEGUARD APPLICATION

Flask now serves **both** the approved frontend UI and the REST API from one process.

```bash
cd backend
source venv/bin/activate
FILEGUARD_PORT=5050 python app.py
```

Open the UI: http://127.0.0.1:5050

- Health check: http://127.0.0.1:5050/api/health
- API metadata: http://127.0.0.1:5050/api

Static assets live under `static/css/style.css` and `static/js/main.js`. Jinja templates live under `templates/`.

Production-style local run (same as Render):

```bash
cd backend
source venv/bin/activate
gunicorn app:app --bind 127.0.0.1:5050
```

## DEPLOYMENT — RENDER

**Platform:** Render Web Service (free tier)

| Setting | Value |
|---|---|
| Root Directory | `backend` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app --bind 0.0.0.0:$PORT` |
| Health Check Path | `/api/health` |

Render sets the `PORT` environment variable automatically. You do **not** need custom env vars for a basic deploy.

Optional: connect the repo using the project-root `render.yaml` Blueprint (same settings as above).

**SQLite on Render Free:** the filesystem is **ephemeral**. `fileguard.db` lives next to the app (`config.DATABASE_PATH`, absolute path from `__file__`). Registrations and verification history may be **lost** when the service restarts, redeploys, or the instance is recreated. That is acceptable for this college demo. The app creates an empty schema via `init_db()` if the database file is missing. Demo data is **not** seeded on startup (`seed_demo.py` is manual only).

**Same-origin UI:** the browser uses relative URLs (`/api/...`). No hardcoded localhost or port in `main.js`.

## Running backend (API only)

```bash
cd backend
source venv/bin/activate
python app.py
```

- Default URL: http://127.0.0.1:5000 (UI + API)
- Health check: http://127.0.0.1:5000/api/health

On macOS, AirPlay Receiver (Control Center) often listens on port 5000, and `python app.py` will exit with "Address already in use". Turn AirPlay Receiver off in System Settings, or start on another port:

```bash
FILEGUARD_PORT=5050 python app.py
```

The frontend base URL has to use that same port. The default in `config.py` stays 5000.

The first run creates `fileguard.db` with empty tables. No demo rows are inserted.

Debug mode is controlled by `DEBUG` in `config.py`. It is `True` for local development. Set it to `False` before using the app on a shared machine. `python app.py` is wrapped in `if __name__ == "__main__":`.

Optional demo rows (fingerprints and history only):

```bash
python seed_demo.py
```

Running the seed script twice does not duplicate those demo files.

## Testing

```bash
cd backend
source venv/bin/activate
python -m unittest test_api.py -v
```

The tests create a temporary database and do not modify `fileguard.db`.

They cover health, register, duplicate register, unchanged verify, modified verify, unregistered verify, list, details, missing file, history, dashboard, search, and a missing upload. Extra cases cover verify-by-id, delete-keeps-history, the 50 MB guard (with a tiny test limit), filename sanitizing, and the optional seed script.

## Frontend integration

Give `API_CONTRACT.md` to the frontend developer. Short version:

- Call `http://127.0.0.1:5000`.
- Send files as `FormData` with the field name `file`.
- Do not set the `Content-Type` header yourself. The browser must add the multipart boundary.
- For verify, branch on `data.status` (`VERIFIED`, `TAMPERED`, `NOT_REGISTERED`), not only on HTTP status. Those three results are HTTP 200.
- Stored filenames pass through `secure_filename`. `my report.pdf` is stored as `my_report.pdf`. The same sanitizing is applied on verify, so a second upload of the same original name still matches.
- `latest_status` is JSON `null` until that file has been checked.
- After `DELETE`, history entries can still contain a `file_id` that returns 404 from `GET /api/files/<file_id>`.

CORS allows every origin while the frontend is developed separately (`config.CORS_ORIGINS = "*"`). To lock it down, set `CORS_ORIGINS` to the real frontend origin list, for example `http://127.0.0.1:5500`.

If the HTML file is opened with `file://` and the browser blocks the call, serve the frontend with a local static server instead.

## Security decisions

- `secure_filename()` on every uploaded name before it is stored or looked up.
- Maximum body size 50 MB, with a second check while the hash is computed.
- Parameterized SQL only.
- No passwords, private keys, or file contents in the database.
- No execution or format parsing of uploads.
- No permanent copy of the upload.
- JSON errors with HTTP 400, 404, 413, and 500. Unexpected exceptions are logged on the server and returned as a generic message, without a stack trace.
- CORS is explicit and documented.
- There is no login. Anyone who can reach the port can register, verify, and delete. Keep the process on `127.0.0.1` for the demo.

## Delete / audit behavior

`DELETE /api/files/<file_id>` removes the registration only.

Verification history is kept. A later `GET /api/history` still shows those attempts. `GET /api/files/<file_id>` then returns 404. Dashboard verification counts still include attempts for deleted registrations. `total_files` counts registrations that still exist.

## Limitations

- Filename verification can attach a check to the wrong baseline when two different documents share a sanitized name. Prefer verify-by-File-ID.
- There are no user accounts, roles, or per-user files.
- SQLite is a single-file database for this demo, not a multi-server deployment. On Render Free, SQLite data is not durable across restarts.
- A matching hash is not a digital signature. There is no private key and no signer identity.
- `secure_filename()` removes characters outside a conservative ASCII set, so some original display names change.
- The extension label is not a real content-type check. A renamed file still hashes correctly; the label may say `TXT` even if the bytes are not text.
- The Flask development server is not a production WSGI server.
- On macOS, port 5000 may already be taken by AirPlay Receiver. See the running section.
- Timestamps are UTC strings with microseconds. If two events still share a timestamp, the internal integer id is only a tiebreaker, and those ids are not one sequence across the two tables.
- Search is case-insensitive for ASCII. `%` and `_` in the query are literal characters.

## Future improvements

- Make File ID verification the primary frontend action, with filename matching as a fallback.
- Add authentication before any deployment beyond localhost.
- Add pagination on the file list and history.
- Move to PostgreSQL if more than one machine must share the database.
- Rate-limit register and verify.
- Attach an optional human-readable display name separately from the sanitized lookup name.
- If authorship is ever required, that is a signature scheme, not a stronger hash. Hashing alone cannot provide it.
