# FileGuard API contract

This document is for the frontend developer. The backend is a separate Flask server. Do not send file bytes to any URL except the register and verify endpoints below.

## Base URL

```
http://127.0.0.1:5000
```

If the machine cannot bind port 5000 (macOS AirPlay Receiver often takes it), the backend can be started with `FILEGUARD_PORT=5050 python app.py`. Use that same host and port in every `fetch` URL below.

All responses are JSON. Timestamps are UTC ISO-8601 with microseconds, for example `2026-10-28T18:00:22.123456Z`.

## What the frontend must branch on

Integrity results use HTTP **200** and `"success": true`. Read `status`:

| `status` | `integrity` | UI |
|---|---|---|
| `VERIFIED` | `INTACT` | Green. Bytes match the registered fingerprint. |
| `TAMPERED` | `COMPROMISED` | Red. Bytes do not match. |
| `NOT_REGISTERED` | `UNKNOWN` | Neutral. No fingerprint was found for this lookup. |

Do not treat `TAMPERED` or `NOT_REGISTERED` as a failed HTTP request.

HTTP **400 / 404 / 413 / 500** look like this. `success` is false and there is no `status` field:

```json
{
  "success": false,
  "error": "Human readable error"
}
```

A match does **not** mean the file is authentic, owned by someone, true, or safe. It only means the current bytes match the previously registered SHA-256 fingerprint. Copy that limitation into any "verified" help text.

## How to upload a file

Field name: `file`

Content type: `multipart/form-data`

Do **not** set the `Content-Type` header in `fetch`. The browser adds the boundary. If you set `Content-Type: multipart/form-data` yourself, the server will not see the file.

```javascript
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch("http://127.0.0.1:5000/api/files/verify", {
  method: "POST",
  body: formData
});

const data = await response.json();

if (!response.ok || data.success === false) {
  // show data.error
}

if (data.status === "VERIFIED") {
  // show green verified UI
}

if (data.status === "TAMPERED") {
  // show red tampering UI
}

if (data.status === "NOT_REGISTERED") {
  // show unregistered UI
}
```

## Filename rules the UI should know

The stored name is the sanitized name, not always the raw name from the user's disk.

- `my report.pdf` is stored as `my_report.pdf`
- path pieces such as `../../` are removed
- characters outside letters, digits, dot, dash, and underscore are removed

You do not need to sanitize in the browser. Send the `File` object. The server sanitizes both register and filename-verify the same way, so the same file still matches.

Filename verify uses the **newest** registration of that sanitized name. If the user registered two different versions under one name, the older File ID is not the baseline for `POST /api/files/verify`.

To check a specific registration, use:

```
POST /api/files/verify/<file_id>
```

The uploaded filename can differ. The comparison uses that File ID only.

`latest_status` on a file is `null` when that file has never been checked. After a check it is `VERIFIED` or `TAMPERED`. `NOT_REGISTERED` attempts are not attached to a file row, so they do not appear as `latest_status`.

`file_size` is an integer number of bytes. Display `file_size_formatted` (`824 B`, `2.0 KB`, `2.4 MB`).

`file_type` is an uppercase extension such as `PDF`, `DOCX`, `TXT`, `JPG`, `PNG`, `ZIP`, `CSV`, or `PY`. No extension becomes `UNKNOWN`. The API accepts those and other normal files. There is no PDF-only restriction.

Maximum upload size is **50 MB**. Larger files return HTTP 413.

## CORS

Any origin may call the API during local development. If you open the HTML file as `file://` and the browser blocks the request, serve the frontend from localhost (Live Server, or `python -m http.server`) instead.

---

## GET /api

Service banner (JSON metadata). The browser UI is served at `GET /` (dashboard HTML).

**Success 200**

```json
{
  "name": "FileGuard API",
  "version": "1.0.0",
  "status": "online"
}
```

```javascript
const response = await fetch("/api");
const data = await response.json();
```

---

## GET /api/health

**Success 200**

```json
{
  "success": true,
  "status": "online",
  "service": "FileGuard API"
}
```

```javascript
const response = await fetch("http://127.0.0.1:5000/api/health");
const data = await response.json();
```

---

## POST /api/files/register

Register a fingerprint. The file is not stored.

**Request**

`multipart/form-data` with field `file`.

**Success 201** (new registration)

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
    "sha256_hash": "64 lowercase hex characters",
    "registered_at": "2026-10-28T18:00:00Z"
  }
}
```

**Success 200** (same sanitized filename and same SHA-256 already exist)

No second row is created. `file` is the existing record. `file_id` stays the same.

```json
{
  "success": true,
  "already_registered": true,
  "message": "This filename and fingerprint are already registered.",
  "file": {
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf",
    "file_type": "PDF",
    "file_size": 2516582,
    "file_size_formatted": "2.4 MB",
    "sha256_hash": "64 lowercase hex characters",
    "registered_at": "2026-10-28T18:00:00Z"
  }
}
```

Same filename with a **different** hash creates a new File ID (`already_registered: false`, HTTP 201).

**Errors**

| HTTP | When |
|---|---|
| 400 | Missing `file` field, empty filename, or filename not allowed |
| 413 | Larger than 50 MB |
| 500 | Unexpected server error |

```json
{
  "success": false,
  "error": "No file was uploaded. Send multipart/form-data with a 'file' field."
}
```

```javascript
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch("http://127.0.0.1:5000/api/files/register", {
  method: "POST",
  body: formData
});

const data = await response.json();

if (data.success && data.already_registered) {
  // tell the user this exact file name and fingerprint were already registered
  // data.file.file_id is the existing id
}

if (data.success && !data.already_registered) {
  // show data.file.file_id so the user can verify against it later
}
```

Save `data.file.file_id`. It is the reliable key for a later check.

---

## POST /api/files/verify

Compare the upload with the **newest** registration of the same sanitized filename.

**Request**

`multipart/form-data` with field `file`.

**Success 200 — VERIFIED**

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
  "stored_hash": "registered fingerprint",
  "current_hash": "fingerprint of this upload",
  "registered_at": "2026-10-28T18:00:00Z",
  "verified_at": "2026-10-28T18:05:00Z"
}
```

**Success 200 — TAMPERED**

`stored_hash` and `current_hash` differ. `file` is the registration that was used as the baseline (the newest one with that filename).

```json
{
  "success": true,
  "status": "TAMPERED",
  "integrity": "COMPROMISED",
  "message": "File fingerprint does not match the registered fingerprint.",
  "verification_id": "VER-991BC2",
  "file": {
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf"
  },
  "stored_hash": "registered fingerprint",
  "current_hash": "fingerprint of this upload",
  "registered_at": "2026-10-28T18:00:00Z",
  "verified_at": "2026-10-28T18:06:00Z"
}
```

**Success 200 — NOT_REGISTERED**

There is no `file` object and no `stored_hash`. `filename` is the sanitized upload name.

```json
{
  "success": true,
  "status": "NOT_REGISTERED",
  "integrity": "UNKNOWN",
  "message": "No registered fingerprint was found for this file.",
  "verification_id": "VER-10AA01",
  "filename": "notes.txt",
  "current_hash": "fingerprint of this upload",
  "verified_at": "2026-10-28T18:07:00Z"
}
```

**Errors**

| HTTP | When |
|---|---|
| 400 | Missing file or empty filename |
| 413 | Larger than 50 MB |
| 500 | Unexpected server error |

Every attempt, including `NOT_REGISTERED`, is stored and shows up in `GET /api/history`.

```javascript
const formData = new FormData();
formData.append("file", selectedFile);

const response = await fetch("http://127.0.0.1:5000/api/files/verify", {
  method: "POST",
  body: formData
});

const data = await response.json();

if (data.status === "VERIFIED") {
  // show green verified UI
}

if (data.status === "TAMPERED") {
  // show red tampering UI
  // data.stored_hash is the registered fingerprint
  // data.current_hash is this upload
}

if (data.status === "NOT_REGISTERED") {
  // show unregistered UI
  // data.filename is the sanitized name
}
```

---

## POST /api/files/verify/\<file_id\>

Compare the upload with one registration. This is more reliable than filename matching.

**Request**

`multipart/form-data` with field `file`.

URL example: `http://127.0.0.1:5000/api/files/verify/FG-A82F91`

**Success 200**

Same three bodies as `POST /api/files/verify`.

- If the File ID exists, `file.file_id` is that id and `file.filename` is the **registered** name, even when the uploaded file has a different name.
- If the File ID does not exist, the body is the `NOT_REGISTERED` shape (HTTP 200, not 404). The attempt is still recorded. `file_id` inside history is `null`.

**Errors**

Same 400 / 413 / 500 cases as filename verify.

```javascript
const formData = new FormData();
formData.append("file", selectedFile);

const fileId = "FG-A82F91";
const response = await fetch(
  "http://127.0.0.1:5000/api/files/verify/" + encodeURIComponent(fileId),
  {
    method: "POST",
    body: formData
  }
);

const data = await response.json();
```

Prefer this endpoint when the user still has the File ID from registration.

---

## GET /api/files

All registrations, newest first.

**Success 200**

```json
{
  "success": true,
  "count": 2,
  "files": [
    {
      "file_id": "FG-B721CD",
      "filename": "notes.txt",
      "file_type": "TXT",
      "file_size": 128,
      "file_size_formatted": "128 B",
      "sha256_hash": "64 lowercase hex characters",
      "registered_at": "2026-10-28T18:10:00Z",
      "latest_status": null
    },
    {
      "file_id": "FG-A82F91",
      "filename": "internship_report.pdf",
      "file_type": "PDF",
      "file_size": 2516582,
      "file_size_formatted": "2.4 MB",
      "sha256_hash": "64 lowercase hex characters",
      "registered_at": "2026-10-28T18:00:00Z",
      "latest_status": "VERIFIED"
    }
  ]
}
```

`latest_status` is `null`, `"VERIFIED"`, or `"TAMPERED"`.

`count` is the number of objects in `files`.

```javascript
const response = await fetch("http://127.0.0.1:5000/api/files");
const data = await response.json();

data.files.forEach((file) => {
  // file.file_id, file.filename, file.latest_status
});
```

---

## GET /api/files/search

**Query**

| Parameter | Required | Meaning |
|---|---|---|
| `q` | yes | Text matched against filename and file_id. ASCII case-insensitive. |

Example: `GET /api/files/search?q=certificate`

**Success 200**

```json
{
  "success": true,
  "query": "certificate",
  "count": 1,
  "files": [
    {
      "file_id": "FG-A82F91",
      "filename": "Internship_Certificate.txt",
      "file_type": "TXT",
      "file_size": 40,
      "file_size_formatted": "40 B",
      "sha256_hash": "64 lowercase hex characters",
      "registered_at": "2026-10-28T18:00:00Z",
      "latest_status": null
    }
  ]
}
```

Each object has the same fields as `GET /api/files`. Newest matches come first. An empty match list is success with `count: 0`. It is not a 404.

**Error 400**

```json
{
  "success": false,
  "error": "Search query is required. Use ?q= followed by text."
}
```

```javascript
const q = new URLSearchParams({ q: searchBoxValue });
const response = await fetch("http://127.0.0.1:5000/api/files/search?" + q.toString());
const data = await response.json();
```

Use `URLSearchParams` so spaces and other characters are encoded.

---

## GET /api/files/\<file_id\>

**Success 200**

```json
{
  "success": true,
  "file": {
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf",
    "file_type": "PDF",
    "file_size": 2516582,
    "file_size_formatted": "2.4 MB",
    "sha256_hash": "64 lowercase hex characters",
    "registered_at": "2026-10-28T18:00:00Z",
    "verification_attempts": 2,
    "last_verified": "2026-10-28T18:06:00Z",
    "last_status": "TAMPERED",
    "recent_verifications": [
      {
        "verification_id": "VER-991BC2",
        "file_id": "FG-A82F91",
        "filename": "internship_report.pdf",
        "stored_hash": "registered fingerprint",
        "current_hash": "fingerprint of that upload",
        "status": "TAMPERED",
        "verified_at": "2026-10-28T18:06:00Z"
      }
    ]
  }
}
```

`verification_attempts` counts every check for this File ID. `recent_verifications` contains at most 10, newest first.

`last_verified` and `last_status` are `null` when `verification_attempts` is 0. `recent_verifications` is then `[]`.

**Error 404**

```json
{
  "success": false,
  "error": "File ID not found."
}
```

```javascript
const response = await fetch(
  "http://127.0.0.1:5000/api/files/" + encodeURIComponent(fileId)
);
const data = await response.json();

if (response.status === 404) {
  // registration was removed, or the id is wrong
}
```

---

## DELETE /api/files/\<file_id\>

Removes the registration. **Does not** remove verification history.

**Success 200**

```json
{
  "success": true,
  "message": "File registration removed successfully"
}
```

**Error 404**

```json
{
  "success": false,
  "error": "File ID not found."
}
```

```javascript
const response = await fetch(
  "http://127.0.0.1:5000/api/files/" + encodeURIComponent(fileId),
  { method: "DELETE" }
);
const data = await response.json();
```

After a successful delete, `GET /api/files/<file_id>` is 404, but `GET /api/history/<verification_id>` for an old check still returns 200. If a history row links to a deleted file, handle that 404.

---

## GET /api/history

All verification attempts, newest first.

**Query (both optional)**

| Parameter | Meaning |
|---|---|
| `status` | `VERIFIED`, `TAMPERED`, or `NOT_REGISTERED`. Other values return 400. Case does not matter. |
| `limit` | Whole number from 1 to 1000. Example: `?limit=20`. |

Examples:

- `GET /api/history`
- `GET /api/history?status=TAMPERED`
- `GET /api/history?status=VERIFIED&limit=20`

**Success 200**

```json
{
  "success": true,
  "count": 1,
  "history": [
    {
      "verification_id": "VER-82AF31",
      "file_id": "FG-A82F91",
      "filename": "internship_report.pdf",
      "stored_hash": "registered fingerprint or null",
      "current_hash": "fingerprint of that upload",
      "status": "VERIFIED",
      "verified_at": "2026-10-28T18:05:00Z"
    }
  ]
}
```

`count` is the number of objects returned, after the filter and limit. It is not a total-in-database count when `limit` is set.

For `NOT_REGISTERED`, `file_id` is `null` and `stored_hash` is `null`.

**Error 400**

```json
{
  "success": false,
  "error": "Invalid status. Use VERIFIED, TAMPERED, or NOT_REGISTERED."
}
```

```json
{
  "success": false,
  "error": "Limit must be a whole number between 1 and 1000."
}
```

```javascript
const params = new URLSearchParams();
if (statusFilter) params.set("status", statusFilter);
if (limit) params.set("limit", String(limit));

const response = await fetch("http://127.0.0.1:5000/api/history?" + params.toString());
const data = await response.json();
```

---

## GET /api/history/\<verification_id\>

**Success 200**

```json
{
  "success": true,
  "verification": {
    "verification_id": "VER-82AF31",
    "file_id": "FG-A82F91",
    "filename": "internship_report.pdf",
    "stored_hash": "registered fingerprint or null",
    "current_hash": "fingerprint of that upload",
    "status": "VERIFIED",
    "verified_at": "2026-10-28T18:05:00Z"
  }
}
```

**Error 404**

```json
{
  "success": false,
  "error": "Verification ID not found."
}
```

```javascript
const response = await fetch(
  "http://127.0.0.1:5000/api/history/" + encodeURIComponent(verificationId)
);
const data = await response.json();
```

---

## GET /api/dashboard

One call for the dashboard cards and the activity list.

**Success 200**

```json
{
  "success": true,
  "stats": {
    "total_files": 24,
    "successful_verifications": 18,
    "tampering_detected": 3,
    "total_verifications": 23
  },
  "integrity_overview": {
    "verified": 18,
    "tampered": 3,
    "not_registered": 2
  },
  "recent_activity": [
    {
      "event": "verification",
      "status": "TAMPERED",
      "file_id": "FG-A82F91",
      "filename": "internship_report.pdf",
      "verification_id": "VER-991BC2",
      "timestamp": "2026-10-28T18:06:00Z",
      "summary": "TAMPERED internship_report.pdf"
    },
    {
      "event": "registration",
      "status": "REGISTERED",
      "file_id": "FG-B721CD",
      "filename": "notes.txt",
      "verification_id": null,
      "timestamp": "2026-10-28T18:00:00Z",
      "summary": "Registered notes.txt"
    }
  ]
}
```

How to read the numbers:

- `stats.total_files` is registrations that still exist. Deleted ones are not included.
- `stats.successful_verifications` equals `integrity_overview.verified`.
- `stats.tampering_detected` equals `integrity_overview.tampered`.
- `stats.total_verifications` is `verified + tampered + not_registered`.
- These verification numbers count **attempts**, including attempts whose registration was later deleted. They are not "number of files".
- `recent_activity` has at most 8 items, newest first. It mixes registrations and verifications.
- `event` is `"registration"` or `"verification"`.
- `status` on a registration event is `"REGISTERED"`. That word is only used in this feed. It is not a verification status.
- `verification_id` is `null` on registration events.
- `file_id` is `null` on a `NOT_REGISTERED` verification event.

```javascript
const response = await fetch("http://127.0.0.1:5000/api/dashboard");
const data = await response.json();

const stats = data.stats;
const overview = data.integrity_overview;

data.recent_activity.forEach((item) => {
  // item.summary is ready to display
  // item.timestamp is UTC
});
```

The numbers in the example are illustrative. An empty database returns zeros and `recent_activity: []`.

---

## Suggested screens

| Screen | Calls |
|---|---|
| Home / health | `GET /api/health` or `GET /api/dashboard` |
| Register | `POST /api/files/register`, then show `file.file_id` and `file.sha256_hash` |
| Verify | `POST /api/files/verify` or `POST /api/files/verify/<file_id>` |
| Registered files | `GET /api/files` |
| File detail | `GET /api/files/<file_id>` |
| Search | `GET /api/files/search?q=` |
| History | `GET /api/history` |
| One check | `GET /api/history/<verification_id>` |
| Dashboard | `GET /api/dashboard` |
| Remove a registration | `DELETE /api/files/<file_id>` |

## Empty database

Starting the backend does not insert sample files. Lists return `"count": 0` and an empty array. The optional command `python seed_demo.py` adds demo metadata. The frontend should not depend on those names existing.
