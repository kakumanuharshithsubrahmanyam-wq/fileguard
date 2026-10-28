"""SQLite persistence for FileGuard.

Flask routes call these helpers instead of embedding SQL. Every query uses
`?` placeholders. User input is never concatenated into a SQL string.

Uploaded file bytes are not stored. The registered_files table keeps only the
public File ID, sanitized filename, type label, size, SHA-256 fingerprint,
and registration time.

verification_history.file_id is intentionally not a foreign key. Deleting a
registration leaves past verification rows in place for the audit trail.
"""

import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import current_app, has_app_context

import config

STATUS_VERIFIED = "VERIFIED"
STATUS_TAMPERED = "TAMPERED"
STATUS_NOT_REGISTERED = "NOT_REGISTERED"
VALID_STATUSES = (
    STATUS_VERIFIED,
    STATUS_TAMPERED,
    STATUS_NOT_REGISTERED,
)

# Internal integer primary keys stay in SQLite. Public IDs are random.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS registered_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    registered_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_registered_name_hash
    ON registered_files (filename, sha256_hash);

CREATE INDEX IF NOT EXISTS idx_registered_filename
    ON registered_files (filename);

CREATE TABLE IF NOT EXISTS verification_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    verification_id TEXT NOT NULL UNIQUE,
    file_id TEXT,
    filename TEXT NOT NULL,
    stored_hash TEXT,
    current_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'TAMPERED', 'NOT_REGISTERED')),
    verified_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_file
    ON verification_history (file_id);

CREATE INDEX IF NOT EXISTS idx_verification_status
    ON verification_history (status);

CREATE INDEX IF NOT EXISTS idx_verification_time
    ON verification_history (verified_at);
"""


def utc_now_iso():
    """Current UTC time as ISO-8601 with microseconds.

    Example: 2026-10-28T18:00:22.123456Z
    Fractional seconds keep registrations and checks in order when they
    happen within the same wall-clock second.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _resolve_path(db_path=None):
    """Pick the database file.

    An explicit path wins. Inside a Flask app (including tests) the path comes
    from app config so tests never write to the normal fileguard.db. Outside
    a request, the configured project path is used.
    """
    if db_path:
        return db_path
    if has_app_context():
        configured = current_app.config.get("DATABASE_PATH")
        if configured:
            return configured
    return config.DATABASE_PATH


@contextmanager
def get_connection(db_path=None):
    """Open a SQLite connection, commit on success, and always close it."""
    conn = sqlite3.connect(
        _resolve_path(db_path),
        timeout=10,
        isolation_level="DEFERRED",
    )
    conn.row_factory = sqlite3.Row
    try:
        # History rows are kept after a file is deleted, so there is no
        # foreign key from verification_history to registered_files.
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=None):
    """Create the database file and tables when they do not already exist."""
    path = _resolve_path(db_path)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _row(row):
    if row is None:
        return None
    return dict(row)


def _new_public_id(prefix):
    """Build a public id such as FG-A82F91 or VER-82AF31.

    The suffix is taken from a random UUID. It is not a sequential counter,
    so outsiders cannot guess the next id by adding one.
    """
    return "%s-%s" % (prefix, uuid.uuid4().hex[:6].upper())


def _select_by_file_id(conn, file_id):
    row = conn.execute(
        """
        SELECT id, file_id, filename, file_type, file_size, sha256_hash, registered_at
        FROM registered_files
        WHERE file_id = ?
        """,
        (file_id,),
    ).fetchone()
    return _row(row)


def _select_duplicate(conn, filename, sha256_hash):
    row = conn.execute(
        """
        SELECT id, file_id, filename, file_type, file_size, sha256_hash, registered_at
        FROM registered_files
        WHERE filename = ? AND sha256_hash = ?
        ORDER BY registered_at DESC, id DESC
        LIMIT 1
        """,
        (filename, sha256_hash),
    ).fetchone()
    return _row(row)


def register_file(filename, file_type, file_size, sha256_hash, db_path=None):
    """Store a fingerprint, or return the existing row when it is a duplicate.

    Duplicate rule (also enforced by a unique index):
    the same sanitized filename AND the same SHA-256 are one registration.
    The same filename with a different hash is a new registration.

    Returns (record_dict, already_registered).
    """
    with get_connection(db_path) as conn:
        existing = _select_duplicate(conn, filename, sha256_hash)
        if existing:
            return existing, True

        registered_at = utc_now_iso()
        for _attempt in range(8):
            file_id = _new_public_id("FG")
            try:
                conn.execute(
                    """
                    INSERT INTO registered_files (
                        file_id, filename, file_type, file_size, sha256_hash, registered_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (file_id, filename, file_type, file_size, sha256_hash, registered_at),
                )
            except sqlite3.IntegrityError:
                # Either a random File ID collided, or the same name+hash
                # was inserted at the same time. Roll back the failed
                # statement, then return the existing fingerprint if it is there.
                conn.rollback()
                existing = _select_duplicate(conn, filename, sha256_hash)
                if existing:
                    return existing, True
                continue

            created = _select_by_file_id(conn, file_id)
            return created, False

    raise RuntimeError("Could not allocate a unique file ID.")


def get_file_by_id(file_id, db_path=None):
    """Return one registration, or None when the File ID is unknown."""
    with get_connection(db_path) as conn:
        return _select_by_file_id(conn, file_id)


def get_latest_file_by_filename(filename, db_path=None):
    """Return the newest registration for a sanitized filename, or None.

    When several registrations share a filename, the newest registered_at
    (and then the highest internal id) is the baseline for filename verification.
    Verification by File ID does not use this helper.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, file_id, filename, file_type, file_size, sha256_hash, registered_at
            FROM registered_files
            WHERE filename = ?
            ORDER BY registered_at DESC, id DESC
            LIMIT 1
            """,
            (filename,),
        ).fetchone()
        return _row(row)


def get_all_files(db_path=None):
    """Return every registration, newest first, with the latest verification status."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                rf.id,
                rf.file_id,
                rf.filename,
                rf.file_type,
                rf.file_size,
                rf.sha256_hash,
                rf.registered_at,
                (
                    SELECT vh.status
                    FROM verification_history AS vh
                    WHERE vh.file_id = rf.file_id
                    ORDER BY vh.verified_at DESC, vh.id DESC
                    LIMIT 1
                ) AS latest_status
            FROM registered_files AS rf
            ORDER BY rf.registered_at DESC, rf.id DESC
            """
        ).fetchall()
        return [_row(row) for row in rows]


def search_files(query, db_path=None):
    """Case-insensitive search of filename and file_id. Newest first.

    `%` and `_` in the query are treated as literal characters.
    """
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = "%" + escaped + "%"
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                rf.id,
                rf.file_id,
                rf.filename,
                rf.file_type,
                rf.file_size,
                rf.sha256_hash,
                rf.registered_at,
                (
                    SELECT vh.status
                    FROM verification_history AS vh
                    WHERE vh.file_id = rf.file_id
                    ORDER BY vh.verified_at DESC, vh.id DESC
                    LIMIT 1
                ) AS latest_status
            FROM registered_files AS rf
            WHERE rf.filename LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR rf.file_id LIKE ? ESCAPE '\\' COLLATE NOCASE
            ORDER BY rf.registered_at DESC, rf.id DESC
            """,
            (pattern, pattern),
        ).fetchall()
        return [_row(row) for row in rows]


def add_verification(file_id, filename, stored_hash, current_hash, status, db_path=None):
    """Record one verification attempt and return the stored row.

    Every attempt is stored, including NOT_REGISTERED. file_id and stored_hash
    may be None when no registration was found.
    """
    if status not in VALID_STATUSES:
        raise ValueError("Invalid verification status.")

    with get_connection(db_path) as conn:
        verified_at = utc_now_iso()
        for _attempt in range(8):
            verification_id = _new_public_id("VER")
            try:
                conn.execute(
                    """
                    INSERT INTO verification_history (
                        verification_id, file_id, filename, stored_hash,
                        current_hash, status, verified_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        verification_id,
                        file_id,
                        filename,
                        stored_hash,
                        current_hash,
                        status,
                        verified_at,
                    ),
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                continue

            row = conn.execute(
                """
                SELECT verification_id, file_id, filename, stored_hash,
                       current_hash, status, verified_at
                FROM verification_history
                WHERE verification_id = ?
                """,
                (verification_id,),
            ).fetchone()
            return _row(row)

    raise RuntimeError("Could not allocate a unique verification ID.")


def _verification_from_row(row):
    return _row(row)


def get_verification_history(status=None, limit=None, db_path=None):
    """Return verification attempts, newest first.

    status filters to one of VERIFIED, TAMPERED, NOT_REGISTERED.
    limit caps the number of rows. None returns every row.
    """
    sql = """
        SELECT verification_id, file_id, filename, stored_hash,
               current_hash, status, verified_at
        FROM verification_history
    """
    params = []
    if status is not None:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY verified_at DESC, id DESC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_verification_from_row(row) for row in rows]


def get_verification_by_id(verification_id, db_path=None):
    """Return one verification attempt, or None."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT verification_id, file_id, filename, stored_hash,
                   current_hash, status, verified_at
            FROM verification_history
            WHERE verification_id = ?
            """,
            (verification_id,),
        ).fetchone()
        return _verification_from_row(row)


def get_file_verification_history(file_id, limit=None, db_path=None):
    """Return verification attempts for one File ID, newest first."""
    sql = """
        SELECT verification_id, file_id, filename, stored_hash,
               current_hash, status, verified_at
        FROM verification_history
        WHERE file_id = ?
        ORDER BY verified_at DESC, id DESC
    """
    params = [file_id]
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_verification_from_row(row) for row in rows]


def get_file_verification_stats(file_id, db_path=None):
    """Return attempt count, last timestamp, and last status for one File ID."""
    with get_connection(db_path) as conn:
        count_row = conn.execute(
            "SELECT COUNT(*) AS attempts FROM verification_history WHERE file_id = ?",
            (file_id,),
        ).fetchone()
        latest = conn.execute(
            """
            SELECT status, verified_at
            FROM verification_history
            WHERE file_id = ?
            ORDER BY verified_at DESC, id DESC
            LIMIT 1
            """,
            (file_id,),
        ).fetchone()

    attempts = int(count_row["attempts"]) if count_row else 0
    if latest is None:
        return {
            "verification_attempts": attempts,
            "last_verified": None,
            "last_status": None,
        }
    return {
        "verification_attempts": attempts,
        "last_verified": latest["verified_at"],
        "last_status": latest["status"],
    }


def get_dashboard_stats(activity_limit=8, db_path=None):
    """Counts for the dashboard, plus a short mixed activity feed.

    Verification counts include attempts whose registration was later deleted.
    They count events, not distinct files. total_files counts current
    registrations only.
    """
    with get_connection(db_path) as conn:
        total_files = conn.execute(
            "SELECT COUNT(*) AS n FROM registered_files"
        ).fetchone()["n"]
        status_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM verification_history
            GROUP BY status
            """
        ).fetchall()
        recent_files = conn.execute(
            """
            SELECT file_id, filename, sha256_hash, registered_at, id
            FROM registered_files
            ORDER BY registered_at DESC, id DESC
            LIMIT ?
            """,
            (activity_limit,),
        ).fetchall()
        recent_checks = conn.execute(
            """
            SELECT verification_id, file_id, filename, status, verified_at, id
            FROM verification_history
            ORDER BY verified_at DESC, id DESC
            LIMIT ?
            """,
            (activity_limit,),
        ).fetchall()

    counts = {status: 0 for status in VALID_STATUSES}
    for row in status_rows:
        counts[row["status"]] = int(row["n"])

    verified = counts[STATUS_VERIFIED]
    tampered = counts[STATUS_TAMPERED]
    not_registered = counts[STATUS_NOT_REGISTERED]

    activity = []
    for row in recent_files:
        activity.append(
            {
                "event": "registration",
                "status": "REGISTERED",
                "file_id": row["file_id"],
                "filename": row["filename"],
                "verification_id": None,
                "timestamp": row["registered_at"],
                "summary": "Registered %s" % row["filename"],
                "_sort_id": row["id"],
            }
        )
    for row in recent_checks:
        activity.append(
            {
                "event": "verification",
                "status": row["status"],
                "file_id": row["file_id"],
                "filename": row["filename"],
                "verification_id": row["verification_id"],
                "timestamp": row["verified_at"],
                "summary": "%s %s" % (row["status"], row["filename"]),
                "_sort_id": row["id"],
            }
        )

    activity.sort(key=lambda item: (item["timestamp"], item["_sort_id"]), reverse=True)
    trimmed = []
    for item in activity[:activity_limit]:
        cleaned = dict(item)
        cleaned.pop("_sort_id", None)
        trimmed.append(cleaned)

    return {
        "stats": {
            "total_files": int(total_files),
            "successful_verifications": verified,
            "tampering_detected": tampered,
            "total_verifications": verified + tampered + not_registered,
        },
        "integrity_overview": {
            "verified": verified,
            "tampered": tampered,
            "not_registered": not_registered,
        },
        "recent_activity": trimmed,
    }


def delete_file(file_id, db_path=None):
    """Delete one registration. Verification history is kept for audit.

    Returns True when a row was removed, False when the File ID did not exist.
    """
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM registered_files WHERE file_id = ?",
            (file_id,),
        )
        return cursor.rowcount > 0
