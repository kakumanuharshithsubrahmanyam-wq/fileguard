"""FileGuard HTTP API.

The server accepts an uploaded file, hashes its raw bytes, and discards the
upload. It never executes a file and never stores file contents.

Run locally:

    python app.py

Then open http://127.0.0.1:5000/ (UI) or http://127.0.0.1:5000/api/health
"""

import logging
import os
import re

from flask import Flask, current_app, jsonify, render_template, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

import config
import database
from hash_utils import (
    FileTooLargeError,
    file_type_from_filename,
    format_file_size,
    hash_stream,
)

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_FILENAME_LENGTH = 255
_HISTORY_LIMIT_MAX = 1000
_RECENT_VERIFICATIONS = 10
_ACTIVITY_LIMIT = 8


def create_app(overrides=None):
    """Build the Flask app. Tests pass overrides so they can use a temp database."""
    overrides = overrides or {}
    app = Flask(__name__)

    database_path = overrides.get("DATABASE_PATH", config.DATABASE_PATH)
    max_file_size = overrides.get("MAX_FILE_SIZE", config.MAX_FILE_SIZE)

    app.config["DATABASE_PATH"] = database_path
    app.config["MAX_CONTENT_LENGTH"] = max_file_size
    app.config["DEBUG"] = overrides.get("DEBUG", config.DEBUG)
    # Always return JSON error responses instead of the interactive debugger page.
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.json.sort_keys = False

    # Allow a frontend on another localhost port to call this API.
    # See config.CORS_ORIGINS for how to restrict this later.
    CORS(app, resources={r"/*": {"origins": config.CORS_ORIGINS}})

    database.init_db(database_path)
    _register_ui_routes(app)
    _register_routes(app)
    _register_error_handlers(app)
    return app


def json_error(message, status):
    """Consistent error body: {"success": false, "error": "..."}."""
    return jsonify({"success": False, "error": message}), status


def file_payload(record, include_status=False):
    """Shape a registration row for JSON responses."""
    payload = {
        "file_id": record["file_id"],
        "filename": record["filename"],
        "file_type": record["file_type"],
        "file_size": record["file_size"],
        "file_size_formatted": format_file_size(record["file_size"]),
        "sha256_hash": record["sha256_hash"],
        "registered_at": record["registered_at"],
    }
    if include_status:
        payload["latest_status"] = record.get("latest_status")
    return payload


def verification_payload(record):
    """Shape a verification-history row for JSON responses."""
    return {
        "verification_id": record["verification_id"],
        "file_id": record["file_id"],
        "filename": record["filename"],
        "stored_hash": record["stored_hash"],
        "current_hash": record["current_hash"],
        "status": record["status"],
        "verified_at": record["verified_at"],
    }


def read_uploaded_file():
    """Validate the multipart `file` field and fingerprint it.

    Returns (metadata, None) or (None, error_response).

    Security: secure_filename() strips path characters. The bytes are hashed
    in chunks and then dropped. upload.save() is never called, and the bytes
    are never passed to a shell or a parser.
    """
    if "file" not in request.files:
        return None, json_error(
            "No file was uploaded. Send multipart/form-data with a 'file' field.",
            400,
        )

    upload = request.files["file"]
    raw_name = upload.filename or ""
    if not str(raw_name).strip():
        return None, json_error("Filename is missing.", 400)

    # Security: drop directory parts and characters that are unsafe in a stored name.
    filename = secure_filename(raw_name)
    if not filename:
        return None, json_error("Filename is not allowed.", 400)
    if len(filename) > _MAX_FILENAME_LENGTH:
        return None, json_error("Filename is too long.", 400)

    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    try:
        # Hash and measure in one chunked pass. The upload is not saved.
        sha256_hash, file_size = hash_stream(upload.stream, max_bytes=max_bytes)
    except FileTooLargeError:
        limit_label = format_file_size(max_bytes)
        return None, json_error(
            "File is too large. Maximum upload size is %s." % limit_label,
            413,
        )
    except Exception:
        current_app.logger.exception("Could not read upload")
        return None, json_error("Could not read the uploaded file.", 400)

    if not _SHA256_RE.match(sha256_hash):
        return None, json_error("Could not fingerprint the uploaded file.", 500)

    return {
        "filename": filename,
        "file_type": file_type_from_filename(filename),
        "file_size": file_size,
        "sha256_hash": sha256_hash,
    }, None


def compare_fingerprints(stored_hash, current_hash):
    """Compare a stored fingerprint with the fingerprint of the current bytes.

    VERIFIED  means the bytes match the registered fingerprint.
    TAMPERED  means they do not.

    This is file-integrity verification only. A match does not prove authorship,
    ownership, truthfulness, or that the file is malware-free. The fingerprint
    is not a secret, so a normal string comparison is enough.
    """
    if stored_hash == current_hash:
        return database.STATUS_VERIFIED
    return database.STATUS_TAMPERED


def matched_verification_body(saved, record):
    """JSON body for VERIFIED and TAMPERED results."""
    status = saved["status"]
    if status == database.STATUS_VERIFIED:
        integrity = "INTACT"
        message = "File integrity verified. No modification detected."
    else:
        integrity = "COMPROMISED"
        message = "File fingerprint does not match the registered fingerprint."

    return {
        "success": True,
        "status": status,
        "integrity": integrity,
        "message": message,
        "verification_id": saved["verification_id"],
        "file": {
            "file_id": record["file_id"],
            "filename": record["filename"],
        },
        "stored_hash": saved["stored_hash"],
        "current_hash": saved["current_hash"],
        "registered_at": record["registered_at"],
        "verified_at": saved["verified_at"],
    }


def unregistered_verification_body(saved):
    """JSON body when no registration matches the lookup."""
    return {
        "success": True,
        "status": database.STATUS_NOT_REGISTERED,
        "integrity": "UNKNOWN",
        "message": "No registered fingerprint was found for this file.",
        "verification_id": saved["verification_id"],
        "filename": saved["filename"],
        "current_hash": saved["current_hash"],
        "verified_at": saved["verified_at"],
    }


def perform_verification(upload, record):
    """Compare an upload to a registration (or to nothing) and store the attempt.

    `record` is the baseline chosen by the caller:
    the latest row for that filename, or one specific File ID.
    Passing None means nothing was registered under that lookup.
    """
    if record is None:
        saved = database.add_verification(
            file_id=None,
            filename=upload["filename"],
            stored_hash=None,
            current_hash=upload["sha256_hash"],
            status=database.STATUS_NOT_REGISTERED,
        )
        return jsonify(unregistered_verification_body(saved)), 200

    # Integrity comparison: stored fingerprint vs fingerprint of this upload.
    status = compare_fingerprints(record["sha256_hash"], upload["sha256_hash"])
    saved = database.add_verification(
        file_id=record["file_id"],
        filename=upload["filename"],
        stored_hash=record["sha256_hash"],
        current_hash=upload["sha256_hash"],
        status=status,
    )
    return jsonify(matched_verification_body(saved, record)), 200


def parse_history_filters():
    """Read optional ?status= and ?limit= query parameters.

    Returns (status, limit, error_response). status and limit may be None.
    """
    raw_status = request.args.get("status")
    status = None
    if raw_status is not None and raw_status.strip() != "":
        status = raw_status.strip().upper()
        if status not in database.VALID_STATUSES:
            return None, None, json_error(
                "Invalid status. Use VERIFIED, TAMPERED, or NOT_REGISTERED.",
                400,
            )

    raw_limit = request.args.get("limit")
    limit = None
    if raw_limit is not None and str(raw_limit).strip() != "":
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = -1
        if limit < 1 or limit > _HISTORY_LIMIT_MAX:
            return None, None, json_error(
                "Limit must be a whole number between 1 and 1000.",
                400,
            )

    return status, limit, None


def _register_ui_routes(app):
    """Serve the approved Jinja frontend from the same Flask process as the API."""

    @app.route("/", methods=["GET"])
    def dashboard():
        return render_template(
            "dashboard.html",
            active_page="dashboard",
            page_title="Security Dashboard",
            page_subtitle="Monitor file integrity and detect unauthorized modifications.",
        )

    @app.route("/register", methods=["GET"])
    def register():
        return render_template(
            "register.html",
            active_page="register",
            page_title="Register File",
            page_subtitle="Create a secure SHA-256 fingerprint for a file.",
        )

    @app.route("/verify", methods=["GET"])
    def verify():
        return render_template(
            "verify.html",
            active_page="verify",
            page_title="Verify File Integrity",
            page_subtitle="Check whether a registered file has been modified.",
        )

    @app.route("/files", methods=["GET"])
    def files():
        return render_template(
            "files.html",
            active_page="files",
            page_title="File Registry",
            page_subtitle="Manage files protected by FileGuard.",
        )

    @app.route("/history", methods=["GET"])
    def history():
        return render_template(
            "history.html",
            active_page="history",
            page_title="Verification History",
            page_subtitle="Review previous file-integrity checks.",
        )

    @app.route("/files/<file_id>", methods=["GET"])
    def file_details(file_id):
        return render_template(
            "file_details.html",
            active_page="files",
            page_title="File Details",
            page_subtitle="Registered metadata, fingerprint and verification history for a single file.",
            file_id=file_id,
        )


def _register_routes(app):
    @app.route("/api", methods=["GET"])
    def api_root():
        return jsonify(
            {
                "name": config.API_NAME,
                "version": config.API_VERSION,
                "status": "online",
            }
        )

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify(
            {
                "success": True,
                "status": "online",
                "service": config.API_NAME,
            }
        )

    @app.route("/api/files/register", methods=["POST"])
    def register_file():
        upload, error = read_uploaded_file()
        if error:
            return error

        record, already_registered = database.register_file(
            filename=upload["filename"],
            file_type=upload["file_type"],
            file_size=upload["file_size"],
            sha256_hash=upload["sha256_hash"],
        )
        if already_registered:
            message = "This filename and fingerprint are already registered."
            status_code = 200
        else:
            message = "File registered successfully"
            status_code = 201

        return jsonify(
            {
                "success": True,
                "already_registered": already_registered,
                "message": message,
                "file": file_payload(record),
            }
        ), status_code

    @app.route("/api/files/verify", methods=["POST"])
    def verify_file():
        """Verify an upload against the newest registration of the same filename.

        Filename lookup is the simple baseline for this internship version.
        POST /api/files/verify/<file_id> checks one specific registration and
        is the more reliable option when names collide.
        """
        upload, error = read_uploaded_file()
        if error:
            return error

        # Baseline = most recent registration of this sanitized filename.
        record = database.get_latest_file_by_filename(upload["filename"])
        return perform_verification(upload, record)

    @app.route("/api/files/verify/<file_id>", methods=["POST"])
    def verify_file_by_id(file_id):
        """Verify an upload against one File ID, ignoring the uploaded filename.

        The lookup is isolated in get_file_by_id() so a future identifier
        (for example a user-supplied id in a form field) can reuse the same
        comparison in perform_verification().
        """
        upload, error = read_uploaded_file()
        if error:
            return error

        record = database.get_file_by_id(file_id)
        return perform_verification(upload, record)

    @app.route("/api/files", methods=["GET"])
    def list_files():
        records = database.get_all_files()
        files = [file_payload(record, include_status=True) for record in records]
        return jsonify({"success": True, "count": len(files), "files": files})

    @app.route("/api/files/search", methods=["GET"])
    def search_files():
        query = (request.args.get("q") or "").strip()
        if not query:
            return json_error("Search query is required. Use ?q= followed by text.", 400)
        if len(query) > 200:
            return json_error("Search query is too long.", 400)

        records = database.search_files(query)
        files = [file_payload(record, include_status=True) for record in records]
        return jsonify(
            {
                "success": True,
                "query": query,
                "count": len(files),
                "files": files,
            }
        )

    @app.route("/api/files/<file_id>", methods=["GET"], endpoint="api_file_details")
    def api_file_details(file_id):
        record = database.get_file_by_id(file_id)
        if record is None:
            return json_error("File ID not found.", 404)

        stats = database.get_file_verification_stats(file_id)
        history = database.get_file_verification_history(
            file_id, limit=_RECENT_VERIFICATIONS
        )
        payload = file_payload(record)
        payload["verification_attempts"] = stats["verification_attempts"]
        payload["last_verified"] = stats["last_verified"]
        payload["last_status"] = stats["last_status"]
        payload["recent_verifications"] = [
            verification_payload(item) for item in history
        ]
        return jsonify({"success": True, "file": payload})

    @app.route("/api/files/<file_id>", methods=["DELETE"])
    def delete_file(file_id):
        # Audit decision: verification_history rows are NOT deleted.
        removed = database.delete_file(file_id)
        if not removed:
            return json_error("File ID not found.", 404)
        return jsonify(
            {
                "success": True,
                "message": "File registration removed successfully",
            }
        )

    @app.route("/api/history", methods=["GET"])
    def verification_history():
        status, limit, error = parse_history_filters()
        if error:
            return error
        history = database.get_verification_history(status=status, limit=limit)
        return jsonify(
            {
                "success": True,
                "count": len(history),
                "history": [verification_payload(item) for item in history],
            }
        )

    @app.route("/api/history/<verification_id>", methods=["GET"])
    def verification_details(verification_id):
        record = database.get_verification_by_id(verification_id)
        if record is None:
            return json_error("Verification ID not found.", 404)
        return jsonify({"success": True, "verification": verification_payload(record)})

    @app.route("/api/dashboard", methods=["GET"], endpoint="api_dashboard")
    def api_dashboard():
        summary = database.get_dashboard_stats(activity_limit=_ACTIVITY_LIMIT)
        return jsonify(
            {
                "success": True,
                "stats": summary["stats"],
                "integrity_overview": summary["integrity_overview"],
                "recent_activity": summary["recent_activity"],
            }
        )


def _register_error_handlers(app):
    @app.errorhandler(RequestEntityTooLarge)
    def file_too_large(_error):
        # Flask raises this when Content-Length is above MAX_CONTENT_LENGTH,
        # before the route reads the upload.
        limit_label = format_file_size(current_app.config["MAX_CONTENT_LENGTH"])
        return json_error(
            "File is too large. Maximum upload size is %s." % limit_label,
            413,
        )

    @app.errorhandler(HTTPException)
    def http_exception(error):
        if error.code == 413:
            return file_too_large(error)
        messages = {
            400: "Bad request.",
            404: "Resource not found.",
            405: "Method not allowed.",
        }
        message = messages.get(error.code, "Request failed.")
        return json_error(message, error.code or 500)

    @app.errorhandler(Exception)
    def unexpected_error(error):
        # Security: log the traceback on the server, never return it to the client.
        if isinstance(error, HTTPException):
            return http_exception(error)
        current_app.logger.exception("Unexpected server error")
        return json_error("An unexpected error occurred.", 500)


app = create_app()


if __name__ == "__main__":
    port = int(
        os.environ.get(
            "PORT",
            os.environ.get("FILEGUARD_PORT", "5000"),
        )
    )
    logging.basicConfig(
        level=logging.DEBUG if config.DEBUG else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    # Local development only. Render uses Gunicorn, not this block.
    app.run(host="0.0.0.0", port=port, debug=False)
