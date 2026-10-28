"""Optional demonstration metadata.

This script is NOT run when the API starts. A normal start uses an empty
database (tables only). Run it yourself if you want sample rows:

    python seed_demo.py

The script stores fingerprints and history only. It does not store file bytes.
Running it twice does not duplicate the demo registrations.
"""

import hashlib
import sys

import database


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def seed(db_path=None, echo=True):
    """Insert a few demo registrations and verification events."""

    def say(message):
        if echo:
            print(message)

    database.init_db(db_path)

    certificate_hash = _digest("FileGuard demo certificate - original bytes")
    notes_hash = _digest("FileGuard demo meeting notes - original bytes")
    notes_tampered_hash = _digest("FileGuard demo meeting notes - edited bytes")
    report_hash = _digest("FileGuard demo weekly report - original bytes")
    unknown_hash = _digest("FileGuard demo file that was never registered")

    existing = database.get_latest_file_by_filename("demo_certificate.pdf", db_path=db_path)
    if existing and existing["sha256_hash"] == certificate_hash:
        say("Demo data already exists. Nothing to do.")
        return

    certificate, _ = database.register_file(
        filename="demo_certificate.pdf",
        file_type="PDF",
        file_size=24831,
        sha256_hash=certificate_hash,
        db_path=db_path,
    )
    notes, _ = database.register_file(
        filename="demo_notes.txt",
        file_type="TXT",
        file_size=4096,
        sha256_hash=notes_hash,
        db_path=db_path,
    )
    report, _ = database.register_file(
        filename="demo_report.csv",
        file_type="CSV",
        file_size=1024,
        sha256_hash=report_hash,
        db_path=db_path,
    )

    database.add_verification(
        file_id=certificate["file_id"],
        filename=certificate["filename"],
        stored_hash=certificate["sha256_hash"],
        current_hash=certificate["sha256_hash"],
        status=database.STATUS_VERIFIED,
        db_path=db_path,
    )
    database.add_verification(
        file_id=notes["file_id"],
        filename=notes["filename"],
        stored_hash=notes["sha256_hash"],
        current_hash=notes_tampered_hash,
        status=database.STATUS_TAMPERED,
        db_path=db_path,
    )
    database.add_verification(
        file_id=None,
        filename="unknown_photo.jpg",
        stored_hash=None,
        current_hash=unknown_hash,
        status=database.STATUS_NOT_REGISTERED,
        db_path=db_path,
    )
    database.add_verification(
        file_id=report["file_id"],
        filename=report["filename"],
        stored_hash=report["sha256_hash"],
        current_hash=report["sha256_hash"],
        status=database.STATUS_VERIFIED,
        db_path=db_path,
    )

    say("Demo metadata inserted.")
    say("  %s  demo_certificate.pdf" % certificate["file_id"])
    say("  %s  demo_notes.txt" % notes["file_id"])
    say("  %s  demo_report.csv" % report["file_id"])


if __name__ == "__main__":
    try:
        seed()
    except Exception as exc:
        print("Could not seed demo data: %s" % exc)
        sys.exit(1)
