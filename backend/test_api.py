"""API tests for FileGuard.

Each test uses a temporary SQLite file. Nothing here reads or writes the
normal backend/fileguard.db used by `python app.py`.
"""

import hashlib
import io
import os
import tempfile
import unittest

import config
from app import create_app
from hash_utils import calculate_sha256, format_file_size

ORIGINAL = b"This is the original FileGuard test file."
MODIFIED = b"This is the modified FileGuard test file."


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class FormatAndHashTests(unittest.TestCase):
    def test_format_file_size_examples(self):
        self.assertEqual(format_file_size(824), "824 B")
        self.assertEqual(format_file_size(2048), "2.0 KB")
        self.assertEqual(format_file_size(2516582), "2.4 MB")
        self.assertEqual(format_file_size(0), "0 B")

    def test_calculate_sha256_matches_hashlib_and_rewinds(self):
        payload = b"abc" * 30000  # larger than one 64 KB chunk
        stream = io.BytesIO(payload)
        digest = calculate_sha256(stream)
        self.assertEqual(digest, sha256_bytes(payload))
        self.assertEqual(stream.read(), payload)

    def test_empty_file_hash_is_the_standard_sha256(self):
        stream = io.BytesIO(b"")
        digest = calculate_sha256(stream)
        self.assertEqual(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


class FileGuardApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test_fileguard.db")
        self.app = create_app(
            {
                "DATABASE_PATH": self.db_path,
                "DEBUG": False,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, url, content, filename):
        return self.client.post(
            url,
            data={"file": (io.BytesIO(content), filename)},
        )

    def register(self, content, filename):
        return self.upload("/api/files/register", content, filename)

    def verify(self, content, filename, file_id=None):
        url = "/api/files/verify"
        if file_id:
            url = "/api/files/verify/" + file_id
        return self.upload(url, content, filename)

    def test_temporary_database_is_not_the_project_database(self):
        self.assertNotEqual(self.app.config["DATABASE_PATH"], config.DATABASE_PATH)
        self.assertTrue(self.db_path.startswith(self.tmp.name))

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["success"], True)
        self.assertEqual(body["status"], "online")
        self.assertEqual(body["service"], "FileGuard API")

    def test_api_root(self):
        response = self.client.get("/api")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["name"], "FileGuard API")
        self.assertEqual(body["version"], "1.0.0")
        self.assertEqual(body["status"], "online")

    def test_ui_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Dashboard", response.data)
        self.assertIn(b"text/html", response.content_type.encode())

    def test_ui_register(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Register File", response.data)

    def test_ui_verify(self):
        response = self.client.get("/verify")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Verify File Integrity", response.data)

    def test_ui_files(self):
        response = self.client.get("/files")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"File Registry", response.data)

    def test_ui_history(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Verification History", response.data)

    def test_ui_file_details_missing_record(self):
        response = self.client.get("/files/FG-MISSING")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"File Details", response.data)
        self.assertIn(b'data-file-id="FG-MISSING"', response.data)

    def test_register_file(self):
        response = self.register(ORIGINAL, "sample.txt")
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertFalse(body["already_registered"])
        self.assertEqual(body["message"], "File registered successfully")
        recorded = body["file"]
        self.assertTrue(recorded["file_id"].startswith("FG-"))
        self.assertEqual(len(recorded["file_id"]), 9)
        self.assertEqual(recorded["filename"], "sample.txt")
        self.assertEqual(recorded["file_type"], "TXT")
        self.assertEqual(recorded["file_size"], len(ORIGINAL))
        self.assertEqual(recorded["sha256_hash"], sha256_bytes(ORIGINAL))
        self.assertTrue(recorded["registered_at"].endswith("Z"))
        self.assertIn("file_size_formatted", recorded)

    def test_register_duplicate(self):
        first = self.register(ORIGINAL, "sample.txt").get_json()
        second_response = self.register(ORIGINAL, "sample.txt")
        self.assertEqual(second_response.status_code, 200)
        second = second_response.get_json()
        self.assertTrue(second["success"])
        self.assertTrue(second["already_registered"])
        self.assertEqual(second["file"]["file_id"], first["file"]["file_id"])

        listing = self.client.get("/api/files").get_json()
        self.assertEqual(listing["count"], 1)

    def test_same_filename_different_hash_is_a_new_registration(self):
        first = self.register(ORIGINAL, "sample.txt").get_json()["file"]
        second_response = self.register(MODIFIED, "sample.txt")
        self.assertEqual(second_response.status_code, 201)
        second = second_response.get_json()["file"]
        self.assertNotEqual(first["file_id"], second["file_id"])
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 2)

    def test_verify_unchanged_file(self):
        registered = self.register(ORIGINAL, "sample.txt").get_json()["file"]
        response = self.verify(ORIGINAL, "sample.txt")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["status"], "VERIFIED")
        self.assertEqual(body["integrity"], "INTACT")
        self.assertTrue(body["verification_id"].startswith("VER-"))
        self.assertEqual(body["file"]["file_id"], registered["file_id"])
        self.assertEqual(body["stored_hash"], body["current_hash"])
        self.assertEqual(body["current_hash"], sha256_bytes(ORIGINAL))

    def test_verify_modified_file_with_same_filename(self):
        self.register(ORIGINAL, "sample.txt")
        response = self.verify(MODIFIED, "sample.txt")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["status"], "TAMPERED")
        self.assertEqual(body["integrity"], "COMPROMISED")
        self.assertNotEqual(body["stored_hash"], body["current_hash"])
        self.assertEqual(body["current_hash"], sha256_bytes(MODIFIED))
        self.assertEqual(body["stored_hash"], sha256_bytes(ORIGINAL))

    def test_verify_unregistered_file(self):
        response = self.verify(ORIGINAL, "never_registered.txt")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["status"], "NOT_REGISTERED")
        self.assertEqual(body["integrity"], "UNKNOWN")
        self.assertEqual(body["filename"], "never_registered.txt")
        self.assertEqual(body["current_hash"], sha256_bytes(ORIGINAL))
        self.assertNotIn("file", body)

    def test_filename_verification_uses_the_most_recent_registration(self):
        original = self.register(ORIGINAL, "sample.txt").get_json()["file"]
        revised = self.register(MODIFIED, "sample.txt").get_json()["file"]

        latest = self.verify(MODIFIED, "sample.txt").get_json()
        self.assertEqual(latest["status"], "VERIFIED")
        self.assertEqual(latest["file"]["file_id"], revised["file_id"])

        older_bytes = self.verify(ORIGINAL, "sample.txt").get_json()
        self.assertEqual(older_bytes["status"], "TAMPERED")
        self.assertEqual(older_bytes["file"]["file_id"], revised["file_id"])

        # The specific File ID still checks the original registration.
        by_id = self.verify(ORIGINAL, "renamed.txt", file_id=original["file_id"]).get_json()
        self.assertEqual(by_id["status"], "VERIFIED")
        self.assertEqual(by_id["file"]["file_id"], original["file_id"])
        self.assertEqual(by_id["file"]["filename"], "sample.txt")

    def test_verify_by_unknown_file_id(self):
        body = self.verify(ORIGINAL, "sample.txt", file_id="FG-UNKNOWN").get_json()
        self.assertEqual(body["status"], "NOT_REGISTERED")
        history = self.client.get("/api/history").get_json()["history"]
        self.assertEqual(history[0]["status"], "NOT_REGISTERED")
        self.assertIsNone(history[0]["file_id"])

    def test_get_all_files(self):
        self.register(ORIGINAL, "older.txt")
        self.register(MODIFIED, "newer.txt")
        self.verify(ORIGINAL, "older.txt")

        response = self.client.get("/api/files")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["files"][0]["filename"], "newer.txt")
        self.assertIsNone(body["files"][0]["latest_status"])
        self.assertEqual(body["files"][1]["filename"], "older.txt")
        self.assertEqual(body["files"][1]["latest_status"], "VERIFIED")
        for item in body["files"]:
            self.assertIn("file_size_formatted", item)
            self.assertIn("sha256_hash", item)

    def test_get_file_details(self):
        registered = self.register(ORIGINAL, "sample.txt").get_json()["file"]
        self.verify(ORIGINAL, "sample.txt")
        self.verify(MODIFIED, "sample.txt")

        response = self.client.get("/api/files/" + registered["file_id"])
        self.assertEqual(response.status_code, 200)
        record = response.get_json()["file"]
        self.assertEqual(record["file_id"], registered["file_id"])
        self.assertEqual(record["verification_attempts"], 2)
        self.assertEqual(record["last_status"], "TAMPERED")
        self.assertIsNotNone(record["last_verified"])
        self.assertEqual(len(record["recent_verifications"]), 2)
        self.assertEqual(record["recent_verifications"][0]["status"], "TAMPERED")

    def test_file_not_found(self):
        response = self.client.get("/api/files/FG-MISSING")
        self.assertEqual(response.status_code, 404)
        body = response.get_json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "File ID not found.")

    def test_verification_history(self):
        self.register(ORIGINAL, "sample.txt")
        verified = self.verify(ORIGINAL, "sample.txt").get_json()
        self.verify(MODIFIED, "sample.txt")
        self.verify(ORIGINAL, "other.txt")

        all_history = self.client.get("/api/history")
        self.assertEqual(all_history.status_code, 200)
        body = all_history.get_json()
        self.assertEqual(body["count"], 3)
        self.assertEqual(body["history"][0]["status"], "NOT_REGISTERED")

        only_verified = self.client.get("/api/history?status=VERIFIED").get_json()
        self.assertEqual(only_verified["count"], 1)
        self.assertEqual(only_verified["history"][0]["status"], "VERIFIED")

        limited = self.client.get("/api/history?limit=1").get_json()
        self.assertEqual(limited["count"], 1)

        bad_status = self.client.get("/api/history?status=MAYBE")
        self.assertEqual(bad_status.status_code, 400)
        self.assertFalse(bad_status.get_json()["success"])

        one = self.client.get("/api/history/" + verified["verification_id"])
        self.assertEqual(one.status_code, 200)
        self.assertEqual(
            one.get_json()["verification"]["verification_id"],
            verified["verification_id"],
        )

        missing = self.client.get("/api/history/VER-MISSING")
        self.assertEqual(missing.status_code, 404)
        self.assertFalse(missing.get_json()["success"])

    def test_dashboard_stats(self):
        self.register(ORIGINAL, "sample.txt")
        self.verify(ORIGINAL, "sample.txt")
        self.verify(MODIFIED, "sample.txt")
        self.verify(ORIGINAL, "missing.txt")

        response = self.client.get("/api/dashboard")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["stats"]["total_files"], 1)
        self.assertEqual(body["stats"]["successful_verifications"], 1)
        self.assertEqual(body["stats"]["tampering_detected"], 1)
        self.assertEqual(body["stats"]["total_verifications"], 3)
        self.assertEqual(
            body["integrity_overview"],
            {"verified": 1, "tampered": 1, "not_registered": 1},
        )
        self.assertGreaterEqual(len(body["recent_activity"]), 1)
        self.assertLessEqual(len(body["recent_activity"]), 8)
        events = {item["event"] for item in body["recent_activity"]}
        self.assertIn("registration", events)
        self.assertIn("verification", events)

    def test_dashboard_activity_is_newest_first(self):
        self.register(ORIGINAL, "sample.txt")
        self.verify(ORIGINAL, "sample.txt")
        activity = self.client.get("/api/dashboard").get_json()["recent_activity"]
        self.assertEqual(activity[0]["status"], "VERIFIED")
        self.assertEqual(activity[1]["status"], "REGISTERED")
        self.assertGreater(activity[0]["timestamp"], activity[1]["timestamp"])

    def test_search(self):
        registered = self.register(ORIGINAL, "Internship_Certificate.txt").get_json()["file"]
        self.register(MODIFIED, "notes.txt")

        by_name = self.client.get("/api/files/search?q=certificate")
        self.assertEqual(by_name.status_code, 200)
        body = by_name.get_json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["files"][0]["file_id"], registered["file_id"])

        by_id = self.client.get(
            "/api/files/search?q=" + registered["file_id"].lower()
        ).get_json()
        self.assertEqual(by_id["count"], 1)
        self.assertEqual(by_id["files"][0]["filename"], "Internship_Certificate.txt")

        missing_query = self.client.get("/api/files/search")
        self.assertEqual(missing_query.status_code, 400)

    def test_search_treats_underscore_as_a_literal(self):
        self.register(ORIGINAL, "ab.txt")
        self.register(MODIFIED, "a_b.txt")
        body = self.client.get("/api/files/search?q=_").get_json()
        names = [item["filename"] for item in body["files"]]
        self.assertEqual(names, ["a_b.txt"])

    def test_missing_upload(self):
        for url in ("/api/files/register", "/api/files/verify"):
            response = self.client.post(url, data={})
            self.assertEqual(response.status_code, 400, url)
            body = response.get_json()
            self.assertFalse(body["success"])
            self.assertIn("file", body["error"].lower())

        empty_name = self.client.post(
            "/api/files/register",
            data={"file": (io.BytesIO(b"hello"), "")},
        )
        self.assertEqual(empty_name.status_code, 400)

    def test_secure_filename_blocks_path_traversal(self):
        response = self.register(ORIGINAL, "../../etc/passwd.txt")
        self.assertEqual(response.status_code, 201)
        stored = response.get_json()["file"]["filename"]
        self.assertNotIn("/", stored)
        self.assertNotIn("..", stored)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "etc")))

    def test_upload_is_not_saved_beside_the_database(self):
        before = set(os.listdir(self.tmp.name))
        self.register(ORIGINAL, "sample.txt")
        after = set(os.listdir(self.tmp.name))
        self.assertEqual(before, after)

    def test_delete_keeps_verification_history(self):
        registered = self.register(ORIGINAL, "sample.txt").get_json()["file"]
        verified = self.verify(ORIGINAL, "sample.txt").get_json()
        response = self.client.delete("/api/files/" + registered["file_id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["message"],
            "File registration removed successfully",
        )
        self.assertEqual(self.client.get("/api/files").get_json()["count"], 0)
        missing = self.client.get("/api/files/" + registered["file_id"])
        self.assertEqual(missing.status_code, 404)

        still_there = self.client.get("/api/history/" + verified["verification_id"])
        self.assertEqual(still_there.status_code, 200)
        self.assertEqual(still_there.get_json()["verification"]["status"], "VERIFIED")

        gone = self.client.delete("/api/files/" + registered["file_id"])
        self.assertEqual(gone.status_code, 404)

    def test_file_too_large(self):
        tiny = tempfile.TemporaryDirectory()
        self.addCleanup(tiny.cleanup)
        db_path = os.path.join(tiny.name, "tiny.db")
        app = create_app({"DATABASE_PATH": db_path, "MAX_FILE_SIZE": 32, "DEBUG": False})
        client = app.test_client()
        response = client.post(
            "/api/files/register",
            data={"file": (io.BytesIO(b"x" * 64), "big.txt")},
        )
        self.assertEqual(response.status_code, 413)
        body = response.get_json()
        self.assertFalse(body["success"])
        self.assertIn("too large", body["error"].lower())
        self.assertEqual(client.get("/api/files").get_json()["count"], 0)

    def test_seed_demo_is_opt_in_and_idempotent(self):
        import seed_demo

        seed_demo.seed(self.db_path, echo=False)
        first = self.client.get("/api/files").get_json()["count"]
        self.assertGreaterEqual(first, 3)
        history = self.client.get("/api/history").get_json()["count"]
        self.assertGreaterEqual(history, 3)

        seed_demo.seed(self.db_path, echo=False)
        second = self.client.get("/api/files").get_json()["count"]
        self.assertEqual(first, second)

    def test_other_file_types_are_accepted(self):
        samples = {
            "report.pdf": "PDF",
            "notes.docx": "DOCX",
            "photo.jpg": "JPG",
            "diagram.png": "PNG",
            "bundle.zip": "ZIP",
            "data.csv": "CSV",
            "main.py": "PY",
            "README": "UNKNOWN",
        }
        for name, expected_type in samples.items():
            response = self.register(b"bytes-for-" + name.encode("utf-8"), name)
            self.assertEqual(response.status_code, 201, name)
            self.assertEqual(response.get_json()["file"]["file_type"], expected_type)


if __name__ == "__main__":
    unittest.main()
