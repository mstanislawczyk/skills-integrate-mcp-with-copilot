import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from src import auth


class AuthTests(unittest.TestCase):
    def test_password_hash_verifies_only_matching_password(self):
        credential = auth.hash_password("correct horse battery staple")

        self.assertTrue(auth.verify_password("correct horse battery staple", credential))
        self.assertFalse(auth.verify_password("not the password", credential))

    def test_load_credentials_rejects_duplicate_usernames(self):
        credential = {"username": "teacher", **auth.hash_password("long password")}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "teachers.json"
            path.write_text(json.dumps([credential, credential]), encoding="utf-8")
            with patch.object(auth, "TEACHER_CREDENTIALS_FILE", path):
                with self.assertRaises(RuntimeError):
                    auth.load_teacher_credentials()

    def test_session_token_requires_valid_signature_and_secret(self):
        with patch.dict(os.environ, {"SESSION_SECRET": "s" * 32}):
            token = auth.create_session_token("teacher")
            self.assertEqual(auth.get_current_teacher(token), "teacher")
            self.assertIsNone(auth.get_current_teacher(token + "tampered"))
            self.assertIsNone(auth.get_current_teacher("é.invalid"))

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(HTTPException) as error:
                auth.create_session_token("teacher")
            self.assertEqual(error.exception.status_code, 503)
            self.assertIsNone(auth.get_current_teacher(token))

    def test_require_teacher_rejects_missing_session(self):
        with self.assertRaises(HTTPException) as error:
            auth.require_teacher(None)
        self.assertEqual(error.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
