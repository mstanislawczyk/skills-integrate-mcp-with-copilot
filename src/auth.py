"""Teacher credential and session helpers."""

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import Cookie, HTTPException

TEACHER_CREDENTIALS_FILE = Path(__file__).with_name("teachers.json")
SESSION_COOKIE_NAME = "teacher_session"
SESSION_LIFETIME_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000
MIN_PASSWORD_HASH_ITERATIONS = 100_000
MAX_PASSWORD_HASH_ITERATIONS = 2_000_000


def hash_password(password: str) -> dict[str, str | int]:
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(password_hash).decode("ascii"),
        "iterations": PASSWORD_HASH_ITERATIONS,
    }


def load_teacher_credentials() -> list[dict[str, Any]]:
    try:
        credentials = json.loads(TEACHER_CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail="Teacher authentication is not configured.",
        ) from error

    if not isinstance(credentials, list):
        raise RuntimeError("Teacher credentials file must contain a JSON array.")

    usernames: set[str] = set()
    for credential in credentials:
        if not isinstance(credential, dict):
            raise RuntimeError("Each teacher credential must be a JSON object.")

        username = credential.get("username")
        salt = credential.get("salt")
        password_hash = credential.get("password_hash")
        iterations = credential.get("iterations")
        if (
            not isinstance(username, str)
            or not username.strip()
            or username in usernames
            or not isinstance(salt, str)
            or not isinstance(password_hash, str)
            or not isinstance(iterations, int)
            or isinstance(iterations, bool)
            or not MIN_PASSWORD_HASH_ITERATIONS
            <= iterations
            <= MAX_PASSWORD_HASH_ITERATIONS
        ):
            raise RuntimeError("Teacher credentials file has an invalid entry.")

        try:
            decoded_salt = base64.b64decode(salt, validate=True)
            decoded_hash = base64.b64decode(password_hash, validate=True)
        except ValueError as error:
            raise RuntimeError("Teacher credentials file has an invalid entry.") from error
        if len(decoded_salt) != 16 or len(decoded_hash) != hashlib.sha256().digest_size:
            raise RuntimeError("Teacher credentials file has an invalid entry.")

        usernames.add(username)

    return credentials


def verify_password(password: str, credential: dict[str, Any]) -> bool:
    salt = base64.b64decode(credential["salt"], validate=True)
    expected_hash = base64.b64decode(credential["password_hash"], validate=True)
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, credential["iterations"]
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def _session_secret() -> bytes | None:
    secret = os.environ.get("SESSION_SECRET")
    if secret is None or len(secret.encode("utf-8")) < 32:
        return None
    return secret.encode("utf-8")


def create_session_token(username: str) -> str:
    secret = _session_secret()
    if secret is None:
        raise HTTPException(
            status_code=503,
            detail="Teacher authentication is not configured.",
        )

    payload = json.dumps(
        {"sub": username, "exp": int(time.time()) + SESSION_LIFETIME_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(secret, encoded_payload.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"


def get_current_teacher(
    teacher_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str | None:
    secret = _session_secret()
    if secret is None or teacher_session is None:
        return None

    try:
        encoded_payload, encoded_signature = teacher_session.split(".", 1)
        supplied_signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        expected_signature = hmac.new(
            secret, encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None

        payload_bytes = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        )
        payload = json.loads(payload_bytes)
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("sub"), str)
            or not isinstance(payload.get("exp"), int)
            or payload["exp"] <= int(time.time())
        ):
            return None
        return payload["sub"]
    except (ValueError, UnicodeError):
        return None


def require_teacher(
    teacher_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> str:
    username = get_current_teacher(teacher_session)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required.")
    return username
