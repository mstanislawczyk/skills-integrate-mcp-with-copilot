"""Provision teacher credentials without storing plaintext passwords."""

import getpass
import json
import os
import sys

from auth import TEACHER_CREDENTIALS_FILE, hash_password, load_teacher_credentials


def main() -> None:
    username = input("Teacher username: ").strip()
    if not username:
        raise SystemExit("Username must not be empty.")

    password = getpass.getpass("Teacher password (at least 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    if TEACHER_CREDENTIALS_FILE.exists():
        credentials = load_teacher_credentials()
    else:
        credentials = []

    credential = {"username": username, **hash_password(password)}
    for index, existing in enumerate(credentials):
        if existing["username"] == username:
            credentials[index] = credential
            break
    else:
        credentials.append(credential)

    TEACHER_CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        TEACHER_CREDENTIALS_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as credential_file:
        json.dump(credentials, credential_file, indent=2)
        credential_file.write("\n")
    os.chmod(TEACHER_CREDENTIALS_FILE, 0o600)

    print(f"Credentials saved for {username}.")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, OSError, json.JSONDecodeError, RuntimeError) as error:
        print(f"Could not update teacher credentials: {error}", file=sys.stderr)
        raise SystemExit(1) from error
