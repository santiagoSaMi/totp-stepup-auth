"""One-off migration: encrypt the TOTP secrets already stored in plain text.

    .venv/bin/python scripts/encrypt_existing_secrets.py --dry-run
    .venv/bin/python scripts/encrypt_existing_secrets.py

Steps, all in one transaction (either everything is applied or nothing is):
1. Rename mfa_configs.secret_base32 -> secret_encrypted (if not done yet).
2. Encrypt every value that isn't in the "v1:..." format yet.
3. Add the CHECK constraint that rejects any unencrypted value from now on.
4. Decrypt every row back to check the key works before committing.

Safe to run more than once. Users keep their phones: the secret itself
doesn't change, only how it is stored.
"""

import argparse
import sys

import psycopg

from app.config import get_settings
from app.security.secret_box import decrypt_secret, encrypt_secret, is_encrypted


def columns(conn: psycopg.Connection) -> set[str]:
    rows = conn.execute(
        "select column_name from information_schema.columns"
        " where table_schema = 'public' and table_name = 'mfa_configs'"
    ).fetchall()
    return {r[0] for r in rows}


def has_constraint(conn: psycopg.Connection, name: str) -> bool:
    return conn.execute("select 1 from pg_constraint where conname = %s", (name,)).fetchone() is not None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="show what would change, then roll back")
    args = parser.parse_args()

    settings = get_settings()  # fails early if MFA_ENCRYPTION_KEY is missing or invalid
    with psycopg.connect(settings.database_url) as conn:
        with conn.transaction():
            if "secret_base32" in columns(conn):
                conn.execute("alter table mfa_configs rename column secret_base32 to secret_encrypted")
                print("renamed column secret_base32 -> secret_encrypted")

            rows = conn.execute(
                "select user_id, secret_encrypted from mfa_configs where secret_encrypted is not null"
            ).fetchall()
            pending = [(user_id, value) for user_id, value in rows if not is_encrypted(value)]
            print(f"{len(rows)} secrets found, {len(pending)} in plain text")

            for user_id, plain in pending:
                conn.execute(
                    "update mfa_configs set secret_encrypted = %s, updated_at = now() where user_id = %s",
                    (encrypt_secret(plain, user_id), user_id),
                )

            if not has_constraint(conn, "secret_is_encrypted"):
                conn.execute(
                    "alter table mfa_configs add constraint secret_is_encrypted"
                    " check (secret_encrypted is null or secret_encrypted like 'v1:%')"
                )
                print("added constraint secret_is_encrypted")

            # Round-trip check before committing: every row must decrypt with this key.
            for user_id, value in conn.execute(
                "select user_id, secret_encrypted from mfa_configs where secret_encrypted is not null"
            ).fetchall():
                decrypt_secret(value, user_id)
            print(f"verified: all {len(rows)} secrets decrypt with the current key")

            if args.dry_run:
                raise psycopg.Rollback()  # undoes the whole transaction; psycopg swallows it

    print("dry run: nothing was changed" if args.dry_run else "done: secrets are now encrypted at rest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
