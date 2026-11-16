"""Dashboard authentication helpers: password hashing, account rules, the
session secret key, the login limiter, CSRF tokens and the access-control
decorators the Flask app in src/web.py uses.

Only uses what Flask already ships (werkzeug.security for hashing, Flask's
signed session cookie for sessions) -- no Flask-Login or similar. All of
this is inactive unless `auth.enabled` is set in config.yaml.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash


@lru_cache(maxsize=None)
def password_hash_method() -> str:
    """The strongest hashing method this werkzeug/Python build supports:
    scrypt when hashlib has it (needs OpenSSL 1.1+, which is nearly
    everywhere), PBKDF2-SHA256 otherwise."""
    try:
        hashlib.scrypt(b"probe", salt=b"probe", n=2, r=8, p=1)
    except (AttributeError, ValueError):
        return "pbkdf2:sha256"
    return "scrypt"


def hash_password(password: str) -> str:
    """A salted hash of password, in werkzeug's "method$salt$hash" format,
    for the users table. The plaintext is never stored or logged."""
    return generate_password_hash(password, method=password_hash_method())


@lru_cache(maxsize=None)
def _dummy_hash() -> str:
    """A throwaway hash, computed once, to check against when a login names
    a user that doesn't exist -- see verify_password()."""
    return hash_password("netsentry-dummy-password-never-matches")


def verify_password(password_hash: Optional[str], password: str) -> bool:
    """True if password matches password_hash. Pass None as the hash for a
    username that doesn't exist: the password is still checked (against a
    dummy hash) so a login for a missing user takes about as long as one
    for a real user with a wrong password, and response timing doesn't
    reveal which usernames exist."""
    if password_hash is None:
        check_password_hash(_dummy_hash(), password)
        return False
    try:
        return check_password_hash(password_hash, password)
    except ValueError:  # malformed hash in the table -- treat as no match
        return False
