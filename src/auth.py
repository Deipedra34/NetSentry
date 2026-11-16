"""Dashboard authentication helpers: password hashing, account rules, the
session secret key, the login limiter, CSRF tokens and the access-control
decorators the Flask app in src/web.py uses.

Only uses what Flask already ships (werkzeug.security for hashing, Flask's
signed session cookie for sessions) -- no Flask-Login or similar. All of
this is inactive unless `auth.enabled` is set in config.yaml.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlsplit

from flask import request, session
from werkzeug.security import check_password_hash, generate_password_hash

from src.database import Database, User

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
# admin: everything, including user management. viewer: read-only dashboard,
# charts, events and reports.
ROLES: Tuple[str, ...] = (ROLE_ADMIN, ROLE_VIEWER)

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9._-]{3,32}", re.ASCII)
# hashing is deliberately slow, so cap the input -- nobody types more than
# this, and a multi-megabyte "password" shouldn't tie up a worker
MAX_PASSWORD_LENGTH = 1024

# bytes of randomness in a freshly generated session secret key; anything
# shorter found on disk is refused rather than silently used
SECRET_KEY_BYTES = 32

# CSRF: one random token per session, sent back by every state-changing
# request as a form field (HTML forms) or a header (fetch() calls)
CSRF_SESSION_KEY = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class AccountError(ValueError):
    """An account change that was refused; the message is safe to show to
    the admin making the change (CLI or user management page)."""


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


def validate_username(username: str) -> str:
    """Returns username if it's 3-32 letters, digits, dots, dashes or
    underscores; raises AccountError otherwise."""
    if not USERNAME_PATTERN.fullmatch(username or ""):
        raise AccountError(
            "Usernames must be 3 to 32 characters: letters, digits, dot, dash or underscore."
        )
    return username


def validate_password(password: str, username: str, min_length: int) -> None:
    """Raises AccountError unless password is at least min_length
    characters (and at most MAX_PASSWORD_LENGTH) and isn't the username."""
    if len(password) < min_length:
        raise AccountError(f"Passwords must be at least {min_length} characters long.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AccountError(f"Passwords must be at most {MAX_PASSWORD_LENGTH} characters long.")
    if password.casefold() == username.casefold():
        raise AccountError("The password must not be the same as the username.")


def validate_role(role: str) -> str:
    """Returns role if it's one of ROLES; raises AccountError otherwise."""
    if role not in ROLES:
        raise AccountError(f"Unknown role {role!r}, expected one of: {', '.join(ROLES)}.")
    return role


def _require_user(database: Database, username: str) -> User:
    user = database.get_user_by_username(username)
    if user is None:
        raise AccountError(f"No user named {username!r}.")
    return user


def _is_last_enabled_admin(database: Database, user: User) -> bool:
    return user.role == ROLE_ADMIN and not user.disabled and database.count_enabled_admins() <= 1


def create_account(
    database: Database, username: str, password: str, role: str, min_password_length: int
) -> User:
    """Validates and creates an account (shared by the CLI and the user
    management page). Raises AccountError if anything's off."""
    validate_username(username)
    validate_role(role)
    validate_password(password, username, min_password_length)
    if database.get_user_by_username(username) is not None:
        raise AccountError(f"A user named {username!r} already exists.")
    try:
        return database.create_user(username, hash_password(password), role)
    except ValueError as exc:  # lost a race with another create
        raise AccountError(f"A user named {username!r} already exists.") from exc


def set_account_password(
    database: Database, username: str, password: str, min_password_length: int
) -> User:
    """Validates and stores a new password for an existing account."""
    user = _require_user(database, username)
    validate_password(password, user.username, min_password_length)
    database.update_user_password(user.id, hash_password(password))  # type: ignore[arg-type]
    return user


def set_account_role(database: Database, username: str, role: str) -> User:
    """Changes an account's role. Refuses to demote the last enabled admin,
    so there's always someone left who can manage users."""
    validate_role(role)
    user = _require_user(database, username)
    if role != ROLE_ADMIN and _is_last_enabled_admin(database, user):
        raise AccountError(f"{user.username!r} is the last enabled admin and cannot be demoted.")
    database.set_user_role(user.id, role)  # type: ignore[arg-type]
    user.role = role
    return user


def set_account_disabled(
    database: Database, username: str, disabled: bool, acting_user_id: Optional[int] = None
) -> User:
    """Disables or re-enables an account. Refuses to disable the last
    enabled admin, or (from the dashboard) the acting admin's own account."""
    user = _require_user(database, username)
    if disabled:
        if acting_user_id is not None and user.id == acting_user_id:
            raise AccountError("You cannot disable your own account.")
        if _is_last_enabled_admin(database, user):
            raise AccountError(f"{user.username!r} is the last enabled admin and cannot be disabled.")
    database.set_user_disabled(user.id, disabled)  # type: ignore[arg-type]
    user.disabled = disabled
    return user


def delete_account(
    database: Database, username: str, acting_user_id: Optional[int] = None
) -> None:
    """Deletes an account. Refuses to delete the last enabled admin, or
    (from the dashboard) the acting admin's own account."""
    user = _require_user(database, username)
    if acting_user_id is not None and user.id == acting_user_id:
        raise AccountError("You cannot delete your own account while signed in.")
    if _is_last_enabled_admin(database, user):
        raise AccountError(f"{user.username!r} is the last enabled admin and cannot be deleted.")
    database.delete_user(user.id)  # type: ignore[arg-type]


def load_or_create_secret_key(path: str | Path) -> bytes:
    """The key Flask signs session cookies with. Created on first start as
    SECRET_KEY_BYTES random bytes at path (owner read/write only, 0600,
    where the OS supports it), then read back on every later start so
    sessions survive a restart. Deleting the file signs everyone out.
    Raises RuntimeError if an existing file is too short to be a real key.
    The key itself is never logged."""
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(SECRET_KEY_BYTES)
        try:
            # O_EXCL: if two processes race on first start, only one writes
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
            try:
                os.chmod(path, 0o600)  # in case the umask got in the way
            except OSError:
                pass
            return key

    key = path.read_bytes()
    if len(key) < SECRET_KEY_BYTES:
        raise RuntimeError(
            f"The session secret key at {path} is shorter than {SECRET_KEY_BYTES} bytes; "
            "delete the file to have a new one generated."
        )
    return key


class LoginLimiter:
    """Locks out login attempts after too many failures, in memory.

    Failures are counted per key -- the login view passes one key for the
    username and one for the client IP (see limiter_keys()). Once a key
    collects max_failures failures within lockout_seconds, it's locked for
    lockout_seconds; while any of a request's keys is locked, the login is
    refused without even checking the password. A lockout always expires on
    its own (nothing extends it -- refused attempts aren't counted), so
    nobody can use it to lock an admin out for good, only to slow them down.

    Holds at most max_entries keys: when full, expired entries go first,
    then the least recently touched ones, so a flood of made-up usernames
    can't grow memory without bound. clock is injectable for tests.
    """

    def __init__(
        self,
        max_failures: int,
        lockout_seconds: float,
        clock: Callable[[], float] = time.time,
        max_entries: int = 10_000,
    ) -> None:
        self.max_failures = max(1, int(max_failures))
        self.lockout_seconds = float(lockout_seconds)
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        # key -> (failure timestamps within the window, locked until)
        self._entries: "OrderedDict[str, Tuple[List[float], float]]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def _is_stale(self, entry: Tuple[List[float], float], now: float) -> bool:
        failures, locked_until = entry
        return locked_until <= now and all(now - t >= self.lockout_seconds for t in failures)

    def is_locked(self, *keys: str) -> bool:
        """True while any of keys is locked out."""
        now = self._clock()
        with self._lock:
            return any(
                key in self._entries and self._entries[key][1] > now for key in keys
            )

    def record_failure(self, *keys: str) -> None:
        """Counts one failed login against each of keys, locking any key that
        reaches max_failures within the window."""
        now = self._clock()
        with self._lock:
            for key in keys:
                failures, locked_until = self._entries.pop(key, ([], 0.0))
                failures = [t for t in failures if now - t < self.lockout_seconds]
                failures.append(now)
                if len(failures) >= self.max_failures:
                    failures, locked_until = [], now + self.lockout_seconds
                self._entries[key] = (failures, locked_until)
            self._evict(now)

    def reset(self, *keys: str) -> None:
        """Forgets the failures for keys (e.g. a username after it logs in)."""
        with self._lock:
            for key in keys:
                self._entries.pop(key, None)

    def _evict(self, now: float) -> None:
        if len(self._entries) <= self.max_entries:
            return
        for key in [k for k, entry in self._entries.items() if self._is_stale(entry, now)]:
            del self._entries[key]
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)


def limiter_keys(username: str, client_ip: Optional[str]) -> Tuple[str, str]:
    """The LoginLimiter keys for a login attempt: the username (case-folded,
    whether or not it exists) and the client IP."""
    return f"user:{username.casefold()}", f"ip:{client_ip or 'unknown'}"


def csrf_token() -> str:
    """This session's CSRF token, created on first use. Templates put it in
    a hidden csrf_token field on every form that changes something."""
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = rotate_csrf_token()
    return token


def rotate_csrf_token() -> str:
    """Replaces this session's CSRF token with a fresh one (on login)."""
    token = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = token
    return token


def csrf_check_needed() -> bool:
    """True for request methods that change state and so need a token."""
    return request.method in STATE_CHANGING_METHODS


def csrf_token_valid() -> bool:
    """True if the current request carries this session's CSRF token, in
    the form field or the header. Always False when the session has no
    token yet (e.g. a forged POST from a fresh browser)."""
    expected = session.get(CSRF_SESSION_KEY)
    sent = request.form.get(CSRF_FORM_FIELD) or request.headers.get(CSRF_HEADER)
    if not expected or not sent:
        return False
    return secrets.compare_digest(str(sent), str(expected))


def safe_next_url(target: Optional[str], default: str = "/") -> str:
    """target if it's a local path on this dashboard ("/", "/api/report?x=1"),
    default otherwise. Used for the login page's ?next= so a crafted link
    can't bounce someone to another site after they sign in: anything with
    a scheme or host, a protocol-relative "//host", a backslash (browsers
    treat a backslash like a slash, so "/" + "\\host" means "//host") or a
    control character is refused."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return default
    if "\\" in target or any(ord(char) < 32 or ord(char) == 127 for char in target):
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return default
    return target
