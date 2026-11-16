"""Tests for account validation and last-admin protection in :mod:`src.auth`."""

from __future__ import annotations

import pytest

from src import auth
from src.auth import AccountError
from src.database import Database

PASSWORD = "a-long-enough-password"


def _make(db: Database, username: str, role: str = "viewer") -> None:
    auth.create_account(db, username, PASSWORD, role, min_password_length=12)


@pytest.mark.parametrize("username", ["abc", "alice", "a.b-c_d", "A" * 32, "user123"])
def test_valid_usernames(username: str) -> None:
    assert auth.validate_username(username) == username


@pytest.mark.parametrize(
    "username", ["", "ab", "A" * 33, "with space", "semi;colon", "émile", "a/b", "name\n"]
)
def test_invalid_usernames(username: str) -> None:
    with pytest.raises(AccountError):
        auth.validate_username(username)


def test_password_length_rules() -> None:
    auth.validate_password("x" * 12, "alice", min_length=12)
    with pytest.raises(AccountError, match="at least 12"):
        auth.validate_password("x" * 11, "alice", min_length=12)
    with pytest.raises(AccountError, match="at most"):
        auth.validate_password("x" * (auth.MAX_PASSWORD_LENGTH + 1), "alice", min_length=12)


def test_password_equal_to_username_is_rejected() -> None:
    with pytest.raises(AccountError, match="same as the username"):
        auth.validate_password("Administrator", "administrator", min_length=8)


def test_create_account_hashes_password(in_memory_db: Database) -> None:
    user = auth.create_account(in_memory_db, "alice", PASSWORD, "admin", min_password_length=12)
    stored = in_memory_db.get_user(user.id)
    assert stored.password_hash != PASSWORD
    assert auth.verify_password(stored.password_hash, PASSWORD)


def test_create_account_validates(in_memory_db: Database) -> None:
    with pytest.raises(AccountError):
        auth.create_account(in_memory_db, "a", PASSWORD, "admin", 12)
    with pytest.raises(AccountError, match="Unknown role"):
        auth.create_account(in_memory_db, "alice", PASSWORD, "root", 12)
    with pytest.raises(AccountError, match="at least"):
        auth.create_account(in_memory_db, "alice", "short", "admin", 12)
    assert in_memory_db.count_users() == 0


def test_create_account_rejects_duplicate_in_any_case(in_memory_db: Database) -> None:
    _make(in_memory_db, "alice")
    with pytest.raises(AccountError, match="already exists"):
        _make(in_memory_db, "ALICE")


def test_set_account_password(in_memory_db: Database) -> None:
    _make(in_memory_db, "alice")
    auth.set_account_password(in_memory_db, "alice", "another-good-password", 12)
    stored = in_memory_db.get_user_by_username("alice")
    assert auth.verify_password(stored.password_hash, "another-good-password")
    assert not auth.verify_password(stored.password_hash, PASSWORD)
    with pytest.raises(AccountError, match="same as the username"):
        auth.set_account_password(in_memory_db, "alice", "ALICE", 3)
    with pytest.raises(AccountError, match="No user"):
        auth.set_account_password(in_memory_db, "bob", "another-good-password", 12)


def test_last_admin_cannot_be_demoted_disabled_or_deleted(in_memory_db: Database) -> None:
    _make(in_memory_db, "root", "admin")
    with pytest.raises(AccountError, match="last enabled admin"):
        auth.set_account_role(in_memory_db, "root", "viewer")
    with pytest.raises(AccountError, match="last enabled admin"):
        auth.set_account_disabled(in_memory_db, "root", True)
    with pytest.raises(AccountError, match="last enabled admin"):
        auth.delete_account(in_memory_db, "root")
    user = in_memory_db.get_user_by_username("root")
    assert (user.role, user.disabled) == ("admin", False)


def test_admin_can_be_changed_when_another_enabled_admin_exists(in_memory_db: Database) -> None:
    _make(in_memory_db, "root", "admin")
    _make(in_memory_db, "root2", "admin")
    auth.set_account_role(in_memory_db, "root", "viewer")
    assert in_memory_db.get_user_by_username("root").role == "viewer"
    # root2 is now the last one
    with pytest.raises(AccountError):
        auth.delete_account(in_memory_db, "root2")


def test_disabled_admin_does_not_count(in_memory_db: Database) -> None:
    _make(in_memory_db, "root", "admin")
    _make(in_memory_db, "sleeper", "admin")
    auth.set_account_disabled(in_memory_db, "sleeper", True)
    with pytest.raises(AccountError, match="last enabled admin"):
        auth.set_account_disabled(in_memory_db, "root", True)
    # a disabled admin itself can always be removed
    auth.delete_account(in_memory_db, "sleeper")


def test_cannot_delete_or_disable_own_account(in_memory_db: Database) -> None:
    _make(in_memory_db, "root", "admin")
    _make(in_memory_db, "root2", "admin")
    me = in_memory_db.get_user_by_username("root")
    with pytest.raises(AccountError, match="your own account"):
        auth.delete_account(in_memory_db, "root", acting_user_id=me.id)
    with pytest.raises(AccountError, match="your own account"):
        auth.set_account_disabled(in_memory_db, "root", True, acting_user_id=me.id)
    auth.delete_account(in_memory_db, "root2", acting_user_id=me.id)
    assert in_memory_db.get_user_by_username("root2") is None


def test_viewer_changes(in_memory_db: Database) -> None:
    _make(in_memory_db, "root", "admin")
    _make(in_memory_db, "watcher")
    auth.set_account_disabled(in_memory_db, "watcher", True)
    assert in_memory_db.get_user_by_username("watcher").disabled is True
    auth.set_account_disabled(in_memory_db, "watcher", False)
    auth.set_account_role(in_memory_db, "watcher", "admin")
    assert in_memory_db.get_user_by_username("watcher").role == "admin"
    with pytest.raises(AccountError, match="Unknown role"):
        auth.set_account_role(in_memory_db, "watcher", "owner")
    auth.delete_account(in_memory_db, "watcher")
    assert in_memory_db.count_users() == 1
