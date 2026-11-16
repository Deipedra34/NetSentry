"""Tests for the users table and user functions in :mod:`src.database`."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.database import Database, Event


def test_create_and_get_user(in_memory_db: Database) -> None:
    user = in_memory_db.create_user("alice", "hash-a", "admin")
    assert user.id is not None
    assert user.disabled is False
    assert user.last_login_at is None

    fetched = in_memory_db.get_user(user.id)
    assert fetched is not None
    assert (fetched.username, fetched.password_hash, fetched.role) == ("alice", "hash-a", "admin")
    assert fetched.created_at == user.created_at


def test_get_missing_user_returns_none(in_memory_db: Database) -> None:
    assert in_memory_db.get_user(42) is None
    assert in_memory_db.get_user_by_username("nobody") is None


def test_usernames_are_case_insensitive(in_memory_db: Database) -> None:
    in_memory_db.create_user("Alice", "hash", "viewer")
    fetched = in_memory_db.get_user_by_username("aLiCe")
    assert fetched is not None
    assert fetched.username == "Alice"  # stored as entered
    with pytest.raises(ValueError, match="already exists"):
        in_memory_db.create_user("ALICE", "hash", "viewer")


def test_invalid_role_is_rejected(in_memory_db: Database) -> None:
    with pytest.raises(ValueError):
        in_memory_db.create_user("alice", "hash", "superuser")
    user = in_memory_db.create_user("alice", "hash", "viewer")
    with pytest.raises(ValueError):
        in_memory_db.set_user_role(user.id, "root")
    assert in_memory_db.get_user(user.id).role == "viewer"


def test_list_users_sorted_by_username(in_memory_db: Database) -> None:
    for name in ("carol", "Bob", "alice"):
        in_memory_db.create_user(name, "hash", "viewer")
    assert [u.username for u in in_memory_db.list_users()] == ["alice", "Bob", "carol"]


def test_update_password_role_and_disabled(in_memory_db: Database) -> None:
    user = in_memory_db.create_user("alice", "old", "viewer")
    assert in_memory_db.update_user_password(user.id, "new")
    assert in_memory_db.set_user_role(user.id, "admin")
    assert in_memory_db.set_user_disabled(user.id, True)

    fetched = in_memory_db.get_user(user.id)
    assert (fetched.password_hash, fetched.role, fetched.disabled) == ("new", "admin", True)

    assert in_memory_db.set_user_disabled(user.id, False)
    assert in_memory_db.get_user(user.id).disabled is False


def test_updates_on_missing_user_return_false(in_memory_db: Database) -> None:
    assert in_memory_db.update_user_password(99, "x") is False
    assert in_memory_db.set_user_role(99, "admin") is False
    assert in_memory_db.set_user_disabled(99, True) is False
    assert in_memory_db.delete_user(99) is False


def test_update_last_login(in_memory_db: Database) -> None:
    user = in_memory_db.create_user("alice", "hash", "viewer")
    when = datetime(2026, 11, 16, 9, 30, tzinfo=timezone.utc)
    assert in_memory_db.update_last_login(user.id, when)
    assert in_memory_db.get_user(user.id).last_login_at == when


def test_delete_user(in_memory_db: Database) -> None:
    user = in_memory_db.create_user("alice", "hash", "viewer")
    assert in_memory_db.delete_user(user.id) is True
    assert in_memory_db.get_user(user.id) is None
    assert in_memory_db.count_users() == 0


def test_counts(in_memory_db: Database) -> None:
    assert in_memory_db.count_users() == 0
    assert in_memory_db.count_enabled_admins() == 0
    admin = in_memory_db.create_user("root1", "hash", "admin")
    in_memory_db.create_user("root2", "hash", "admin")
    in_memory_db.create_user("watcher", "hash", "viewer")
    assert in_memory_db.count_users() == 3
    assert in_memory_db.count_enabled_admins() == 2
    in_memory_db.set_user_disabled(admin.id, True)
    assert in_memory_db.count_enabled_admins() == 1


def test_password_hash_never_in_repr_or_dict(in_memory_db: Database) -> None:
    user = in_memory_db.create_user("alice", "scrypt:secret-hash", "admin")
    assert "secret-hash" not in repr(user)
    assert "password_hash" not in user.to_dict()
    assert user.to_dict()["username"] == "alice"


def test_users_table_added_to_existing_database(tmp_path: Path) -> None:
    """A database written by an older version (no users table) opens
    cleanly, keeps its events, and gains an empty users table."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL
        );
        INSERT INTO events (timestamp, source_ip, event_type, details)
        VALUES ('2026-11-01T00:00:00+00:00', '10.0.0.1', 'PORT_SCAN', 'old event');
        """
    )
    conn.commit()
    conn.close()

    with Database(path) as db:
        assert db.count_events() == 1
        assert db.count_users() == 0
        db.create_user("alice", "hash", "admin")
        db.log_event(Event(event_type="ARP_SPOOF", source_ip="10.0.0.2", details="new"))

    # and reopening an already-migrated database is a no-op
    with Database(path) as db:
        assert db.count_events() == 2
        assert [u.username for u in db.list_users()] == ["alice"]
