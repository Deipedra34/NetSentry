"""Tests for the block management database pieces in :mod:`src.database`:
the blocked_ips migration, the audit log and the block history."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.database import AuditEntry, BlockedIP, Database

T0 = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)

# the blocked_ips table as v2.9.0 and earlier created it
OLD_SCHEMA = """
CREATE TABLE blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    event_type TEXT NOT NULL,
    rule_identifier TEXT NOT NULL
);
INSERT INTO blocked_ips (source_ip, blocked_at, expires_at, event_type, rule_identifier)
VALUES ('45.33.1.1', '2026-11-20T10:00:00+00:00', NULL, 'SYN_FLOOD', 'NetSentry_Block_45.33.1.1');
"""


def test_old_blocked_ips_table_is_migrated_in_place(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(OLD_SCHEMA)
    with Database(path) as db:
        (block,) = db.get_blocked_ips()
        # the existing row survives, as an automatic, applied block
        assert (block.source_ip, block.event_type) == ("45.33.1.1", "SYN_FLOOD")
        assert (block.source, block.created_by, block.reason, block.dry_run) == ("auto", None, "", False)
    # opening it again doesn't try to add the columns a second time
    with Database(path) as db:
        assert len(db.get_blocked_ips()) == 1


def test_manual_block_fields_round_trip(in_memory_db: Database) -> None:
    block = in_memory_db.add_blocked_ip(
        BlockedIP(
            "45.33.2.0/24", "MANUAL", "NetSentry_Block_45.33.2.0/24", blocked_at=T0,
            source="manual", created_by="alice", reason="scanner", dry_run=True,
        )
    )
    stored = in_memory_db.get_blocked_ip(block.id)  # type: ignore[arg-type]
    assert stored == block
    assert stored.to_dict()["source"] == "manual"
    assert in_memory_db.count_active_manual_blocks() == 1
    assert in_memory_db.get_blocked_ip(999) is None


def test_update_blocked_ip(in_memory_db: Database) -> None:
    block = in_memory_db.add_blocked_ip(BlockedIP("45.33.1.1", "SYN_FLOOD", "rule", blocked_at=T0))
    block.expires_at = T0 + timedelta(hours=2)
    block.source, block.created_by, block.reason = "manual", "alice", "keep it out"
    assert in_memory_db.update_blocked_ip(block) is True
    assert in_memory_db.get_blocked_ip(block.id) == block  # type: ignore[arg-type]
    assert in_memory_db.count_active_manual_blocks() == 1
    in_memory_db.remove_blocked_ip(block.id)  # type: ignore[arg-type]
    assert in_memory_db.update_blocked_ip(block) is False


# --- audit log ------------------------------------------------------------------


def _audit(db: Database, n: int, actor: str = "alice", action: str = "block", result: str = "success") -> None:
    db.add_audit_entry(
        AuditEntry(actor, action, f"45.33.1.{n}", result, details=f"entry {n}", timestamp=T0 + timedelta(minutes=n))
    )


def test_audit_entries_are_listed_newest_first_and_paged(in_memory_db: Database) -> None:
    for n in range(1, 8):
        _audit(in_memory_db, n)
    assert in_memory_db.count_audit_entries() == 7
    first = in_memory_db.get_audit_entries(limit=3)
    assert [e.target for e in first] == ["45.33.1.7", "45.33.1.6", "45.33.1.5"]
    third = in_memory_db.get_audit_entries(limit=3, offset=6)
    assert [e.target for e in third] == ["45.33.1.1"]
    assert first[0].to_dict()["details"] == "entry 7"


def test_audit_filters_by_action_and_actor(in_memory_db: Database) -> None:
    _audit(in_memory_db, 1, actor="alice", action="block")
    _audit(in_memory_db, 2, actor="bob", action="block", result="refused")
    _audit(in_memory_db, 3, actor="alice", action="unblock")
    _audit(in_memory_db, 4, actor="cli", action="change_duration")
    assert [e.target for e in in_memory_db.get_audit_entries(action="block")] == ["45.33.1.2", "45.33.1.1"]
    assert [e.target for e in in_memory_db.get_audit_entries(actor="alice")] == ["45.33.1.3", "45.33.1.1"]
    assert in_memory_db.count_audit_entries(action="block", actor="bob") == 1
    assert in_memory_db.list_audit_actors() == ["alice", "bob", "cli"]


def test_audit_pruning_removes_only_old_entries(in_memory_db: Database) -> None:
    for n in range(1, 6):
        _audit(in_memory_db, n)
    assert in_memory_db.prune_audit_entries(before=T0 + timedelta(minutes=3)) == 2
    assert [e.target for e in in_memory_db.get_audit_entries()] == ["45.33.1.5", "45.33.1.4", "45.33.1.3"]


def test_stored_text_is_kept_verbatim(in_memory_db: Database) -> None:
    # escaping is the page's job: the database keeps exactly what it's given
    _audit(in_memory_db, 1, actor="<script>alert(1)</script>")
    assert in_memory_db.get_audit_entries()[0].actor == "<script>alert(1)</script>"


# --- block history --------------------------------------------------------------


def test_block_history_records_lifted_blocks(in_memory_db: Database) -> None:
    block = in_memory_db.add_blocked_ip(
        BlockedIP("45.33.1.1", "MANUAL", "rule", blocked_at=T0, expires_at=T0 + timedelta(hours=1),
                  source="manual", created_by="alice", reason="scanner")
    )
    entry = in_memory_db.add_block_history(block, "unblocked", "bob", removed_at=T0 + timedelta(minutes=5))
    (stored,) = in_memory_db.get_block_history()
    assert stored == entry
    assert (stored.source_ip, stored.source, stored.reason, stored.created_by) == ("45.33.1.1", "manual", "scanner", "alice")
    assert (stored.outcome, stored.removed_by) == ("unblocked", "bob")
    assert stored.to_dict()["removed_at"] == (T0 + timedelta(minutes=5)).isoformat()


def test_block_history_is_paged_most_recent_first_and_pruned(in_memory_db: Database) -> None:
    for n in range(1, 6):
        block = BlockedIP(f"45.33.1.{n}", "SYN_FLOOD", "rule", blocked_at=T0)
        in_memory_db.add_block_history(block, "expired", "auto", removed_at=T0 + timedelta(hours=n))
    assert in_memory_db.count_block_history() == 5
    assert [e.source_ip for e in in_memory_db.get_block_history(limit=2)] == ["45.33.1.5", "45.33.1.4"]
    assert [e.source_ip for e in in_memory_db.get_block_history(limit=2, offset=4)] == ["45.33.1.1"]
    assert in_memory_db.prune_block_history(before=T0 + timedelta(hours=3)) == 2
    assert in_memory_db.count_block_history() == 3
