"""Manual blocks across restarts and expiry: they live in the blocked_ips
table, survive a restart, are lifted by the existing expiry mechanism
(AutoBlocker.maybe_check_expired), and old audit/history entries are
pruned at startup. No real firewall commands, no real sleeping."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import main
from src.auto_block import AutoBlocker
from src.block_management import BlockManager, ProtectedAddresses, prune_block_records
from src.config import Config
from src.database import AuditEntry, BlockedIP, Database
from tests.auth_helpers import FakeClock


def manager(db: Database, dry_run: bool = False, clock: FakeClock | None = None) -> BlockManager:
    config = Config()
    config.auto_block.dry_run = dry_run
    return BlockManager(config, db, protected_addresses=lambda: ProtectedAddresses(), clock=clock or FakeClock())


def live_blocker(db: Database) -> AutoBlocker:
    config = Config()
    config.auto_block.dry_run = False
    return AutoBlocker(config, db)


def test_manual_block_survives_a_restart_and_can_be_unblocked(tmp_path: Path) -> None:
    path = tmp_path / "netsentry.db"
    with patch("src.auto_block.platform.system", return_value="Windows"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as run:
        with Database(path) as db:
            created = manager(db).block("45.33.12.7", 60, "scanner", actor="alice").block
        # "restart": a fresh Database and BlockManager on the same file
        with Database(path) as db:
            (block,) = db.get_blocked_ips()
            assert (block.id, block.source, block.created_by, block.reason, block.dry_run) == (
                created.id, "manual", "alice", "scanner", False,
            )
            assert block.expires_at == created.expires_at
            manager(db).unblock(block.id, actor="bob")  # type: ignore[arg-type]
            assert db.get_blocked_ips() == []
            assert db.get_block_history()[0].removed_by == "bob"
    # the rule was removed by the name stored with the block
    assert run.call_args.args[0] == ["netsh", "advfirewall", "firewall", "delete", "rule", "name=NetSentry_Block_45.33.12.7"]


def test_reblocking_after_a_restart_does_not_duplicate(tmp_path: Path) -> None:
    path = tmp_path / "netsentry.db"
    with Database(path) as db:
        manager(db, dry_run=True).block("45.33.12.7", 60)
    with Database(path) as db:
        manager(db, dry_run=True).block("45.33.12.7", 120)
        assert len(db.get_blocked_ips()) == 1


def test_audit_log_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "netsentry.db"
    with Database(path) as db:
        manager(db, dry_run=True).block("45.33.12.7", 60, actor="alice")
    with Database(path) as db:
        assert [(e.actor, e.action) for e in db.get_audit_entries()] == [("alice", "block")]


def test_expired_manual_block_is_lifted_by_the_existing_expiry_check(in_memory_db: Database) -> None:
    clock = FakeClock(datetime(2026, 11, 20, 10, tzinfo=timezone.utc).timestamp())
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as run:
        manager(in_memory_db, clock=clock).block("45.33.12.7", 15, actor="alice")
        # the expiry check compares against the real clock: the block expired long ago
        live_blocker(in_memory_db).maybe_check_expired(now=1_000_000.0)
    assert run.call_args.args[0] == ["iptables", "-D", "INPUT", "-s", "45.33.12.7", "-j", "DROP"]
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_block_history()
    assert (entry.source, entry.outcome, entry.removed_by, entry.created_by) == ("manual", "expired", "auto", "alice")


def test_expired_dry_run_manual_block_never_touches_the_firewall(in_memory_db: Database) -> None:
    clock = FakeClock(datetime(2026, 11, 20, 10, tzinfo=timezone.utc).timestamp())
    manager(in_memory_db, dry_run=True, clock=clock).block("45.33.12.7", 15)
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run") as run:
        live_blocker(in_memory_db).maybe_check_expired(now=1_000_000.0)
    run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []
    assert in_memory_db.get_block_history()[0].dry_run is True


def test_unexpired_and_permanent_manual_blocks_stay(in_memory_db: Database) -> None:
    now = datetime.now(timezone.utc)
    clock = FakeClock(now.timestamp())
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as run:
        blocks = manager(in_memory_db, clock=clock)
        blocks.block("45.33.12.7", 60)
        blocks.block("45.33.12.8", 0)
        run.reset_mock()
        live_blocker(in_memory_db).maybe_check_expired(now=1_000_000.0)
    run.assert_not_called()
    assert len(in_memory_db.get_blocked_ips()) == 2


def _old_and_new_records(db: Database, now: datetime) -> None:
    for days in (400, 10):
        when = now - timedelta(days=days)
        db.add_audit_entry(AuditEntry("alice", "block", f"45.33.12.{days % 250}", "success", timestamp=when))
        block = BlockedIP(f"45.33.12.{days % 250}", "MANUAL", "rule", blocked_at=when, source="manual")
        db.add_block_history(block, "expired", "auto", removed_at=when)


def test_prune_removes_only_entries_older_than_audit_keep_days(in_memory_db: Database) -> None:
    now = datetime(2026, 11, 22, tzinfo=timezone.utc)
    _old_and_new_records(in_memory_db, now)
    assert prune_block_records(in_memory_db, 365, now=now) == (1, 1)
    assert in_memory_db.count_audit_entries() == 1
    assert in_memory_db.count_block_history() == 1
    assert prune_block_records(in_memory_db, 0, now=now + timedelta(days=1000)) == (0, 0)  # 0 keeps everything


def test_startup_prunes_old_entries(tmp_path: Path) -> None:
    path = tmp_path / "netsentry.db"
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        f"database:\n  path: '{path.as_posix()}'\nblock_management:\n  audit_keep_days: 30\n", encoding="utf-8"
    )
    with Database(path) as db:
        _old_and_new_records(db, datetime.now(timezone.utc))
    with patch("main.setup_logging"), patch("main.NetworkSniffer") as sniffer:
        assert main.main(["-c", str(config_file), "--list-blocks"]) == 0
    sniffer.assert_not_called()
    with Database(path) as db:
        assert db.count_audit_entries() == 1
        assert db.count_block_history() == 1


@pytest.mark.parametrize("dry_run", [True, False])
def test_dry_run_flag_is_respected_exactly_like_the_automatic_path(in_memory_db: Database, dry_run: bool) -> None:
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as run:
        manager(in_memory_db, dry_run=dry_run).block("45.33.12.7", 60)
    assert run.called is (not dry_run)
    assert in_memory_db.get_blocked_ips()[0].dry_run is dry_run
