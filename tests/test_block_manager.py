"""Tests for manual block, unblock and duration changes
(:class:`src.block_management.BlockManager`). The firewall is never really
touched: subprocess and the platform are mocked, time comes from a fake
clock."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator, List
from unittest.mock import MagicMock, patch

import pytest

from src.block_management import (
    BlockFailed,
    BlockManager,
    BlockRefused,
    ProtectedAddresses,
)
from src.config import Config
from src.database import BlockedIP, Database
from tests.auth_helpers import FakeClock

NOW = datetime.fromtimestamp(FakeClock().now, timezone.utc)


def make_manager(db: Database, dry_run: bool = True, clock: FakeClock | None = None, **settings: object) -> BlockManager:
    config = Config()
    config.auto_block.dry_run = dry_run
    config.whitelist = ["45.33.7.0/24"]
    for key, value in settings.items():
        setattr(config.block_management, key, value)
    protected = ProtectedAddresses.from_strings(["45.33.9.9"], ["45.33.9.1"])
    return BlockManager(config, db, protected_addresses=lambda: protected, clock=clock or FakeClock())


@pytest.fixture()
def firewall() -> Iterator[MagicMock]:
    """A Linux host whose firewall commands all succeed."""
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)
        yield run


def commands(run: MagicMock) -> List[List[str]]:
    return [call.args[0] for call in run.call_args_list]


# --- block --------------------------------------------------------------------------------


def test_dry_run_block_is_recorded_but_never_calls_subprocess(in_memory_db: Database, firewall: MagicMock) -> None:
    result = make_manager(in_memory_db, dry_run=True).block("45.33.12.7", 15, "scanner", actor="alice")
    firewall.assert_not_called()
    assert result.applied is False
    assert result.message.startswith("Dry run:")
    (block,) = in_memory_db.get_blocked_ips()
    assert (block.source_ip, block.source, block.created_by, block.reason, block.dry_run) == (
        "45.33.12.7", "manual", "alice", "scanner", True,
    )
    assert block.expires_at == NOW + timedelta(minutes=15)


def test_live_block_runs_the_command_as_an_argument_list(in_memory_db: Database, firewall: MagicMock) -> None:
    result = make_manager(in_memory_db, dry_run=False).block("45.33.12.0/24", 60, actor="alice")
    assert commands(firewall) == [["iptables", "-A", "INPUT", "-s", "45.33.12.0/24", "-j", "DROP"]]
    assert "shell" not in firewall.call_args.kwargs
    assert result.applied is True
    (block,) = in_memory_db.get_blocked_ips()
    assert (block.rule_identifier, block.dry_run, block.event_type) == ("NetSentry_Block_45.33.12.0/24", False, "MANUAL")


def test_windows_block_uses_netsh(in_memory_db: Database) -> None:
    with patch("src.auto_block.platform.system", return_value="Windows"), patch("src.auto_block.subprocess.run") as run:
        make_manager(in_memory_db, dry_run=False).block("45.33.12.7", 60)
    assert commands(run)[0][:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]
    assert "remoteip=45.33.12.7" in commands(run)[0]


def test_default_and_permanent_durations(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, default_duration_minutes=30)
    assert manager.block("45.33.12.7").block.expires_at == NOW + timedelta(minutes=30)
    assert manager.block("45.33.12.8", 0).block.expires_at is None


@pytest.mark.parametrize(
    "settings, minutes, rule",
    [
        ({"allow_permanent": False}, 0, "permanent_not_allowed"),
        ({"allow_permanent": False, "default_duration_minutes": 0}, None, "permanent_not_allowed"),
        ({"max_duration_minutes": 120}, 121, "duration_too_long"),
        ({}, -1, "invalid_duration"),
        ({}, True, "invalid_duration"),
    ],
)
def test_duration_limits(in_memory_db: Database, firewall: MagicMock, settings: dict, minutes: object, rule: str) -> None:
    with pytest.raises(BlockRefused) as excinfo:
        make_manager(in_memory_db, **settings).block("45.33.12.7", minutes)  # type: ignore[arg-type]
    assert excinfo.value.rule == rule
    assert in_memory_db.get_blocked_ips() == []


def test_reblocking_updates_the_entry_instead_of_duplicating_it(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    first = manager.block("45.33.12.7", 15, "first", actor="alice").block
    second = manager.block("45.33.12.7", 60, "", actor="bob")
    assert len(commands(firewall)) == 1  # the rule is only ever added once
    (block,) = in_memory_db.get_blocked_ips()
    assert block.id == first.id
    assert (block.created_by, block.reason) == ("bob", "first")
    assert block.expires_at == NOW + timedelta(minutes=60)
    assert "already blocked" in second.message


def test_reblocking_a_dry_run_entry_in_live_mode_applies_it(in_memory_db: Database, firewall: MagicMock) -> None:
    make_manager(in_memory_db, dry_run=True).block("45.33.12.7", 15)
    make_manager(in_memory_db, dry_run=False).block("45.33.12.7", 15)
    assert commands(firewall) == [["iptables", "-A", "INPUT", "-s", "45.33.12.7", "-j", "DROP"]]
    assert in_memory_db.get_blocked_ips()[0].dry_run is False


def test_reblocking_an_automatic_block_takes_it_over(in_memory_db: Database, firewall: MagicMock) -> None:
    in_memory_db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "NetSentry_Block_45.33.12.7"))
    make_manager(in_memory_db, dry_run=False).block("45.33.12.7", 0, "keep out", actor="alice")
    firewall.assert_not_called()
    (block,) = in_memory_db.get_blocked_ips()
    assert (block.source, block.event_type, block.expires_at, block.reason) == ("manual", "SYN_FLOOD", None, "keep out")


def test_max_manual_blocks_cap(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, max_manual_blocks=2)
    in_memory_db.add_blocked_ip(BlockedIP("45.33.50.1", "SYN_FLOOD", "rule"))  # automatic: doesn't count
    manager.block("45.33.12.1")
    manager.block("45.33.12.2")
    with pytest.raises(BlockRefused) as excinfo:
        manager.block("45.33.12.3")
    assert excinfo.value.rule == "max_manual_blocks"
    manager.block("45.33.12.2", 120)  # re-blocking an existing entry isn't a new block
    assert in_memory_db.count_active_manual_blocks() == 2


def test_safety_rules_apply(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    for target, requester, rule in [
        ("192.168.1.1", None, "private"),
        ("45.33.7.7", None, "whitelist"),
        ("45.33.9.9", None, "own_address"),
        ("45.33.9.1", None, "gateway"),
        ("45.33.100.0/24", "45.33.100.5", "requester"),
        ("45.0.0.0/8", None, "range_too_large"),
    ]:
        with pytest.raises(BlockRefused) as excinfo:
            manager.block(target, requester_ip=requester)
        assert excinfo.value.rule == rule
    firewall.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_injection_in_target_or_reason_never_reaches_the_firewall_command(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    with pytest.raises(BlockRefused):
        manager.block("45.33.12.7; iptables -F")
    firewall.assert_not_called()
    manager.block("45.33.12.7", 15, reason="x\"; rm -rf / ; echo \"\n-j ACCEPT")
    (command,) = commands(firewall)
    # the reason is never part of a command, only the normalized address is
    assert command == ["iptables", "-A", "INPUT", "-s", "45.33.12.7", "-j", "DROP"]
    assert in_memory_db.get_blocked_ips()[0].reason == 'x"; rm -rf / ; echo " -j ACCEPT'


def test_firewall_failure_on_block_records_nothing_and_reports_the_error(in_memory_db: Database, firewall: MagicMock) -> None:
    firewall.side_effect = PermissionError("you must be root")
    with pytest.raises(BlockFailed, match="you must be root"):
        make_manager(in_memory_db, dry_run=False).block("45.33.12.7", 15, actor="alice")
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_audit_entries()
    assert (entry.action, entry.result) == ("block", "failed")


def test_unsupported_os_fails_cleanly(in_memory_db: Database) -> None:
    with patch("src.auto_block.platform.system", return_value="Plan9"), patch("src.auto_block.subprocess.run") as run:
        with pytest.raises(BlockFailed, match="isn't supported"):
            make_manager(in_memory_db, dry_run=False).block("45.33.12.7", 15)
    run.assert_not_called()


# --- unblock ------------------------------------------------------------------------------


def test_block_then_unblock_round_trip(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    block = manager.block("45.33.12.7", 15, actor="alice").block
    result = manager.unblock(block.id, actor="bob")  # type: ignore[arg-type]
    assert commands(firewall) == [
        ["iptables", "-A", "INPUT", "-s", "45.33.12.7", "-j", "DROP"],
        ["iptables", "-D", "INPUT", "-s", "45.33.12.7", "-j", "DROP"],
    ]
    assert result.applied is True
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_block_history()
    assert (entry.source_ip, entry.outcome, entry.removed_by, entry.created_by) == ("45.33.12.7", "unblocked", "bob", "alice")


def test_unblocking_an_automatic_block_uses_its_stored_rule(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "NetSentry_Block_45.33.12.7"))
    block = in_memory_db.get_blocked_ips()[0]
    with patch("src.auto_block.platform.system", return_value="Windows"), patch("src.auto_block.subprocess.run") as run:
        make_manager(in_memory_db, dry_run=False).unblock(block.id, "alice")  # type: ignore[arg-type]
    assert commands(run) == [["netsh", "advfirewall", "firewall", "delete", "rule", "name=NetSentry_Block_45.33.12.7"]]
    assert in_memory_db.get_block_history()[0].source == "auto"


def test_firewall_failure_on_unblock_keeps_the_record(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    block = manager.block("45.33.12.7", 15).block
    firewall.side_effect = OSError("iptables: Bad rule")
    with pytest.raises(BlockFailed, match="still blocked"):
        manager.unblock(block.id, "alice")  # type: ignore[arg-type]
    assert [b.source_ip for b in in_memory_db.get_blocked_ips()] == ["45.33.12.7"]
    assert in_memory_db.count_block_history() == 0
    assert in_memory_db.get_audit_entries()[0].result == "failed"


def test_dry_run_entries_are_removed_without_a_firewall_command(in_memory_db: Database, firewall: MagicMock) -> None:
    block = make_manager(in_memory_db, dry_run=True).block("45.33.12.7", 15).block
    make_manager(in_memory_db, dry_run=False).unblock(block.id, "alice")  # type: ignore[arg-type]
    firewall.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_unblock_in_dry_run_never_calls_subprocess(in_memory_db: Database, firewall: MagicMock) -> None:
    in_memory_db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "NetSentry_Block_45.33.12.7"))
    block = in_memory_db.get_blocked_ips()[0]
    result = make_manager(in_memory_db, dry_run=True).unblock(block.id, "alice")  # type: ignore[arg-type]
    firewall.assert_not_called()
    assert result.message.startswith("Dry run:")
    assert in_memory_db.get_audit_entries()[0].result == "dry_run"


def test_unblock_missing_block_is_refused(in_memory_db: Database, firewall: MagicMock) -> None:
    with pytest.raises(BlockRefused) as excinfo:
        make_manager(in_memory_db).unblock(42, "alice")
    assert excinfo.value.rule == "not_found"


def test_find_active_normalizes_the_target(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db)
    manager.block("2606:4700:12::7", 15)
    found = manager.find_active("2606:4700:0012:0000:0000:0000:0000:0007")
    assert found is not None and found.source_ip == "2606:4700:12::7"
    assert manager.find_active("45.33.12.99") is None


def test_bulk_unblock_audits_each_entry_separately(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    ids = [manager.block(f"45.33.12.{n}", 15).block.id for n in (1, 2)]
    results = manager.unblock_many([*ids, 999], actor="alice")  # type: ignore[list-item]
    assert [(ok) for _, ok, _ in results] == [True, True, False]
    unblocks = in_memory_db.get_audit_entries(action="unblock")
    assert sorted((e.target, e.result) for e in unblocks) == [
        ("#999", "refused"), ("45.33.12.1", "success"), ("45.33.12.2", "success"),
    ]


# --- change duration -----------------------------------------------------------------------


def test_change_duration_counts_from_now(in_memory_db: Database, firewall: MagicMock) -> None:
    clock = FakeClock()
    manager = make_manager(in_memory_db, clock=clock)
    block = manager.block("45.33.12.7", 60).block
    clock.advance(45 * 60)  # 45 minutes later...
    manager.change_duration(block.id, 30, "alice")  # type: ignore[arg-type]
    # ...30 minutes from *now*, not from when the block started
    assert in_memory_db.get_blocked_ip(block.id).expires_at == NOW + timedelta(minutes=75)  # type: ignore[arg-type, union-attr]
    manager.change_duration(block.id, 5, "alice")  # shortening works the same way
    assert in_memory_db.get_blocked_ip(block.id).expires_at == NOW + timedelta(minutes=50)  # type: ignore[arg-type, union-attr]
    manager.change_duration(block.id, 0, "alice")
    assert in_memory_db.get_blocked_ip(block.id).expires_at is None  # type: ignore[arg-type, union-attr]
    firewall.assert_not_called()  # expiry is NetSentry's bookkeeping, not a firewall change


def test_change_duration_applies_the_same_limits(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, allow_permanent=False, max_duration_minutes=120)
    block = manager.block("45.33.12.7", 60).block
    for minutes, rule in [(0, "permanent_not_allowed"), (121, "duration_too_long"), (None, "invalid_duration")]:
        with pytest.raises(BlockRefused) as excinfo:
            manager.change_duration(block.id, minutes, "alice")  # type: ignore[arg-type]
        assert excinfo.value.rule == rule
    assert in_memory_db.get_blocked_ip(block.id).expires_at == NOW + timedelta(minutes=60)  # type: ignore[arg-type, union-attr]


def test_change_duration_works_on_automatic_blocks(in_memory_db: Database, firewall: MagicMock) -> None:
    block = in_memory_db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "NetSentry_Block_45.33.12.7"))
    make_manager(in_memory_db).change_duration(block.id, 1440, "alice")  # type: ignore[arg-type]
    assert in_memory_db.get_blocked_ip(block.id).expires_at == NOW + timedelta(days=1)  # type: ignore[arg-type, union-attr]


# --- audit log ------------------------------------------------------------------------------


def test_successful_and_refused_actions_are_audited(in_memory_db: Database, firewall: MagicMock) -> None:
    manager = make_manager(in_memory_db, dry_run=False)
    block = manager.block("45.33.12.7", 15, "scanner", actor="alice").block
    with pytest.raises(BlockRefused):
        manager.block("10.0.0.5", actor="mallory\n<b>x</b>")
    manager.change_duration(block.id, 30, "alice")  # type: ignore[arg-type]
    manager.unblock(block.id, "alice")  # type: ignore[arg-type]
    entries = list(reversed(in_memory_db.get_audit_entries()))
    assert [(e.actor, e.action, e.target, e.result) for e in entries] == [
        ("alice", "block", "45.33.12.7", "success"),
        ("mallory <b>x</b>", "block", "10.0.0.5", "refused"),
        ("alice", "change_duration", "45.33.12.7", "success"),
        ("alice", "unblock", "45.33.12.7", "success"),
    ]
    assert "reason: scanner" in entries[0].details
    assert "refused by rule 'private'" in entries[1].details


def test_local_addresses_are_looked_up_lazily_and_cached(in_memory_db: Database) -> None:
    lookups = []

    def lookup() -> ProtectedAddresses:
        lookups.append(1)
        return ProtectedAddresses()

    clock = FakeClock()
    manager = BlockManager(Config(), in_memory_db, protected_addresses=lookup, clock=clock)
    assert lookups == []
    manager.block("45.33.12.1")
    manager.block("45.33.12.2")
    assert len(lookups) == 1
    clock.advance(301)
    manager.block("45.33.12.3")
    assert len(lookups) == 2
