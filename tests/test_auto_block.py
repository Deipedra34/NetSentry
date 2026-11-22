"""Unit tests for :mod:`src.auto_block`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.auto_block import (
    AutoBlocker,
    build_block_command,
    build_unblock_command,
    normalize_target,
    rule_identifier_for,
    run_firewall_command,
)
from src.config import Config
from src.database import BlockedIP, Database, Event


def _make_event(event_type: str = "SYN_FLOOD", source_ip: str = "45.33.12.9") -> Event:
    return Event(
        event_type=event_type,
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _live_config(min_severity: str = "high") -> Config:
    config = Config()
    config.auto_block.enabled = True
    config.auto_block.dry_run = False
    config.auto_block.min_severity = min_severity
    return config


def test_whitelisted_ip_is_never_blocked(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db, whitelist=["45.33.12.9"])

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_whitelisted_cidr_range_is_never_blocked(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db, whitelist=["45.33.12.0/24"])

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_private_and_local_ips_are_never_blocked(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)

    for private_ip in ("192.168.1.50", "10.0.0.5", "172.16.0.9", "127.0.0.1", "169.254.1.1"):
        with patch("src.auto_block.subprocess.run") as mock_run:
            blocker.maybe_block(_make_event(source_ip=private_ip))
        mock_run.assert_not_called()

    assert in_memory_db.get_blocked_ips() == []


def test_dry_run_never_calls_subprocess(in_memory_db: Database) -> None:
    config = _live_config()
    config.auto_block.dry_run = True
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event())

    mock_run.assert_not_called()
    # Nothing was actually blocked, so nothing should be tracked either.
    assert in_memory_db.get_blocked_ips() == []


def test_disabled_auto_block_never_calls_subprocess(in_memory_db: Database) -> None:
    config = Config()  # auto_block.enabled defaults to False
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event())

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_event_below_min_severity_is_not_blocked(in_memory_db: Database) -> None:
    config = _live_config(min_severity="critical")
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event(event_type="PORT_SCAN"))

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_windows_uses_netsh_command(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.platform.system", return_value="Windows"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))

    mock_run.assert_called_once()
    command = mock_run.call_args[0][0]
    assert command[0] == "netsh"
    assert "advfirewall" in command
    assert any("remoteip=45.33.12.9" in part for part in command)

    blocked = in_memory_db.get_blocked_ips()
    assert len(blocked) == 1
    assert blocked[0].source_ip == "45.33.12.9"


def test_linux_uses_iptables_command(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))

    mock_run.assert_called_once()
    command = mock_run.call_args[0][0]
    assert command == ["iptables", "-A", "INPUT", "-s", "45.33.12.9", "-j", "DROP"]

    blocked = in_memory_db.get_blocked_ips()
    assert len(blocked) == 1
    assert blocked[0].source_ip == "45.33.12.9"


def test_unsupported_os_skips_blocking_without_crashing(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.platform.system", return_value="Plan9"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event())

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def test_subprocess_failure_is_caught_and_logged(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)

    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run", side_effect=FileNotFoundError("iptables not found")):
        blocker.maybe_block(_make_event())  # must not raise

    assert in_memory_db.get_blocked_ips() == []


def test_already_blocked_ip_is_not_blocked_again(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)
    in_memory_db.add_blocked_ip(
        BlockedIP(
            source_ip="45.33.12.9",
            event_type="SYN_FLOOD",
            rule_identifier="NetSentry_Block_45.33.12.9",
        )
    )

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))

    mock_run.assert_not_called()
    assert len(in_memory_db.get_blocked_ips()) == 1


def test_expired_block_is_removed_and_unblocked(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)
    expired = in_memory_db.add_blocked_ip(
        BlockedIP(
            source_ip="45.33.12.9",
            event_type="SYN_FLOOD",
            rule_identifier="NetSentry_Block_45.33.12.9",
            blocked_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )

    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        blocker.maybe_check_expired(now=1_000_000.0)

    mock_run.assert_called_once_with(
        ["iptables", "-D", "INPUT", "-s", "45.33.12.9", "-j", "DROP"],
        check=True, capture_output=True, text=True, timeout=10,
    )
    assert in_memory_db.get_blocked_ips() == []
    assert in_memory_db.get_active_block(expired.source_ip) is None


def test_permanent_block_never_expires(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)
    in_memory_db.add_blocked_ip(
        BlockedIP(
            source_ip="45.33.12.9",
            event_type="SYN_FLOOD",
            rule_identifier="NetSentry_Block_45.33.12.9",
            blocked_at=datetime.now(timezone.utc) - timedelta(days=30),
            expires_at=None,
        )
    )

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_check_expired(now=1_000_000.0)

    mock_run.assert_not_called()
    assert len(in_memory_db.get_blocked_ips()) == 1


def test_expiry_check_is_throttled(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)
    in_memory_db.add_blocked_ip(
        BlockedIP(
            source_ip="45.33.12.9",
            event_type="SYN_FLOOD",
            rule_identifier="NetSentry_Block_45.33.12.9",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )

    with patch("src.auto_block.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        blocker.maybe_check_expired(now=10.0)
        blocker.maybe_check_expired(now=20.0)  # both well within the 60s throttle window

    mock_run.assert_not_called()
    assert len(in_memory_db.get_blocked_ips()) == 1


def test_dry_run_expired_block_never_calls_subprocess(in_memory_db: Database) -> None:
    config = _live_config()
    blocker = AutoBlocker(config, in_memory_db)
    in_memory_db.add_blocked_ip(
        BlockedIP(
            source_ip="45.33.12.9",
            event_type="SYN_FLOOD",
            rule_identifier="NetSentry_Block_45.33.12.9",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    config.auto_block.dry_run = True

    with patch("src.auto_block.subprocess.run") as mock_run:
        blocker.maybe_check_expired(now=1_000_000.0)

    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


# --- shared firewall code path: automatic behavior unchanged --------------------------


def _expired_block(**overrides: object) -> BlockedIP:
    values: dict = dict(
        source_ip="45.33.12.9",
        event_type="SYN_FLOOD",
        rule_identifier="NetSentry_Block_45.33.12.9",
        blocked_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    values.update(overrides)
    return BlockedIP(**values)  # type: ignore[arg-type]


def test_ipv4_commands_are_exactly_what_they_were() -> None:
    with patch("src.auto_block.platform.system", return_value="Windows"):
        assert build_block_command("45.33.12.9") == [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=NetSentry_Block_45.33.12.9", "dir=in", "action=block", "remoteip=45.33.12.9",
        ]
        assert build_unblock_command("45.33.12.9") == [
            "netsh", "advfirewall", "firewall", "delete", "rule", "name=NetSentry_Block_45.33.12.9",
        ]
    with patch("src.auto_block.platform.system", return_value="Linux"):
        assert build_block_command("45.33.12.9") == ["iptables", "-A", "INPUT", "-s", "45.33.12.9", "-j", "DROP"]
        assert build_unblock_command("45.33.12.9") == ["iptables", "-D", "INPUT", "-s", "45.33.12.9", "-j", "DROP"]
    assert rule_identifier_for("45.33.12.9") == "NetSentry_Block_45.33.12.9"


def test_ipv6_targets_use_ip6tables_on_linux() -> None:
    with patch("src.auto_block.platform.system", return_value="Linux"):
        assert build_block_command("2606:4700::1")[0] == "ip6tables"  # type: ignore[index]
        assert build_unblock_command("2606:4700::1")[0] == "ip6tables"  # type: ignore[index]


def test_commands_are_only_ever_built_from_valid_targets() -> None:
    for bad in ("45.33.12.9; reboot", "$(id)", "45.33.12.9 dir=out", ""):
        with pytest.raises(ValueError):
            build_block_command(bad)
    assert normalize_target(" 45.33.12.9 ") == "45.33.12.9"
    # a stored rule identifier that isn't one NetSentry wrote is never used
    with pytest.raises(ValueError):
        build_unblock_command("45.33.12.9", "NetSentry_Block_45.33.12.9 & del C:\\")


def test_run_firewall_command_never_uses_a_shell_and_reports_failures() -> None:
    with patch("src.auto_block.subprocess.run") as mock_run:
        assert run_firewall_command(["iptables", "-L"]) is None
    args, kwargs = mock_run.call_args
    assert args == (["iptables", "-L"],)
    assert "shell" not in kwargs
    with patch("src.auto_block.subprocess.run", side_effect=FileNotFoundError("iptables not found")):
        assert "iptables not found" in (run_firewall_command(["iptables", "-L"]) or "")


def test_automatic_block_rows_are_marked_automatic(in_memory_db: Database) -> None:
    blocker = AutoBlocker(_live_config(), in_memory_db)
    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)):
        blocker.maybe_block(_make_event(source_ip="45.33.12.9"))
    (blocked,) = in_memory_db.get_blocked_ips()
    assert (blocked.source, blocked.created_by, blocked.reason, blocked.dry_run) == ("auto", None, "", False)
    assert blocked.rule_identifier == "NetSentry_Block_45.33.12.9"


def test_dry_run_still_records_nothing(in_memory_db: Database) -> None:
    config = _live_config()
    config.auto_block.dry_run = True
    with patch("src.auto_block.subprocess.run") as mock_run:
        AutoBlocker(config, in_memory_db).maybe_block(_make_event(source_ip="45.33.12.9"))
    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []
    assert in_memory_db.count_block_history() == 0


def test_expired_block_moves_to_history(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(_expired_block())
    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)):
        AutoBlocker(_live_config(), in_memory_db).maybe_check_expired(now=1_000_000.0)
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_block_history()
    assert (entry.source_ip, entry.outcome, entry.removed_by, entry.source) == ("45.33.12.9", "expired", "auto", "auto")


def test_failed_unblock_keeps_the_block_and_writes_no_history(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(_expired_block())
    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run", side_effect=PermissionError("not root")):
        AutoBlocker(_live_config(), in_memory_db).maybe_check_expired(now=1_000_000.0)
    assert len(in_memory_db.get_blocked_ips()) == 1
    assert in_memory_db.count_block_history() == 0


def test_expired_dry_run_block_is_lifted_without_a_firewall_command_even_in_live_mode(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(_expired_block(source="manual", created_by="alice", dry_run=True))
    with patch("src.auto_block.platform.system", return_value="Linux"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        AutoBlocker(_live_config(), in_memory_db).maybe_check_expired(now=1_000_000.0)
    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_block_history()
    assert (entry.outcome, entry.dry_run, entry.created_by) == ("expired", True, "alice")


def test_malformed_stored_rule_identifier_is_left_tracked(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(_expired_block(rule_identifier="something else entirely"))
    with patch("src.auto_block.platform.system", return_value="Windows"), \
         patch("src.auto_block.subprocess.run") as mock_run:
        AutoBlocker(_live_config(), in_memory_db).maybe_check_expired(now=1_000_000.0)
    mock_run.assert_not_called()
    assert len(in_memory_db.get_blocked_ips()) == 1
