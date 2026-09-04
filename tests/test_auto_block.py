"""Unit tests for :mod:`src.auto_block`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.auto_block import AutoBlocker
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
