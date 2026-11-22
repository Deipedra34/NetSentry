"""Tests for main.py's manual blocking commands: --block, --unblock,
--list-blocks and --audit-log. They never start packet capture, and never
run a real firewall command (subprocess and the platform are mocked)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest

import main
from src.block_management import ProtectedAddresses
from src.database import Database


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(f"database:\n  path: '{(tmp_path / 'netsentry.db').as_posix()}'\n", encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def no_capture() -> Iterator[None]:
    """Fails loudly if anything starts capture or builds detectors; keeps
    setup_logging from reconfiguring the test run's logging, and this
    machine's real addresses out of the safety checks."""
    with patch("main.NetworkSniffer") as sniffer, patch("main.build_detectors") as detectors, \
            patch("main.setup_logging"), \
            patch("src.block_management._local_protected_addresses", return_value=ProtectedAddresses()):
        yield
        sniffer.assert_not_called()
        detectors.assert_not_called()


def run(config_file: Path, *args: str) -> int:
    return main.main(["-c", str(config_file), *args])


def database(config_file: Path) -> Database:
    return Database(config_file.parent / "netsentry.db")


def test_block_in_dry_run(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("src.auto_block.subprocess.run") as subprocess_run:
        assert run(config_file, "--block", "45.33.12.7", "--duration", "30", "--reason", "scanner") == 0
    subprocess_run.assert_not_called()
    out = capsys.readouterr().out
    assert "Dry run: 45.33.12.7 recorded as blocked for 30 minutes" in out
    assert "--auto-block-live" in out
    with database(config_file) as db:
        (block,) = db.get_blocked_ips()
        assert (block.created_by, block.reason, block.dry_run) == ("cli", "scanner", True)
        assert db.get_audit_entries()[0].actor == "cli"


def test_block_live_runs_the_firewall_command_as_a_list(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as subprocess_run:
        assert run(config_file, "--auto-block-live", "--block", "45.33.12.0/24", "--duration", "0") == 0
    assert subprocess_run.call_args.args[0] == ["iptables", "-A", "INPUT", "-s", "45.33.12.0/24", "-j", "DROP"]
    assert "Blocked 45.33.12.0/24 permanently." in capsys.readouterr().out


def test_live_firewall_failure_mentions_privileges(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", side_effect=PermissionError("Operation not permitted")):
        assert run(config_file, "--auto-block-live", "--block", "45.33.12.7") == 1
    err = capsys.readouterr().err
    assert "Operation not permitted" in err
    assert "root" in err
    with database(config_file) as db:
        assert db.get_blocked_ips() == []


@pytest.mark.parametrize("target, rule", [("10.0.0.1", "private"), ("127.0.0.1", "loopback"), ("45.33.12.7; reboot", "invalid")])
def test_refused_block(config_file: Path, capsys: pytest.CaptureFixture[str], target: str, rule: str) -> None:
    with patch("src.auto_block.subprocess.run") as subprocess_run:
        assert run(config_file, "--block", target) == 1
    subprocess_run.assert_not_called()
    assert f"Refused ({rule})" in capsys.readouterr().err
    with database(config_file) as db:
        assert db.get_audit_entries()[0].result == "refused"


def test_whitelisted_ip_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        f"database:\n  path: '{(tmp_path / 'netsentry.db').as_posix()}'\nwhitelist:\n  - '45.33.7.0/24'\n",
        encoding="utf-8",
    )
    assert run(config_file, "--block", "45.33.7.7") == 1
    assert "Refused (whitelist)" in capsys.readouterr().err


def test_unblock_and_list(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--block", "45.33.12.7", "--reason", "scanner") == 0
    assert run(config_file, "--list-blocks") == 0
    listing = capsys.readouterr().out
    assert "45.33.12.7" in listing and "dry run, not applied" in listing and "reason: scanner" in listing
    assert run(config_file, "--unblock", "45.33.12.7") == 0
    assert "Removed 45.33.12.7" in capsys.readouterr().out
    assert run(config_file, "--list-blocks") == 0
    assert "No IPs are currently blocked." in capsys.readouterr().out


def test_unblock_unknown_target_is_refused_and_audited(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--unblock", "45.33.12.99") == 1
    assert "Refused (not_found)" in capsys.readouterr().err
    with database(config_file) as db:
        (entry,) = db.get_audit_entries()
        assert (entry.actor, entry.action, entry.result) == ("cli", "unblock", "refused")


def test_audit_log_with_limit(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for n in range(1, 5):
        run(config_file, "--block", f"45.33.12.{n}")
    capsys.readouterr()
    assert run(config_file, "--audit-log", "--limit", "2") == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert "45.33.12.4" in lines[0] and "45.33.12.3" in lines[1]  # newest first


@pytest.mark.parametrize(
    "args, message",
    [
        (["--duration", "5"], "only apply to --block"),
        (["--reason", "x"], "only apply to --block"),
        (["--limit", "5"], "only applies to --audit-log"),
        (["--audit-log", "--limit", "0"], "at least 1"),
    ],
)
def test_argument_validation(config_file: Path, capsys: pytest.CaptureFixture[str], args: list, message: str) -> None:
    assert run(config_file, *args) == 1
    assert message in capsys.readouterr().err


def test_commands_are_mutually_exclusive(config_file: Path) -> None:
    with pytest.raises(SystemExit):
        run(config_file, "--block", "45.33.12.7", "--unblock", "45.33.12.7")
