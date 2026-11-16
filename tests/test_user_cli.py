"""Tests for main.py's dashboard user commands (--create-user, --list-users,
...): they work from the database alone, prompt for passwords with getpass,
apply the account rules, and never start packet capture."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, List
from unittest.mock import MagicMock, patch

import pytest

import main
from src import auth
from src.database import Database

PASSWORD = "a-long-enough-password"


@pytest.fixture()
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "netsentry.db"  # data/ doesn't exist yet


@pytest.fixture()
def config_file(tmp_path: Path, database_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"database:\n  path: '{database_path.as_posix()}'\n"
        f"logging:\n  file: '{(tmp_path / 'netsentry.log').as_posix()}'\n"
        "auth:\n  enabled: true\n  min_password_length: 12\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def no_capture() -> Iterator[MagicMock]:
    """Fails loudly if anything tries to start capture, build detectors or
    the dashboard, and keeps setup_logging from reconfiguring logging."""
    with patch("main.NetworkSniffer") as sniffer, patch("main.build_detectors") as detectors, \
            patch("main.run_web_dashboard") as web, patch("main.setup_logging"):
        yield sniffer
        sniffer.assert_not_called()
        detectors.assert_not_called()
        web.assert_not_called()


def run(config_file: Path, *args: str, passwords: List[str] | None = None) -> int:
    with patch("main.getpass", side_effect=list(passwords or [])) as prompt:
        code = main.main(["-c", str(config_file), *args])
    assert prompt.call_count == len(passwords or [])
    return code


def users(database_path: Path) -> dict:
    with Database(database_path) as db:
        return {u.username: u for u in db.list_users()}


def test_create_user_prompts_twice_and_hashes(
    config_file: Path, database_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD]) == 0
    assert "Created admin user 'alice'" in capsys.readouterr().out
    alice = users(database_path)["alice"]
    assert alice.role == "admin"
    assert alice.password_hash != PASSWORD
    assert auth.verify_password(alice.password_hash, PASSWORD)


def test_create_user_needs_role(config_file: Path, database_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--create-user", "alice") == 1
    assert "--role" in capsys.readouterr().err
    assert users(database_path) == {}


def test_role_without_create_user_is_an_error(config_file: Path) -> None:
    assert run(config_file, "--role", "admin") == 1


def test_create_user_mismatched_confirmation(config_file: Path, database_path: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--create-user", "alice", "--role", "admin",
               passwords=[PASSWORD, PASSWORD + "x"]) == 1
    assert "don't match" in capsys.readouterr().err
    assert users(database_path) == {}


def test_create_user_validates(config_file: Path, database_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--create-user", "alice", "--role", "admin", passwords=["short", "short"]) == 1
    assert "at least 12" in capsys.readouterr().err
    # a bad username is refused before any password prompt
    assert run(config_file, "--create-user", "a b", "--role", "admin") == 1
    assert users(database_path) == {}


def test_create_duplicate_fails_before_prompting(config_file: Path) -> None:
    run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD])
    assert run(config_file, "--create-user", "ALICE", "--role", "viewer") == 1


def test_password_is_not_accepted_as_an_argument(config_file: Path) -> None:
    with pytest.raises(SystemExit):
        main.parse_args(["--create-user", "alice", "--role", "admin", "--password", PASSWORD])


def test_aborted_prompt(config_file: Path, database_path: Path) -> None:
    with patch("main.getpass", side_effect=KeyboardInterrupt):
        assert main.main(["-c", str(config_file), "--create-user", "alice", "--role", "admin"]) == 1
    assert users(database_path) == {}


def test_set_password(config_file: Path, database_path: Path) -> None:
    run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD])
    new = "recovered-password-123"
    assert run(config_file, "--set-password", "alice", passwords=[new, new]) == 0
    assert auth.verify_password(users(database_path)["alice"].password_hash, new)
    assert run(config_file, "--set-password", "nobody") == 1


def test_list_users(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--list-users") == 0
    assert "No dashboard users yet" in capsys.readouterr().out
    run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD])
    run(config_file, "--create-user", "victor", "--role", "viewer", passwords=[PASSWORD, PASSWORD])
    capsys.readouterr()
    assert run(config_file, "--list-users") == 0
    out = capsys.readouterr().out
    assert "alice" in out and "admin" in out and "victor" in out and "never" in out
    assert "scrypt" not in out


def test_set_role_disable_enable_delete(config_file: Path, database_path: Path) -> None:
    run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD])
    run(config_file, "--create-user", "victor", "--role", "viewer", passwords=[PASSWORD, PASSWORD])

    assert run(config_file, "--set-role", "victor", "admin") == 0
    assert users(database_path)["victor"].role == "admin"
    assert run(config_file, "--set-role", "victor", "root") == 1

    assert run(config_file, "--disable-user", "victor") == 0
    assert users(database_path)["victor"].disabled is True
    assert run(config_file, "--enable-user", "victor") == 0
    assert users(database_path)["victor"].disabled is False

    assert run(config_file, "--delete-user", "victor") == 0
    assert "victor" not in users(database_path)
    assert run(config_file, "--delete-user", "victor") == 1


def test_last_admin_rules_apply_to_the_cli(config_file: Path, database_path: Path,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    run(config_file, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD])
    capsys.readouterr()
    assert run(config_file, "--delete-user", "alice") == 1
    assert run(config_file, "--disable-user", "alice") == 1
    assert run(config_file, "--set-role", "alice", "viewer") == 1
    assert "last enabled admin" in capsys.readouterr().err
    assert users(database_path)["alice"].role == "admin"


def test_only_one_user_command_at_a_time(config_file: Path) -> None:
    with pytest.raises(SystemExit):
        main.parse_args(["--list-users", "--delete-user", "alice"])


def test_note_when_auth_is_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "plain.yaml"
    config.write_text(f"database:\n  path: '{(tmp_path / 'x.db').as_posix()}'\n", encoding="utf-8")
    assert run(config, "--create-user", "alice", "--role", "admin", passwords=[PASSWORD, PASSWORD]) == 0
    assert "auth.enabled is false" in capsys.readouterr().out
