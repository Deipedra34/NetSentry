"""Tests for main.py's --report CLI: a report is written from the database
alone, its path is printed, and packet capture is never started."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List
from unittest.mock import MagicMock, patch

import pytest

import main
from src.database import Database, Event


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """A config pointing the database and reports into tmp_path, with one
    event logged yesterday."""
    database_path = tmp_path / "netsentry.db"
    with Database(database_path) as db:
        yesterday_noon = datetime.combine(date.today() - timedelta(days=1), datetime.min.time()).astimezone()
        db.log_event(
            Event(
                "PORT_SCAN",
                "45.33.1.1",
                "scan",
                timestamp=(yesterday_noon + timedelta(hours=12)).astimezone(timezone.utc),
            )
        )
    path = tmp_path / "config.yaml"
    path.write_text(
        f"database:\n  path: '{database_path.as_posix()}'\n"
        f"reports:\n  output_dir: '{(tmp_path / 'reports').as_posix()}'\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def no_capture() -> Iterator[MagicMock]:
    """Fails loudly if anything tries to start capture or build detectors,
    and keeps setup_logging from reconfiguring the test run's logging."""
    with patch("main.NetworkSniffer") as sniffer, patch("main.build_detectors") as detectors, \
            patch("main.setup_logging"):
        yield sniffer
        sniffer.assert_not_called()
        detectors.assert_not_called()


def run(config_file: Path, *args: str) -> int:
    return main.main(["-c", str(config_file), *args])


def _printed_path(output: str) -> Path:
    lines = [line for line in output.splitlines() if line.startswith("Report written to ")]
    assert len(lines) == 1
    return Path(lines[0][len("Report written to "):])


def test_custom_report_is_written_and_its_path_printed(
    config_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(config_file, "--report", "custom", "--from", "2026-11-01", "--to", "2026-11-07") == 0
    path = _printed_path(capsys.readouterr().out)
    # a date-only --to includes that whole day
    assert path == config_file.parent / "reports" / "report_custom_20261101T0000_20261108T0000.pdf"
    assert path.read_bytes().startswith(b"%PDF-")


def test_custom_report_accepts_times_and_defaults_to_now(
    config_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(config_file, "--report", "custom", "--from", "2026-11-01T08:30") == 0
    path = _printed_path(capsys.readouterr().out)
    assert path.name.startswith("report_custom_20261101T0830_")
    assert path.exists()


def test_daily_report_covers_yesterday(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--report", "daily") == 0
    path = _printed_path(capsys.readouterr().out)
    yesterday = date.today() - timedelta(days=1)
    assert path.name == f"report_daily_{yesterday.isoformat()}.pdf"
    assert path.stat().st_size > 0


def test_weekly_report_covers_the_last_seven_days(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(config_file, "--report", "weekly") == 0
    path = _printed_path(capsys.readouterr().out)
    assert path.name == f"report_weekly_{(date.today() - timedelta(days=7)).isoformat()}.pdf"


def test_report_output_overrides_the_folder(
    config_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "elsewhere" / "mine.pdf"
    assert run(config_file, "--report", "daily", "--report-output", str(target)) == 0
    assert _printed_path(capsys.readouterr().out) == target
    assert target.read_bytes().startswith(b"%PDF-")


@pytest.mark.parametrize(
    "args, message",
    [
        (["--report", "daily", "--from", "2026-11-01"], "only apply to --report custom"),
        (["--report", "custom"], "needs --from"),
        (["--report", "custom", "--from", "2026-11-07", "--to", "2026-11-01"], "end must be after"),
        (["--report", "custom", "--from", "last tuesday"], "invalid report range"),
    ],
)
def test_invalid_report_arguments(
    config_file: Path, capsys: pytest.CaptureFixture[str], args: List[str], message: str
) -> None:
    assert run(config_file, *args) == 1
    assert message in capsys.readouterr().err
    assert not (config_file.parent / "reports").exists()


def test_generation_failure_returns_an_error(config_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("src.reports.write_report", side_effect=OSError("disk full")):
        assert run(config_file, "--report", "daily") == 1
    assert "could not generate the report: disk full" in capsys.readouterr().err
