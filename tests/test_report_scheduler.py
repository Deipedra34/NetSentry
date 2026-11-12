"""Tests for scheduled reports (:mod:`src.reports.scheduler`): when reports
are due, generating each one exactly once, rotation, and failures never
reaching the detection engine. Time is always passed in -- no sleeping."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List
from unittest.mock import MagicMock, patch

import pytest

from src.config import Config
from src.database import Database, Event
from src.engine import DetectionEngine
from src.reports.scheduler import CHECK_INTERVAL, RETRY_INTERVAL, ReportScheduler, rotate_reports
from tests.conftest import make_packet

UTC = timezone.utc


def ts(day: int, hour: int, minute: int = 0) -> float:
    """A November 2026 moment (UTC) as a unix timestamp. 2026-11-16 is a Monday."""
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC).timestamp()


@pytest.fixture()
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "netsentry.db")
    yield database
    database.close()


def make_config(tmp_path: Path, **overrides: object) -> Config:
    config = Config()
    config.reports.enabled = True
    config.reports.output_dir = str(tmp_path / "reports")
    for key, value in overrides.items():
        setattr(config.reports, key, value)
    return config


def names(paths: List[Path]) -> List[str]:
    return sorted(path.name for path in paths)


def test_disabled_scheduler_never_writes_anything(db: Database, tmp_path: Path) -> None:
    config = make_config(tmp_path, enabled=False)
    assert ReportScheduler(config, db, tz=UTC).maybe_run(ts(16, 9)) == []
    assert not (tmp_path / "reports").exists()


def test_due_reports_are_generated(db: Database, tmp_path: Path) -> None:
    db.log_event(Event("PORT_SCAN", "45.33.1.1", "scan", timestamp=datetime(2026, 11, 15, 12, tzinfo=UTC)))
    scheduler = ReportScheduler(make_config(tmp_path), db, tz=UTC)
    # Monday 08:30: yesterday's daily report and last week's weekly are due
    written = scheduler.maybe_run(ts(16, 8, 30))
    assert names(written) == ["report_daily_2026-11-15.pdf", "report_weekly_2026-11-09.pdf"]
    for path in written:
        assert path.read_bytes().startswith(b"%PDF-")


def test_before_daily_time_the_previous_report_is_due(db: Database, tmp_path: Path) -> None:
    scheduler = ReportScheduler(make_config(tmp_path, weekly=False), db, tz=UTC)
    # Tuesday 07:59: today's report isn't due yet, Monday's (on Sunday) was
    assert names(scheduler.run_due(ts(17, 7, 59))) == ["report_daily_2026-11-15.pdf"]
    assert names(scheduler.run_due(ts(17, 8, 0))) == ["report_daily_2026-11-16.pdf"]


def test_weekly_report_is_due_on_its_day_after_its_time(db: Database, tmp_path: Path) -> None:
    config = make_config(tmp_path, daily=False, weekly_day="Wednesday", weekly_time="18:30")
    scheduler = ReportScheduler(config, db, tz=UTC)
    # Wednesday 2026-11-18 before 18:30: last Wednesday's report (on Nov 4-10)
    assert names(scheduler.run_due(ts(18, 18, 29))) == ["report_weekly_2026-11-04.pdf"]
    assert names(scheduler.run_due(ts(18, 18, 30))) == ["report_weekly_2026-11-11.pdf"]
    # a later weekday still points at the most recent Wednesday
    assert scheduler.run_due(ts(21, 12)) == []


def test_each_report_is_generated_only_once(db: Database, tmp_path: Path) -> None:
    scheduler = ReportScheduler(make_config(tmp_path), db, tz=UTC)
    assert len(scheduler.run_due(ts(16, 9))) == 2
    with patch("src.reports.scheduler.write_report") as write_report:
        assert scheduler.run_due(ts(16, 10)) == []
    write_report.assert_not_called()


def test_existing_report_is_skipped_after_a_restart(db: Database, tmp_path: Path) -> None:
    output = tmp_path / "reports"
    output.mkdir()
    existing = output / "report_daily_2026-11-15.pdf"
    existing.write_bytes(b"%PDF- written before the restart")
    restarted = ReportScheduler(make_config(tmp_path, weekly=False), db, tz=UTC)
    assert restarted.maybe_run(ts(16, 9)) == []
    assert existing.read_bytes() == b"%PDF- written before the restart"


def test_schedule_is_checked_at_most_once_a_minute(db: Database, tmp_path: Path) -> None:
    scheduler = ReportScheduler(make_config(tmp_path), db, tz=UTC)
    with patch.object(scheduler, "run_due", return_value=[]) as run_due:
        for second in range(0, 150):
            scheduler.maybe_run(ts(16, 9) + second)
    assert run_due.call_count == 3  # at +0s, +60s and +120s
    assert CHECK_INTERVAL == 60.0


def test_invalid_schedule_settings_disable_that_schedule(
    db: Database, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = make_config(tmp_path, daily_time="8 o'clock", weekly_day="someday")
    with caplog.at_level(logging.WARNING, logger="netsentry.reports"):
        scheduler = ReportScheduler(config, db, tz=UTC)
    assert "reports.daily_time" in caplog.text
    assert "reports.weekly_day" in caplog.text
    assert scheduler.describe() == "no schedule"
    assert scheduler.maybe_run(ts(16, 9)) == []


def _touch(folder: Path, name: str, mtime: float) -> Path:
    path = folder / name
    path.write_bytes(b"%PDF-")
    os.utime(path, (mtime, mtime))
    return path


def test_rotation_deletes_only_the_oldest_scheduled_reports(tmp_path: Path) -> None:
    for day in range(1, 7):
        _touch(tmp_path, f"report_daily_2026-11-0{day}.pdf", ts(day, 9))
    _touch(tmp_path, "report_weekly_2026-10-26.pdf", ts(2, 9, 30))
    # on-demand reports and other files are never touched
    _touch(tmp_path, "report_custom_20261101T0000_20261102T0000.pdf", ts(1, 0))
    _touch(tmp_path, "report_24h_20261101T0800.pdf", ts(1, 0))
    _touch(tmp_path, "notes.pdf", ts(1, 0))

    deleted = rotate_reports(tmp_path, keep=4)
    assert names(deleted) == [
        "report_daily_2026-11-01.pdf",
        "report_daily_2026-11-02.pdf",
        "report_weekly_2026-10-26.pdf",
    ]
    assert names(list(tmp_path.iterdir())) == [
        "notes.pdf",
        "report_24h_20261101T0800.pdf",
        "report_custom_20261101T0000_20261102T0000.pdf",
        "report_daily_2026-11-03.pdf",
        "report_daily_2026-11-04.pdf",
        "report_daily_2026-11-05.pdf",
        "report_daily_2026-11-06.pdf",
    ]


def test_rotation_with_keep_zero_keeps_everything(tmp_path: Path) -> None:
    for day in range(1, 7):
        _touch(tmp_path, f"report_daily_2026-11-0{day}.pdf", ts(day, 9))
    assert rotate_reports(tmp_path, keep=0) == []
    assert len(list(tmp_path.iterdir())) == 6


def test_scheduler_rotates_after_writing(db: Database, tmp_path: Path) -> None:
    output = tmp_path / "reports"
    output.mkdir()
    for day in range(10, 15):
        _touch(output, f"report_daily_2026-11-{day}.pdf", ts(day, 8))
    scheduler = ReportScheduler(make_config(tmp_path, weekly=False, keep_reports=3), db, tz=UTC)
    assert names(scheduler.run_due(ts(16, 9))) == ["report_daily_2026-11-15.pdf"]
    assert names(list(output.iterdir())) == [
        "report_daily_2026-11-13.pdf",
        "report_daily_2026-11-14.pdf",
        "report_daily_2026-11-15.pdf",
    ]


def test_generation_failure_is_a_warning_and_retried_later(
    db: Database, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    scheduler = ReportScheduler(make_config(tmp_path, weekly=False), db, tz=UTC)
    with patch("src.reports.scheduler.write_report", side_effect=OSError("disk full")) as write_report, \
            caplog.at_level(logging.WARNING, logger="netsentry.reports"):
        assert scheduler.run_due(ts(16, 9)) == []
        assert scheduler.run_due(ts(16, 9) + RETRY_INTERVAL - 1) == []  # not retried yet
    assert write_report.call_count == 1
    assert "Failed to generate the scheduled daily report" in caplog.text
    assert "disk full" in caplog.text
    assert [r.levelno for r in caplog.records if "Failed to generate" in r.message] == [logging.WARNING]
    # once the retry interval has passed, it's tried again and succeeds
    assert names(scheduler.run_due(ts(16, 9) + RETRY_INTERVAL)) == ["report_daily_2026-11-15.pdf"]


def test_engine_generates_due_reports_while_processing_packets(db: Database, tmp_path: Path) -> None:
    scheduler = ReportScheduler(make_config(tmp_path, weekly=False), db, tz=UTC)
    engine = DetectionEngine(db, [], report_scheduler=scheduler)
    with patch("src.reports.scheduler.time.time", return_value=ts(16, 9)):
        engine.handle_packet(make_packet(timestamp=ts(16, 9)))
    assert (tmp_path / "reports" / "report_daily_2026-11-15.pdf").exists()


def test_scheduler_failure_never_crashes_the_engine(db: Database, caplog: pytest.LogCaptureFixture) -> None:
    scheduler = MagicMock()
    scheduler.maybe_run.side_effect = RuntimeError("boom")
    detector = MagicMock()
    detector.process_packet.return_value = [Event("PORT_SCAN", "45.33.1.1", "scan")]
    engine = DetectionEngine(db, [detector], report_scheduler=scheduler)
    with caplog.at_level(logging.WARNING, logger="netsentry.engine"):
        engine.handle_packet(make_packet(timestamp=1000.0))
        engine.handle_packet(make_packet(timestamp=1001.0))
    assert engine.packet_count == 2
    assert len(db.get_events()) == 2  # detection carried on regardless
    warnings = [r for r in caplog.records if "ReportScheduler raised" in r.message]
    assert warnings and all(r.levelno == logging.WARNING for r in warnings)
