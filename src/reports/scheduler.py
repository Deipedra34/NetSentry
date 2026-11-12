"""Scheduled daily/weekly reports, and rotation of old ones.

ReportScheduler.maybe_run() is called once per packet by the detection
engine, the same way AutoBlocker.maybe_check_expired() is: no extra
thread, and a no-op on almost every call, since it only actually checks
the schedule once every CHECK_INTERVAL seconds. When a daily or weekly
report is due it's written to reports.output_dir under a filename derived
from the period it covers (report_daily_2026-11-11.pdf), and a report whose
file already exists is never generated again -- so restarting NetSentry
doesn't produce duplicates, and a report missed while NetSentry was down
is still generated once it's back (the most recent one only, no backfill).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, tzinfo
from datetime import time as clock_time
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.config import Config
from src.database import Database
from src.reports.data import ReportPeriod, daily_period, local_timezone, weekly_period
from src.reports.generator import write_report

logger = logging.getLogger("netsentry.reports")

# what rotation counts as a scheduled report -- on-demand reports saved to
# the same folder (report_custom_*, report_24h_*, ...) are never deleted
SCHEDULED_REPORT_PATTERNS = ("report_daily_*.pdf", "report_weekly_*.pdf")

WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")

# seconds between schedule checks, however often maybe_run() is called
CHECK_INTERVAL = 60.0
# seconds before a report that failed to generate is tried again
RETRY_INTERVAL = 900.0


def rotate_reports(output_dir: Union[str, Path], keep: int) -> List[Path]:
    """Deletes the oldest scheduled reports in output_dir beyond the newest
    `keep` (by modification time), returning what was deleted. keep <= 0
    keeps everything. A file that can't be deleted is logged and skipped."""
    if keep <= 0:
        return []
    folder = Path(output_dir)
    reports = {path for pattern in SCHEDULED_REPORT_PATTERNS for path in folder.glob(pattern)}
    newest_first = sorted(reports, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
    deleted: List[Path] = []
    for path in newest_first[keep:]:
        try:
            path.unlink()
        except OSError as exc:
            logger.warning("Could not delete old report %s: %s", path, exc)
            continue
        deleted.append(path)
    if deleted:
        logger.info("Deleted %d old report(s) beyond reports.keep_reports=%d", len(deleted), keep)
    return deleted


def _parse_clock(value: str, setting: str) -> Optional[clock_time]:
    """'08:00' -> 08:00, or None (with a warning) if it isn't HH:MM."""
    try:
        hours, minutes = str(value).split(":")
        return clock_time(int(hours), int(minutes))
    except ValueError:
        logger.warning("reports.%s=%r is not a HH:MM time; that schedule is disabled", setting, value)
        return None


class ReportScheduler:
    """Generates the scheduled daily/weekly reports when they're due.

    The daily report covers the previous local calendar day and is due at
    daily_time; the weekly report covers the seven days before weekly_day
    and is due on weekly_day at weekly_time. Does nothing unless
    reports.enabled is true.
    """

    def __init__(self, config: Config, database: Database, tz: Optional[tzinfo] = None) -> None:
        # tz is fixed for tests; by default the machine's local time is used,
        # re-read at every check so a DST change is picked up
        self.settings = config.reports
        self.database = database
        self._tz = tz
        self._last_check = 0.0
        # report filename -> when generating it last failed
        self._failed: Dict[str, float] = {}
        self._daily_time = _parse_clock(self.settings.daily_time, "daily_time") if self.settings.daily else None
        self._weekly_time: Optional[clock_time] = None
        self._weekly_day: Optional[int] = None
        if self.settings.weekly:
            day = str(self.settings.weekly_day).strip().lower()
            if day in WEEKDAYS:
                self._weekly_day = WEEKDAYS.index(day)
                self._weekly_time = _parse_clock(self.settings.weekly_time, "weekly_time")
            else:
                logger.warning(
                    "reports.weekly_day=%r is not a day of the week; the weekly schedule is disabled",
                    self.settings.weekly_day,
                )

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def describe(self) -> str:
        """'daily at 08:00, weekly on monday at 08:00', for the startup log."""
        parts = []
        if self._daily_time is not None:
            parts.append(f"daily at {self._daily_time.strftime('%H:%M')}")
        if self._weekly_time is not None and self._weekly_day is not None:
            parts.append(f"weekly on {WEEKDAYS[self._weekly_day]} at {self._weekly_time.strftime('%H:%M')}")
        return ", ".join(parts) or "no schedule"

    def maybe_run(self, now: Optional[float] = None) -> List[Path]:
        """Called on every packet; actually checks the schedule at most once
        per CHECK_INTERVAL seconds. Returns the reports written, if any."""
        if not self.enabled:
            return []
        current = now if now is not None else time.time()
        if current - self._last_check < CHECK_INTERVAL:
            return []
        self._last_check = current
        return self.run_due(current)

    def due_periods(self, now: float) -> List[ReportPeriod]:
        """The most recent daily and weekly periods whose report is due by now."""
        tz = self._tz or local_timezone()
        local_now = datetime.fromtimestamp(now, tz)
        today = local_now.date()
        periods: List[ReportPeriod] = []
        if self._daily_time is not None:
            # today's report (on yesterday) once daily_time has passed,
            # otherwise yesterday's (on the day before)
            reported_day = today - timedelta(days=1 if local_now.time() >= self._daily_time else 2)
            periods.append(daily_period(reported_day, tz))
        if self._weekly_time is not None and self._weekly_day is not None:
            due_day = today - timedelta(days=(today.weekday() - self._weekly_day) % 7)
            if due_day == today and local_now.time() < self._weekly_time:
                due_day -= timedelta(days=7)
            periods.append(weekly_period(due_day - timedelta(days=7), tz))
        return periods

    def run_due(self, now: float) -> List[Path]:
        """Writes every due report that doesn't exist yet, then rotates. A
        report that fails is logged as a warning and retried after
        RETRY_INTERVAL -- it never raises."""
        output_dir = Path(self.settings.output_dir)
        written: List[Path] = []
        for period in self.due_periods(now):
            path = output_dir / period.filename
            if path.exists():
                continue
            if now - self._failed.get(period.filename, float("-inf")) < RETRY_INTERVAL:
                continue
            try:
                write_report(self.database, period, path, settings=self.settings)
            except Exception as exc:  # noqa: BLE001 - a broken report must never stop capture
                self._failed[period.filename] = now
                logger.warning(
                    "Failed to generate the scheduled %s report %s (retrying in %.0f minutes): %s",
                    period.kind, path, RETRY_INTERVAL / 60, exc, exc_info=True,
                )
                continue
            self._failed.pop(period.filename, None)
            logger.info("Wrote scheduled %s report %s", period.kind, path)
            written.append(path)
        if written:
            rotate_reports(output_dir, self.settings.keep_reports)
        return written
