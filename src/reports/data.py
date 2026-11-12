"""Report periods and the read-only queries behind a report.

Everything here returns plain Python data (dataclasses, lists, dicts) built
from the existing database tables; src/reports/pdf.py does the layout.
Periods are half-open [start, end) ranges of timezone-aware datetimes.
Events are stored in UTC, so queries convert the bounds to UTC first, but
periods themselves are built in local time -- "yesterday" means the
user's yesterday, not UTC's.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from typing import Dict, List, Optional

from src.database import Database
from src.web import EVENT_TYPES

logger = logging.getLogger("netsentry.reports")

# dashboard/API range key -> rolling period length ending now
ROLLING_RANGES: Dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def local_timezone() -> tzinfo:
    """The machine's current UTC offset, as a fixed-offset tzinfo."""
    return datetime.now().astimezone().tzinfo or timezone.utc


@dataclass(frozen=True)
class ReportPeriod:
    """The time range one report covers, [start, end).

    kind is "daily", "weekly", "custom", or a ROLLING_RANGES key ("24h"
    etc.) for the dashboard's rolling windows. It decides the title and
    the filename -- daily and weekly filenames depend only on the dates
    covered, so a scheduled report already written can be recognized after
    a restart.
    """

    kind: str
    start: datetime
    end: datetime

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def previous(self) -> "ReportPeriod":
        """The period of the same length right before this one, for the
        summary's "compared with the previous period" figures."""
        return ReportPeriod(self.kind, self.start - self.duration, self.start)

    @property
    def title(self) -> str:
        start = self.start.strftime("%Y-%m-%d")
        if self.kind == "daily":
            return f"NetSentry daily report: {start}"
        if self.kind == "weekly":
            last_day = (self.end - timedelta(days=1)).strftime("%Y-%m-%d")
            return f"NetSentry weekly report: {start} to {last_day}"
        if self.kind in ROLLING_RANGES:
            return f"NetSentry report: last {_describe_length(self.duration)}"
        return (
            f"NetSentry report: {self.start.strftime('%Y-%m-%d %H:%M')} to "
            f"{self.end.strftime('%Y-%m-%d %H:%M')}"
        )

    @property
    def filename(self) -> str:
        if self.kind in ("daily", "weekly"):
            return f"report_{self.kind}_{self.start.strftime('%Y-%m-%d')}.pdf"
        stamp = "%Y%m%dT%H%M"
        if self.kind in ROLLING_RANGES:
            return f"report_{self.kind}_{self.end.strftime(stamp)}.pdf"
        return f"report_custom_{self.start.strftime(stamp)}_{self.end.strftime(stamp)}.pdf"

    def describe_range(self) -> str:
        """'2026-11-11 00:00 to 2026-11-12 00:00 (UTC+03:00)'."""
        offset = self.start.strftime("%z")
        zone = f"UTC{offset[:3]}:{offset[3:]}" if offset else "UTC"
        return (
            f"{self.start.strftime('%Y-%m-%d %H:%M')} to "
            f"{self.end.strftime('%Y-%m-%d %H:%M')} ({zone})"
        )


def _describe_length(length: timedelta) -> str:
    hours = length.total_seconds() / 3600
    if hours < 48:
        return f"{hours:.0f} hour{'s' if hours != 1 else ''}"
    return f"{hours / 24:.0f} days"


def _midnight(day: date, tz: tzinfo) -> datetime:
    return datetime.combine(day, time(), tzinfo=tz)


def daily_period(day: date, tz: Optional[tzinfo] = None) -> ReportPeriod:
    """The whole local calendar day `day`."""
    tz = tz or local_timezone()
    return ReportPeriod("daily", _midnight(day, tz), _midnight(day + timedelta(days=1), tz))


def weekly_period(first_day: date, tz: Optional[tzinfo] = None) -> ReportPeriod:
    """Seven whole local days starting at `first_day`."""
    tz = tz or local_timezone()
    return ReportPeriod("weekly", _midnight(first_day, tz), _midnight(first_day + timedelta(days=7), tz))


def rolling_period(range_key: str, now: Optional[datetime] = None) -> ReportPeriod:
    """The ROLLING_RANGES window ending at now (the dashboard's ranges).
    Raises KeyError for an unknown range_key."""
    length = ROLLING_RANGES[range_key]
    now = now or datetime.now(local_timezone())
    return ReportPeriod(range_key, now - length, now)


def custom_period(start: datetime, end: datetime) -> ReportPeriod:
    """An arbitrary [start, end) range; naive datetimes are taken as local
    time. Raises ValueError if end isn't after start."""
    tz = local_timezone()
    start = start if start.tzinfo else start.replace(tzinfo=tz)
    end = end if end.tzinfo else end.replace(tzinfo=tz)
    if end <= start:
        raise ValueError("report end must be after its start")
    return ReportPeriod("custom", start, end)


def _utc(moment: datetime) -> datetime:
    """moment in UTC -- events are stored as UTC isoformat strings, and the
    database compares them as plain strings, so bounds must be UTC too."""
    return moment.astimezone(timezone.utc)


def events_by_type(database: Database, period: ReportPeriod) -> Dict[str, int]:
    """Event count per type within the period, in the order of the
    dashboard's EVENT_TYPES (src/web.py, the authoritative list of every
    type a detector can raise), zero-filled. A type in the database that
    isn't in that list (e.g. from an older version) is appended at the end
    rather than dropped."""
    counts = database.event_type_counts(since=_utc(period.start), until=_utc(period.end))
    by_type = {event_type: counts.pop(event_type, 0) for event_type in EVENT_TYPES}
    by_type.update(sorted(counts.items()))
    return by_type


@dataclass
class SourceSummary:
    """One row of the top source IPs table."""

    ip: str
    events: int
    # the event type this IP raised most often, and how many times
    top_type: str
    top_type_events: int


def top_sources(database: Database, period: ReportPeriod, limit: int) -> List[SourceSummary]:
    """The `limit` source IPs with the most events in the period, busiest
    first, each with its most common event type (ties go to the type
    listed first in EVENT_TYPES)."""
    if limit <= 0:
        return []
    order = {event_type: index for index, event_type in enumerate(EVENT_TYPES)}
    summaries: List[SourceSummary] = []
    for ip, count, types in database.top_source_ips(_utc(period.start), _utc(period.end), limit):
        top_type = min(types, key=lambda t: (-types[t], order.get(t, len(order)), t))
        summaries.append(SourceSummary(ip, count, top_type, types[top_type]))
    return summaries
