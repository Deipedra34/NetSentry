"""Unit tests for the report periods in :mod:`src.reports.data`."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from src.reports.data import (
    ROLLING_RANGES,
    custom_period,
    daily_period,
    local_timezone,
    rolling_period,
    weekly_period,
)

TZ = timezone(timedelta(hours=3))


def test_daily_period_covers_one_local_calendar_day() -> None:
    period = daily_period(date(2026, 11, 11), TZ)
    assert period.start == datetime(2026, 11, 11, tzinfo=TZ)
    assert period.end == datetime(2026, 11, 12, tzinfo=TZ)
    assert period.title == "NetSentry daily report: 2026-11-11"
    assert period.filename == "report_daily_2026-11-11.pdf"
    assert period.describe_range() == "2026-11-11 00:00 to 2026-11-12 00:00 (UTC+03:00)"


def test_weekly_period_covers_seven_days() -> None:
    period = weekly_period(date(2026, 11, 2), TZ)
    assert period.duration == timedelta(days=7)
    assert period.title == "NetSentry weekly report: 2026-11-02 to 2026-11-08"
    assert period.filename == "report_weekly_2026-11-02.pdf"


def test_previous_period_has_the_same_length_and_ends_where_this_starts() -> None:
    for period in (
        daily_period(date(2026, 11, 11), TZ),
        weekly_period(date(2026, 11, 2), TZ),
        rolling_period("30d", datetime(2026, 11, 12, 8, 15, tzinfo=TZ)),
    ):
        previous = period.previous()
        assert previous.end == period.start
        assert previous.duration == period.duration
        assert previous.kind == period.kind


def test_rolling_periods_end_now() -> None:
    now = datetime(2026, 11, 12, 8, 15, tzinfo=TZ)
    for key, length in ROLLING_RANGES.items():
        period = rolling_period(key, now)
        assert (period.start, period.end) == (now - length, now)
        assert period.filename == f"report_{key}_20261112T0815.pdf"
    assert rolling_period("24h", now).title == "NetSentry report: last 24 hours"
    assert rolling_period("7d", now).title == "NetSentry report: last 7 days"
    with pytest.raises(KeyError):
        rolling_period("2y", now)


def test_custom_period_takes_naive_datetimes_as_local_time() -> None:
    period = custom_period(datetime(2026, 11, 1), datetime(2026, 11, 5, 12, 30))
    assert period.start.tzinfo == local_timezone()
    assert period.filename == "report_custom_20261101T0000_20261105T1230.pdf"
    assert period.title == "NetSentry report: 2026-11-01 00:00 to 2026-11-05 12:30"


def test_custom_period_rejects_an_empty_or_reversed_range() -> None:
    with pytest.raises(ValueError):
        custom_period(datetime(2026, 11, 5), datetime(2026, 11, 5))
    with pytest.raises(ValueError):
        custom_period(datetime(2026, 11, 5), datetime(2026, 11, 1))


def test_utc_period_label() -> None:
    assert daily_period(date(2026, 11, 11), timezone.utc).describe_range().endswith("(UTC+00:00)")
