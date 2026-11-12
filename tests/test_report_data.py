"""Unit tests for the core report queries in :mod:`src.reports.data`:
events by type, summary, timeline, top source IPs and notable events."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

from src.database import Database, Event
from src.reports.data import (
    collect_report_data,
    daily_period,
    events_by_type,
    notable_events,
    summary,
    timeline,
    top_sources,
)
from src.web import EVENT_TYPES

PERIOD = daily_period(date(2026, 11, 11), timezone.utc)


def at(hour: int, minute: int = 0, second: float = 0.0, day: int = 11) -> datetime:
    whole = int(second)
    return datetime(2026, 11, day, hour, minute, whole, int((second - whole) * 1_000_000), tzinfo=timezone.utc)


def log(db: Database, when: datetime, event_type: str, source_ip: str, details: str = "details") -> None:
    db.log_event(Event(event_type=event_type, source_ip=source_ip, details=details, timestamp=when))


@pytest.fixture()
def db(tmp_path: Path) -> Iterator[Database]:
    """A temporary on-disk database seeded with events on and around
    2026-11-11 (UTC)."""
    database = Database(tmp_path / "reports.db")
    log(database, at(0), "DHCP_STARVATION", "0.0.0.0")  # exactly at the start: included
    for hour in (1, 2, 3):
        log(database, at(hour), "PORT_SCAN", "45.33.1.1")
    log(database, at(5, 30), "SYN_FLOOD", "45.33.1.1")
    log(database, at(10), "BRUTE_FORCE", "10.0.0.5")
    log(database, at(10, 5), "BRUTE_FORCE", "10.0.0.5")
    log(database, at(12), "LEGACY_TYPE", "10.0.0.7")  # a type no detector raises any more
    log(database, at(23, 59, 59.5), "ICMP_OVERSIZED", "10.0.0.9")  # not critical
    log(database, at(0, day=12), "PORT_SCAN", "45.33.9.9")  # exactly at the end: excluded
    log(database, at(8, day=10), "PORT_SCAN", "45.33.2.2")  # previous day
    log(database, at(9, day=10), "ARP_SPOOF", "10.0.0.1")  # previous day
    yield database
    database.close()


def test_events_by_type_is_zero_filled_in_event_types_order(db: Database) -> None:
    by_type = events_by_type(db, PERIOD)
    assert list(by_type)[: len(EVENT_TYPES)] == list(EVENT_TYPES)
    assert by_type["PORT_SCAN"] == 3
    assert by_type["SYN_FLOOD"] == 1
    assert by_type["BRUTE_FORCE"] == 2
    assert by_type["DHCP_STARVATION"] == 1
    assert by_type["ICMP_OVERSIZED"] == 1
    assert by_type["ARP_SPOOF"] == 0
    # unknown types are kept, at the end
    assert list(by_type)[-1] == "LEGACY_TYPE"
    assert sum(by_type.values()) == 9


def test_summary_counts_and_previous_period(db: Database) -> None:
    result = summary(db, PERIOD)
    assert result.total_events == 9
    # ICMP_OVERSIZED and the unknown type aren't critical
    assert result.critical_events == 7
    assert result.distinct_sources == 5
    assert (result.previous_total_events, result.previous_critical_events) == (2, 2)
    assert result.previous_distinct_sources == 2


def test_timeline_buckets_cover_the_whole_period(db: Database) -> None:
    result = timeline(db, PERIOD)
    assert result.bucket_seconds == 3600
    assert len(result.starts) == len(result.counts) == 24
    assert result.starts[0] == PERIOD.start
    assert result.starts[10] == at(10)
    assert result.counts[0] == 1
    assert result.counts[1:4] == [1, 1, 1]
    assert result.counts[10] == 2
    assert result.counts[23] == 1
    assert sum(result.counts) == 9


def test_timeline_bucket_size_scales_with_the_period(db: Database) -> None:
    from src.reports.data import rolling_period

    now = at(12)
    assert timeline(db, rolling_period("1h", now)).bucket_seconds == 300
    assert len(timeline(db, rolling_period("1h", now)).counts) == 12
    assert timeline(db, rolling_period("7d", now)).bucket_seconds == 6 * 3600
    assert len(timeline(db, rolling_period("7d", now)).counts) == 28
    assert timeline(db, rolling_period("30d", now)).bucket_seconds == 86400


def test_top_sources_busiest_first_with_their_most_common_type(db: Database) -> None:
    result = top_sources(db, PERIOD, limit=3)
    assert [(s.ip, s.events, s.top_type, s.top_type_events) for s in result] == [
        ("45.33.1.1", 4, "PORT_SCAN", 3),
        ("10.0.0.5", 2, "BRUTE_FORCE", 2),
        ("0.0.0.0", 1, "DHCP_STARVATION", 1),  # ties are broken by IP
    ]
    assert top_sources(db, PERIOD, limit=0) == []


def test_notable_events_critical_first_then_newest_first_and_capped(db: Database) -> None:
    result = notable_events(db, PERIOD, limit=20)
    assert [e.event_type for e in result] == [
        "BRUTE_FORCE",
        "BRUTE_FORCE",
        "SYN_FLOOD",
        "PORT_SCAN",
        "PORT_SCAN",
        "PORT_SCAN",
        "DHCP_STARVATION",
        # non-critical ones last, newest first
        "ICMP_OVERSIZED",
        "LEGACY_TYPE",
    ]
    assert result[0].timestamp == at(10, 5)
    assert [e.event_type for e in notable_events(db, PERIOD, limit=2)] == ["BRUTE_FORCE", "BRUTE_FORCE"]
    assert notable_events(db, PERIOD, limit=0) == []


def test_collect_report_data_ties_the_queries_together(db: Database) -> None:
    generated = at(8, day=12)
    data = collect_report_data(db, PERIOD, max_notable_events=5, top_n_sources=2, generated_at=generated)
    assert data.period == PERIOD
    assert data.generated_at == generated
    assert data.is_empty is False
    assert data.summary.total_events == sum(data.by_type.values()) == 9
    assert len(data.top_sources) == 2
    assert len(data.notable_events) == 5


def test_empty_database(tmp_path: Path) -> None:
    with Database(tmp_path / "empty.db") as empty:
        data = collect_report_data(empty, PERIOD)
    assert data.is_empty is True
    assert set(data.by_type.values()) == {0}
    assert data.summary.distinct_sources == 0
    assert data.summary.previous_total_events == 0
    assert data.timeline.counts == [0] * 24
    assert data.top_sources == []
    assert data.countries == []
    assert data.flagged_ips == []
    assert not data.blocks
    assert data.notable_events == []
