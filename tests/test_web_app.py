"""Unit tests for the Flask dashboard in :mod:`src.web`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from src.database import Database, Event
from src.web import EVENT_TYPES, create_app


def test_dashboard_page_loads(in_memory_db: Database) -> None:
    app = create_app(in_memory_db, refresh_interval=5)
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"NetSentry" in response.data


def test_api_events_empty(in_memory_db: Database) -> None:
    app = create_app(in_memory_db)
    client = app.test_client()
    response = client.get("/api/events")
    assert response.status_code == 200
    assert response.get_json() == []


def test_api_events_returns_logged_events(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="scan"))
    app = create_app(in_memory_db)
    client = app.test_client()

    response = client.get("/api/events")
    payload = response.get_json()
    assert len(payload) == 1
    assert payload[0]["event_type"] == "PORT_SCAN"
    assert payload[0]["source_ip"] == "10.0.0.1"


def test_api_events_filters_by_type(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="ARP_SPOOF", source_ip="10.0.0.2", details="b"))
    app = create_app(in_memory_db)
    client = app.test_client()

    response = client.get("/api/events?event_type=ARP_SPOOF")
    payload = response.get_json()
    assert len(payload) == 1
    assert payload[0]["event_type"] == "ARP_SPOOF"


def test_api_stats(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="b"))
    app = create_app(in_memory_db)
    client = app.test_client()

    response = client.get("/api/stats")
    payload = response.get_json()
    assert payload["total_events"] == 2
    assert payload["by_type"]["PORT_SCAN"] == 2


def test_healthz(in_memory_db: Database) -> None:
    app = create_app(in_memory_db)
    client = app.test_client()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def _ago(**kwargs: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kwargs)


def _seed_stats_events(db: Database) -> None:
    # two port scans + an ARP spoof within the last hour, a SYN flood a few
    # hours back, and a DNS tunnel a few days back
    db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a", timestamp=_ago(minutes=10)))
    db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="b", timestamp=_ago(minutes=10)))
    db.log_event(Event(event_type="ARP_SPOOF", source_ip="10.0.0.2", details="c", timestamp=_ago(minutes=30)))
    db.log_event(Event(event_type="SYN_FLOOD", source_ip="10.0.0.3", details="d", timestamp=_ago(hours=5)))
    db.log_event(Event(event_type="DNS_TUNNEL", source_ip="10.0.0.4", details="e", timestamp=_ago(days=3)))


def _bucket_index(buckets: List[str], bucket_seconds: int, when: datetime) -> int:
    starts = [datetime.fromisoformat(b) for b in buckets]
    for i, start in enumerate(starts):
        if start <= when < start + timedelta(seconds=bucket_seconds):
            return i
    raise AssertionError(f"{when} not inside any bucket")


@pytest.mark.parametrize(
    ("range_key", "bucket_seconds", "bucket_count"),
    [("1h", 60, 60), ("24h", 3600, 24), ("7d", 6 * 3600, 28)],
)
def test_api_stats_timeline_bucket_layout(
    in_memory_db: Database, range_key: str, bucket_seconds: int, bucket_count: int
) -> None:
    client = create_app(in_memory_db).test_client()
    response = client.get(f"/api/stats/timeline?range={range_key}")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["range"] == range_key
    assert payload["bucket_seconds"] == bucket_seconds
    assert len(payload["buckets"]) == bucket_count

    starts = [datetime.fromisoformat(b) for b in payload["buckets"]]
    gaps = {(later - earlier).total_seconds() for earlier, later in zip(starts, starts[1:])}
    assert gaps == {bucket_seconds}
    assert starts[-1] <= datetime.now(timezone.utc) < starts[-1] + timedelta(seconds=bucket_seconds)


def test_api_stats_timeline_buckets_events(in_memory_db: Database) -> None:
    _seed_stats_events(in_memory_db)
    client = create_app(in_memory_db).test_client()

    payload = client.get("/api/stats/timeline?range=1h").get_json()
    series = payload["series"]
    assert set(series) == {"PORT_SCAN", "ARP_SPOOF"}
    for counts in series.values():
        assert len(counts) == len(payload["buckets"])
        assert all(isinstance(c, int) for c in counts)
    assert sum(series["PORT_SCAN"]) == 2
    assert sum(series["ARP_SPOOF"]) == 1

    index = _bucket_index(payload["buckets"], payload["bucket_seconds"], _ago(minutes=10))
    # allow for a minute boundary ticking over between seeding and the request
    assert series["PORT_SCAN"][index] == 2 or series["PORT_SCAN"][index - 1] == 2

    payload = client.get("/api/stats/timeline?range=24h").get_json()
    assert set(payload["series"]) == {"PORT_SCAN", "ARP_SPOOF", "SYN_FLOOD"}
    syn_index = _bucket_index(payload["buckets"], payload["bucket_seconds"], _ago(hours=5))
    assert payload["series"]["SYN_FLOOD"][syn_index] == 1

    payload = client.get("/api/stats/timeline?range=7d").get_json()
    assert sum(payload["series"]["DNS_TUNNEL"]) == 1


def test_api_stats_timeline_defaults_to_24h(in_memory_db: Database) -> None:
    client = create_app(in_memory_db).test_client()
    payload = client.get("/api/stats/timeline").get_json()
    assert payload["range"] == "24h"


def test_api_stats_timeline_empty(in_memory_db: Database) -> None:
    client = create_app(in_memory_db).test_client()
    response = client.get("/api/stats/timeline?range=1h")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["series"] == {}
    assert len(payload["buckets"]) == 60


def test_api_stats_distribution_counts(in_memory_db: Database) -> None:
    _seed_stats_events(in_memory_db)
    client = create_app(in_memory_db).test_client()

    payload = client.get("/api/stats/distribution?range=1h").get_json()
    assert payload["range"] == "1h"
    assert payload["by_type"]["PORT_SCAN"] == 2
    assert payload["by_type"]["ARP_SPOOF"] == 1
    assert payload["by_type"]["SYN_FLOOD"] == 0
    assert payload["total_events"] == 3

    payload = client.get("/api/stats/distribution").get_json()
    assert payload["range"] == "24h"
    assert payload["by_type"]["SYN_FLOOD"] == 1
    assert payload["total_events"] == 4

    payload = client.get("/api/stats/distribution?range=7d").get_json()
    assert payload["by_type"]["DNS_TUNNEL"] == 1
    assert payload["total_events"] == 5


def test_api_stats_distribution_empty(in_memory_db: Database) -> None:
    client = create_app(in_memory_db).test_client()
    response = client.get("/api/stats/distribution")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["total_events"] == 0
    assert set(payload["by_type"]) == set(EVENT_TYPES)
    assert set(payload["by_type"].values()) == {0}


@pytest.mark.parametrize("endpoint", ["/api/stats/timeline", "/api/stats/distribution"])
def test_api_stats_rejects_unknown_range(in_memory_db: Database, endpoint: str) -> None:
    client = create_app(in_memory_db).test_client()
    response = client.get(f"{endpoint}?range=1y")
    assert response.status_code == 400
    assert "error" in response.get_json()
