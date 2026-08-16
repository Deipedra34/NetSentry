"""Unit tests for the Flask dashboard in :mod:`src.web`."""

from __future__ import annotations

from src.database import Database, Event
from src.web import create_app


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
