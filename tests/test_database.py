"""Unit tests for :mod:`src.database`."""

from __future__ import annotations

from datetime import datetime, timezone

from src.database import Database, Event


def test_log_and_retrieve_event(in_memory_db: Database) -> None:
    event = Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="test event")
    saved = in_memory_db.log_event(event)
    assert saved.id is not None

    events = in_memory_db.get_events()
    assert len(events) == 1
    assert events[0].event_type == "PORT_SCAN"
    assert events[0].source_ip == "10.0.0.1"
    assert events[0].details == "test event"


def test_events_returned_newest_first(in_memory_db: Database) -> None:
    for i in range(3):
        in_memory_db.log_event(
            Event(
                event_type="SYN_FLOOD",
                source_ip=f"10.0.0.{i}",
                details=f"event {i}",
                timestamp=datetime(2024, 1, 1, 0, 0, i, tzinfo=timezone.utc),
            )
        )
    events = in_memory_db.get_events()
    assert [e.source_ip for e in events] == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]


def test_filter_by_event_type(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="ARP_SPOOF", source_ip="10.0.0.2", details="b"))

    events = in_memory_db.get_events(event_type="ARP_SPOOF")
    assert len(events) == 1
    assert events[0].event_type == "ARP_SPOOF"


def test_filter_by_source_ip(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.2", details="b"))

    events = in_memory_db.get_events(source_ip="10.0.0.2")
    assert len(events) == 1
    assert events[0].source_ip == "10.0.0.2"


def test_limit_is_respected(in_memory_db: Database) -> None:
    for i in range(10):
        in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details=str(i)))
    events = in_memory_db.get_events(limit=3)
    assert len(events) == 3


def test_count_events(in_memory_db: Database) -> None:
    assert in_memory_db.count_events() == 0
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="b"))
    assert in_memory_db.count_events() == 2


def test_event_type_counts(in_memory_db: Database) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a"))
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="b"))
    in_memory_db.log_event(Event(event_type="ARP_SPOOF", source_ip="10.0.0.2", details="c"))

    counts = in_memory_db.event_type_counts()
    assert counts == {"PORT_SCAN": 2, "ARP_SPOOF": 1}


def test_event_to_dict_is_json_serializable(in_memory_db: Database) -> None:
    import json

    event = in_memory_db.log_event(
        Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="a")
    )
    payload = json.dumps(event.to_dict())
    assert "PORT_SCAN" in payload
