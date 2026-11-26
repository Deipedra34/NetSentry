"""Tests for :mod:`src.siem.json_format`."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from src import __version__
from src.database import Event, ThreatIntelResult
from src.siem.formatting import FormatSettings
from src.siem.json_format import ECS_VERSION, format_json
from src.siem.normalize import SCHEMA_VERSION, make_test_event, normalize_event
from src.web import EVENT_TYPES
from tests.conftest import make_packet

PLAIN = FormatSettings(hostname="sensor-1")
ECS = FormatSettings(hostname="sensor-1", ecs_fields=True)
WHEN = datetime(2026, 11, 26, 9, 15, 2, 123000, tzinfo=timezone.utc)
GEO = {"45.33.12.9": {"country_name": "Germany", "country_iso_code": "DE", "city_name": "Frankfurt am Main",
                      "as_number": 24940, "as_organization": "Hetzner Online GmbH"}}


def _record(details: str = "beacon every 60s", **kwargs: Any) -> Dict[str, Any]:
    event = Event(
        event_type=kwargs.pop("event_type", "BEACONING"),
        source_ip=kwargs.pop("source_ip", "45.33.12.9"),
        details=details,
        timestamp=WHEN,
        id=kwargs.pop("id", 11),
        destination_ip=kwargs.pop("destination_ip", "8.8.8.8"),
    )
    packet = make_packet(1.0, src_ip=event.source_ip, dst_ip="8.8.8.8", protocol="UDP", src_port=5000, dst_port=443)
    packet.interface = "eth0"
    threat = ThreatIntelResult(source_ip="45.33.12.9", abuseipdb_score=87, abuseipdb_reports=42)
    return normalize_event(
        event, packet=packet, sensor="sensor-1", geo=lambda ip: GEO.get(ip, {}), threat=threat
    )


def _load(data: bytes) -> Dict[str, Any]:
    assert b"\n" not in data and b"\r" not in data
    return json.loads(data.decode("utf-8"))


def test_plain_schema() -> None:
    document = _load(format_json(_record(), PLAIN))
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["timestamp"] == "2026-11-26T09:15:02.123Z"
    assert document["event_type"] == "BEACONING"
    assert document["severity"] == "high"
    assert document["severity_score"] == 75
    assert (document["source_ip"], document["source_port"]) == ("45.33.12.9", 5000)
    assert (document["destination_ip"], document["destination_port"]) == ("8.8.8.8", 443)
    assert document["protocol"] == "UDP"
    assert document["details"] == "beacon every 60s"
    assert document["source_country"] == "Germany"
    assert document["source_abuse_score"] == 87
    assert document["sensor"] == "sensor-1"
    assert document["netsentry_version"] == __version__


@pytest.mark.parametrize("event_type", EVENT_TYPES)
def test_every_event_type_is_valid_json(event_type: str) -> None:
    for settings in (PLAIN, ECS):
        document = _load(format_json(_record(event_type=event_type), settings))
        assert "None" not in json.dumps(document)


def test_missing_fields_are_omitted_not_null() -> None:
    record = normalize_event(Event(event_type="DHCP_STARVATION", source_ip="0.0.0.0", details="x", timestamp=WHEN))
    for settings in (PLAIN, ECS):
        text = format_json(record, settings).decode("utf-8")
        assert "null" not in text and "None" not in text
    assert "source_ip" not in _load(format_json(record, PLAIN))
    assert "source" not in _load(format_json(record, ECS))


def test_ecs_field_names() -> None:
    document = _load(format_json(_record(), ECS))
    assert document["@timestamp"] == "2026-11-26T09:15:02.123Z"
    assert document["message"] == "Beaconing from 45.33.12.9: beacon every 60s"
    assert document["ecs"] == {"version": ECS_VERSION}
    event = document["event"]
    assert event["kind"] == "alert"
    assert event["category"] == ["intrusion_detection", "network"]
    assert event["code"] == "BEACONING"
    assert event["severity"] == 75
    assert event["id"] == "11"
    assert document["log"]["level"] == "high"
    assert document["source"]["ip"] == "45.33.12.9"
    assert document["source"]["port"] == 5000
    assert document["source"]["mac"] == "AA-AA-AA-AA-AA-AA"
    assert document["source"]["geo"] == {
        "country_name": "Germany",
        "country_iso_code": "DE",
        "city_name": "Frankfurt am Main",
    }
    assert document["source"]["as"] == {"number": 24940, "organization": {"name": "Hetzner Online GmbH"}}
    assert document["destination"] == {"ip": "8.8.8.8", "port": 443}
    assert document["network"] == {"transport": "udp"}
    assert document["observer"]["name"] == "sensor-1"
    assert document["observer"]["product"] == "NetSentry"
    assert document["observer"]["version"] == __version__
    assert document["observer"]["ingress"] == {"interface": {"name": "eth0"}}
    assert document["netsentry"]["schema_version"] == SCHEMA_VERSION
    assert document["netsentry"]["threat_intel"] == {"source": {"abuseipdb_score": 87, "abuseipdb_reports": 42}}
    assert document["tags"] == ["netsentry"]
    # no flat NetSentry names leak into the ECS document
    assert "source_ip" not in document and "timestamp" not in document


def test_test_event_is_labeled_in_both_modes() -> None:
    record = normalize_event(make_test_event())
    plain = _load(format_json(record, PLAIN))
    assert plain["event_type"] == "siem_test" and plain["test"] is True
    ecs = _load(format_json(record, ECS))
    assert ecs["event"]["code"] == "siem_test"
    assert ecs["netsentry"]["test"] is True
    assert ecs["tags"] == ["netsentry", "test"]


@pytest.mark.parametrize(
    "payload",
    [
        'evil.com","severity":"critical',
        "evil.com\n{\"event_type\":\"FORGED\"}",
        "evil.com\r\nforged",
        "a=b|c\\d]e",
        "  \x00\x1b",
    ],
)
def test_log_injection_stays_inside_one_value(payload: str) -> None:
    record = _record(details=payload)
    for settings in (PLAIN, ECS):
        data = format_json(record, settings)
        assert " ".encode("utf-8") not in data
        document = _load(data)
        if settings.ecs_fields:
            assert document["log"]["level"] == "high"
            assert document["message"].startswith("Beaconing from 45.33.12.9: ")
        else:
            assert document["severity"] == "high"
            assert document["event_type"] == "BEACONING"


def test_oversized_message_is_truncated_and_marked() -> None:
    record = _record(details="é" * 4000)
    for settings in (PLAIN, ECS):
        data = format_json(record, settings, max_bytes=2048)
        assert len(data) <= 2048
        document = _load(data)
        if settings.ecs_fields:
            assert document["netsentry"]["truncated"] is True
            assert document["message"].endswith("[truncated]")
        else:
            assert document["truncated"] is True
            assert document["details"].endswith("[truncated]")
            assert document["source_ip"] == "45.33.12.9"


def test_invalid_utf8_is_encoded_safely() -> None:
    raw = b"\xff\xfe.example.com".decode("utf-8", errors="surrogateescape")
    document = _load(format_json(_record(details=raw), PLAIN))
    assert document["details"] == "\\udcff\\udcfe.example.com"
