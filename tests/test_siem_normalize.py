"""Tests for :mod:`src.siem.normalize`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from src.database import Event, ThreatIntelResult
from src.detectors import DHCPDetector
from src.siem.normalize import (
    SCHEMA_VERSION,
    TEST_EVENT_TYPE,
    event_name,
    format_timestamp,
    make_test_event,
    normalize_event,
)
from src.web import EVENT_TYPES
from tests.conftest import make_packet

WHEN = datetime(2026, 11, 26, 9, 15, 2, 123456, tzinfo=timezone.utc)
GEO: Dict[str, Dict[str, Any]] = {
    "45.33.12.9": {
        "country_name": "Germany",
        "country_iso_code": "DE",
        "city_name": "Frankfurt am Main",
        "as_number": 24940,
        "as_organization": "Hetzner Online GmbH",
    },
    "8.8.8.8": {"country_name": "United States", "country_iso_code": "US"},
}


def _event(event_type: str = "PORT_SCAN", source_ip: str = "45.33.12.9", **kwargs: Any) -> Event:
    return Event(
        event_type=event_type,
        source_ip=source_ip,
        details=kwargs.pop("details", "something happened"),
        timestamp=kwargs.pop("timestamp", WHEN),
        **kwargs,
    )


def _no_none_anywhere(record: Dict[str, Any]) -> None:
    for key, value in record.items():
        assert value is not None, key
        assert value != "None", key
        assert value != "", key


@pytest.mark.parametrize("event_type", EVENT_TYPES)
def test_every_event_type_normalizes(event_type: str) -> None:
    record = normalize_event(_event(event_type, id=7), packet=make_packet(1.0, src_ip="45.33.12.9"))
    assert record["schema_version"] == SCHEMA_VERSION
    assert record["event_type"] == event_type
    assert record["event_id"] == 7
    assert record["severity"] in {"low", "medium", "high", "critical"}
    assert isinstance(record["severity_score"], int)
    assert record["source_ip"] == "45.33.12.9"
    assert "test" not in record
    _no_none_anywhere(record)


@pytest.mark.parametrize("event_type", EVENT_TYPES)
def test_every_event_type_normalizes_without_any_ip(event_type: str) -> None:
    record = normalize_event(_event(event_type, source_ip=""))
    for key in ("source_ip", "destination_ip", "source_port", "destination_port", "protocol"):
        assert key not in record
    _no_none_anywhere(record)


def test_a_future_event_type_works_without_changes() -> None:
    record = normalize_event(_event("QUANTUM_ENTANGLEMENT_ABUSE"))
    assert record["event_type"] == "QUANTUM_ENTANGLEMENT_ABUSE"
    assert record["event_name"] == "Quantum entanglement abuse"
    assert record["severity"] == "low"


def test_field_order_and_basic_values() -> None:
    packet = make_packet(1.0, src_ip="45.33.12.9", dst_ip="10.0.0.2", src_port=40000, dst_port=22)
    packet.interface = "eth0"
    record = normalize_event(_event("BRUTE_FORCE", id=3), packet=packet, sensor="sensor-1")
    assert list(record) == [
        "schema_version",
        "timestamp",
        "event_type",
        "event_name",
        "event_id",
        "severity",
        "severity_score",
        "sensor",
        "source_ip",
        "source_port",
        "source_mac",
        "destination_ip",
        "destination_port",
        "protocol",
        "interface",
        "details",
    ]
    assert record["timestamp"] == "2026-11-26T09:15:02.123Z"
    assert (record["source_port"], record["destination_ip"], record["destination_port"]) == (40000, "10.0.0.2", 22)
    assert record["protocol"] == "TCP"


def test_dhcp_starvation_from_the_real_detector_is_identified_by_mac() -> None:
    detector = DHCPDetector(starvation_max_clients=3, starvation_window_seconds=30)
    events: List[Event] = []
    packet = None
    for index in range(3):
        packet = make_packet(
            1.0 + index,
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            protocol="UDP",
            src_port=68,
            dst_port=67,
            tcp_flags=None,
            dhcp_message_type="DISCOVER",
            dhcp_chaddr=f"02:00:00:00:00:0{index}",
            src_mac="de:ad:be:ef:00:01",
        )
        events += detector.process_packet(packet)
    assert len(events) == 1
    record = normalize_event(events[0], packet=packet)
    assert record["event_type"] == "DHCP_STARVATION"
    assert "source_ip" not in record  # 0.0.0.0 is no address
    assert record["source_mac"] == "de:ad:be:ef:00:01"
    assert record["destination_ip"] == "255.255.255.255"
    assert record["protocol"] == "UDP"
    _no_none_anywhere(record)


def test_event_destination_wins_over_the_packet() -> None:
    packet = make_packet(1.0, src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=443)
    record = normalize_event(_event("DATA_EXFILTRATION", "10.0.0.5", destination_ip="8.8.8.8"), packet=packet)
    assert record["destination_ip"] == "8.8.8.8"
    # the packet went somewhere else, so its port isn't this destination's
    assert "destination_port" not in record


def test_a_packet_from_another_source_is_ignored() -> None:
    packet = make_packet(1.0, src_ip="10.9.9.9", dst_ip="10.0.0.2")
    record = normalize_event(_event(), packet=packet)
    for key in ("source_port", "source_mac", "destination_ip", "protocol"):
        assert key not in record


def test_ipv6_addresses_are_normalized() -> None:
    record = normalize_event(_event(source_ip="2001:DB8:0:0::1"))
    assert record["source_ip"] == "2001:db8::1"


def test_values_that_are_not_ips_are_dropped() -> None:
    record = normalize_event(_event(source_ip="not-an-ip\n<13>forged"))
    assert "source_ip" not in record


def test_geo_and_threat_intel_fields_when_present() -> None:
    threat = ThreatIntelResult(
        source_ip="45.33.12.9",
        abuseipdb_score=87,
        abuseipdb_reports=42,
        virustotal_malicious_count=12,
        virustotal_total_engines=94,
    )
    record = normalize_event(
        _event("BEACONING", destination_ip="8.8.8.8"),
        geo=lambda ip: GEO.get(ip, {}),
        threat=threat,
    )
    assert record["source_country"] == "Germany"
    assert record["source_country_code"] == "DE"
    assert record["source_city"] == "Frankfurt am Main"
    assert record["source_asn"] == 24940
    assert record["source_as_org"] == "Hetzner Online GmbH"
    assert record["source_abuse_score"] == 87
    assert record["source_abuse_reports"] == 42
    assert record["source_vt_malicious"] == 12
    assert record["source_vt_engines"] == 94
    assert record["destination_country"] == "United States"
    assert "destination_city" not in record
    assert "destination_abuse_score" not in record


def test_threat_intel_for_the_destination() -> None:
    threat = ThreatIntelResult(source_ip="8.8.8.8", abuseipdb_score=5)
    record = normalize_event(_event("BEACONING", "10.0.0.5", destination_ip="8.8.8.8"), threat=threat)
    assert record["destination_abuse_score"] == 5
    assert "source_abuse_score" not in record
    assert "destination_vt_malicious" not in record


def test_include_details_false_leaves_details_out() -> None:
    assert "details" not in normalize_event(_event(), include_details=False)


def test_strings_are_cleaned() -> None:
    record = normalize_event(_event(details="evil.com\n<13>1 forged line\x00", source_ip=""), sensor="a\nb")
    assert record["details"] == "evil.com\\n<13>1 forged line\\x00"
    assert record["sensor"] == "a\\nb"


def test_details_are_capped() -> None:
    record = normalize_event(_event(details="x" * 10000))
    assert len(record["details"]) == 4096
    assert record["details"].endswith("[truncated]")


def test_invalid_utf8_in_details_is_safe() -> None:
    raw = b"q=\xff\xfe.example.com".decode("utf-8", errors="surrogateescape")
    record = normalize_event(_event(details=raw))
    record["details"].encode("utf-8")  # must not raise
    assert "\\udcff" in record["details"]


def test_test_event_is_clearly_labeled() -> None:
    record = normalize_event(make_test_event())
    assert record["event_type"] == TEST_EVENT_TYPE == "siem_test"
    assert record["test"] is True
    assert "not a real detection" in record["details"]
    assert "source_ip" not in record


@pytest.mark.parametrize(
    ("event_type", "name"),
    [
        ("PORT_SCAN", "Port scan"),
        ("DNS_TUNNEL", "DNS tunnel"),
        ("TLS_ANOMALY", "TLS anomaly"),
        ("ML_ANOMALY", "ML anomaly"),
        ("ROGUE_DHCP_SERVER", "Rogue DHCP server"),
        ("SYN_FLOOD", "SYN flood"),
        ("siem_test", "SIEM test"),
        ("", "Event"),
    ],
)
def test_event_name(event_type: str, name: str) -> None:
    assert event_name(event_type) == name


def test_format_timestamp_converts_to_utc() -> None:
    plus_three = timezone(timedelta(hours=3))
    assert format_timestamp(datetime(2026, 1, 1, 3, 0, 0, tzinfo=plus_three)) == "2026-01-01T00:00:00.000Z"
    assert format_timestamp(datetime(2026, 1, 1, 12, 30, 5, 999999)) == "2026-01-01T12:30:05.999Z"
