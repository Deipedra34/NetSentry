"""Turns an Event into the one flat dict every SIEM format is built from.

normalize_event() works for any event type, including ones a future
detector adds: nothing here lists event types. Fields that don't apply --
no destination, no port, no GeoIP data -- are left out entirely, never sent
as None or "None". Every string is cleaned (see sanitize.py) and capped,
so the formats only have to escape for their own syntax.

The fields, in order (see README.md "SIEM and Syslog Forwarding" for the
reference): schema_version, timestamp, event_type, event_name, event_id,
severity, severity_score, sensor, source_ip, source_port, source_mac,
destination_ip, destination_port, protocol, interface, details,
{source,destination}_{country,country_code,city,asn,as_org},
{source,destination}_{abuse_score,abuse_reports,vt_malicious,vt_engines},
and test (only on the synthetic --siem-test event).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional

from src.database import Event, ThreatIntelResult
from src.packet_info import PacketInfo
from src.siem.sanitize import MAX_DETAILS_LENGTH, clean_text
from src.siem.severity import event_severity, severity_score

# bumped whenever a field is renamed or changes meaning, so parsers
# downstream can tell; adding a field doesn't bump it
SCHEMA_VERSION = 1

# event_type of the synthetic event --siem-test sends, so it's never
# mistaken for a real detection
TEST_EVENT_TYPE = "siem_test"
TEST_EVENT_DETAILS = "NetSentry SIEM forwarding test event -- not a real detection"

# kept upper case in event_name ("DNS tunnel", "TLS anomaly")
_ACRONYMS = {"ARP", "DHCP", "DNS", "DOS", "ICMP", "IP", "ML", "SIEM", "SYN", "TCP", "TLS", "UDP"}

# GeoIPLookup.locate() field -> suffix after "source_" / "destination_"
_GEO_FIELDS = {
    "country_name": "country",
    "country_iso_code": "country_code",
    "city_name": "city",
    "as_number": "asn",
    "as_organization": "as_org",
}
# ThreatIntelResult attribute -> suffix after "source_" / "destination_"
_THREAT_FIELDS = {
    "abuseipdb_score": "abuse_score",
    "abuseipdb_reports": "abuse_reports",
    "virustotal_malicious_count": "vt_malicious",
    "virustotal_total_engines": "vt_engines",
}

GeoLookup = Callable[[str], Mapping[str, Any]]


def event_name(event_type: str) -> str:
    """A readable name for an event type: "PORT_SCAN" -> "Port scan",
    "DNS_TUNNEL" -> "DNS tunnel"."""
    words = [word for word in clean_text(event_type).replace("-", "_").split("_") if word]
    named = [word.upper() if word.upper() in _ACRONYMS else word.lower() for word in words]
    if named and named[0].islower():
        named[0] = named[0].capitalize()
    return " ".join(named) or "Event"


def format_timestamp(moment: datetime) -> str:
    """moment as an RFC 3339 UTC timestamp with milliseconds, e.g.
    "2026-11-26T09:15:02.123Z". A naive datetime is taken as UTC, which
    is what Event.timestamp always is."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def make_test_event() -> Event:
    """The synthetic event --siem-test sends: TEST_EVENT_TYPE, no IPs."""
    return Event(event_type=TEST_EVENT_TYPE, source_ip="", details=TEST_EVENT_DETAILS)


def _ip(value: Any) -> Optional[str]:
    """value as a normalized IP address string, or None if it isn't one --
    including the unspecified addresses (0.0.0.0, ::) detectors use when an
    event has no real IP, such as DHCP starvation from a client that has
    no address yet."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return None if address.is_unspecified else str(address)


def _port(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value <= 65535 else None


def _number(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _put(record: Dict[str, Any], key: str, value: Any, max_length: int = 256) -> None:
    """Adds key to record if value is present, cleaning strings."""
    if value is None:
        return
    if isinstance(value, str):
        value = clean_text(value, max_length)
        if not value:
            return
    record[key] = value


def normalize_event(
    event: Event,
    *,
    packet: Optional[PacketInfo] = None,
    geo: Optional[GeoLookup] = None,
    threat: Optional[ThreatIntelResult] = None,
    sensor: str = "",
    include_details: bool = True,
) -> Dict[str, Any]:
    """The normalized field set for event.

    packet is the packet that triggered the event: its ports, source MAC,
    protocol and interface are used when it comes from the event's source
    (and its destination when the event names none). geo is a lookup like
    GeoIPLookup.locate, threat a ThreatIntelResult for the event's source or
    destination IP. sensor names this NetSentry instance.
    """
    severity = event_severity(event.event_type)
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": format_timestamp(event.timestamp),
    }
    _put(record, "event_type", event.event_type or "UNKNOWN")
    record["event_name"] = event_name(event.event_type or "UNKNOWN")
    _put(record, "event_id", _number(event.id))
    record["severity"] = severity
    record["severity_score"] = severity_score(severity)
    _put(record, "sensor", sensor)

    source = _ip(event.source_ip)
    destination = _ip(event.destination_ip)
    from_source = packet is not None and (source is None or _ip(packet.src_ip) == source)
    if from_source and destination is None:
        destination = _ip(packet.dst_ip if packet is not None else None)

    _put(record, "source_ip", source)
    if from_source and packet is not None:
        _put(record, "source_port", _port(packet.src_port))
        _put(record, "source_mac", packet.src_mac)
    _put(record, "destination_ip", destination)
    if from_source and packet is not None and destination and _ip(packet.dst_ip) == destination:
        _put(record, "destination_port", _port(packet.dst_port))
    if from_source and packet is not None:
        _put(record, "protocol", packet.protocol)
        _put(record, "interface", packet.interface)
    if include_details:
        _put(record, "details", event.details, MAX_DETAILS_LENGTH)

    for role, ip in (("source", source), ("destination", destination)):
        if ip is None:
            continue
        if geo is not None:
            located = geo(ip) or {}
            for field_name, suffix in _GEO_FIELDS.items():
                _put(record, f"{role}_{suffix}", located.get(field_name))
        if threat is not None and _ip(threat.source_ip) == ip:
            for attribute, suffix in _THREAT_FIELDS.items():
                _put(record, f"{role}_{suffix}", _number(getattr(threat, attribute, None)))

    if event.event_type == TEST_EVENT_TYPE:
        record["test"] = True
    return record
