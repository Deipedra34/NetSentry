"""Tests for :mod:`src.siem.cef`."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import pytest

from src import __version__
from src.database import Event, ThreatIntelResult
from src.siem.cef import format_cef
from src.siem.formatting import FormatSettings
from src.siem.normalize import make_test_event, normalize_event
from tests.conftest import make_packet

SETTINGS = FormatSettings(hostname="sensor-1")
WHEN = datetime(2026, 11, 26, 9, 15, 2, 123000, tzinfo=timezone.utc)
_KEY = re.compile(r"(?:^| )([A-Za-z0-9]+)=")


def _record(details: str = "20 ports in 10s", **kwargs: Any) -> Dict[str, Any]:
    event = Event(
        event_type=kwargs.pop("event_type", "PORT_SCAN"),
        source_ip=kwargs.pop("source_ip", "45.33.12.9"),
        details=details,
        timestamp=WHEN,
        id=kwargs.pop("id", 11),
        **kwargs,
    )
    packet = make_packet(1.0, src_ip=event.source_ip, dst_ip="10.0.0.2", src_port=40000, dst_port=22)
    return normalize_event(
        event,
        packet=packet,
        sensor="sensor-1",
        geo=kwargs.get("geo"),
    )


def _unescape_header(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _unescape_extension(value: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r"}.get(m.group(1), m.group(1)), value)


def parse(message: bytes) -> Tuple[List[str], List[Tuple[str, str]]]:
    """(the 7 header fields unescaped, the extension's key/value pairs)."""
    text = message.decode("utf-8")
    assert "\n" not in text and "\r" not in text
    fields: List[str] = []
    current = ""
    index = 0
    while len(fields) < 7:
        char = text[index]
        if char == "\\":
            current += text[index : index + 2]
            index += 2
            continue
        if char == "|":
            fields.append(current)
            current = ""
        else:
            current += char
        index += 1
    extension = text[index:]
    keys = list(_KEY.finditer(extension))
    pairs = []
    for position, match in enumerate(keys):
        end = keys[position + 1].start() if position + 1 < len(keys) else len(extension)
        pairs.append((match.group(1), _unescape_extension(extension[match.end() : end])))
    return [_unescape_header(field) for field in fields], pairs


def test_header() -> None:
    header, _ = parse(format_cef(_record(), SETTINGS))
    assert header == ["CEF:0", "NetSentry", "NetSentry", __version__, "PORT_SCAN", "Port scan", "3"]


@pytest.mark.parametrize(
    ("event_type", "severity"), [("PORT_SCAN", "3"), ("ML_ANOMALY", "5"), ("BEACONING", "8"), ("SYN_FLOOD", "10")]
)
def test_severity_is_0_to_10(event_type: str, severity: str) -> None:
    header, _ = parse(format_cef(_record(event_type=event_type), SETTINGS))
    assert header[6] == severity


def test_standard_extension_keys() -> None:
    _, pairs = parse(format_cef(_record(), SETTINGS))
    values = dict(pairs)
    assert values["rt"] == str(int(WHEN.timestamp() * 1000))
    assert values["src"] == "45.33.12.9"
    assert values["spt"] == "40000"
    assert values["dst"] == "10.0.0.2"
    assert values["dpt"] == "22"
    assert values["proto"] == "TCP"
    assert values["smac"] == "aa:aa:aa:aa:aa:aa"
    assert values["dvchost"] == "sensor-1"
    assert values["externalId"] == "11"
    assert values["msg"] == "20 ports in 10s"
    assert (values["cs1Label"], values["cs1"]) == ("severity", "low")
    assert (values["flexNumber1Label"], values["flexNumber1"]) == ("schemaVersion", "1")
    # msg goes last
    assert pairs[-1][0] == "msg"


def test_custom_fields_come_with_their_labels() -> None:
    record = _record()
    record.update(
        source_country="Germany",
        source_asn=24940,
        source_as_org="Hetzner Online GmbH",
        source_abuse_score=87,
        source_vt_malicious=12,
    )
    values = dict(parse(format_cef(record, SETTINGS))[1])
    assert (values["cs2Label"], values["cs2"]) == ("sourceCountry", "Germany")
    assert (values["cs4Label"], values["cs4"]) == ("sourceNetwork", "AS24940 Hetzner Online GmbH")
    assert (values["cn1Label"], values["cn1"]) == ("sourceAbuseScore", "87")
    assert (values["cn2Label"], values["cn2"]) == ("sourceVirusTotalMalicious", "12")
    assert "cs3" not in values and "cs3Label" not in values


def test_missing_fields_are_left_out() -> None:
    record = normalize_event(Event(event_type="DHCP_STARVATION", source_ip="0.0.0.0", details="x", timestamp=WHEN))
    keys = [key for key, _ in parse(format_cef(record, SETTINGS))[1]]
    for key in ("src", "dst", "spt", "dpt", "proto", "externalId", "cs2"):
        assert key not in keys
    assert b"None" not in format_cef(record, SETTINGS)


def test_ipv6_addresses_use_the_ipv6_fields() -> None:
    values = dict(parse(format_cef(_record(source_ip="2001:db8::1"), SETTINGS))[1])
    assert "src" not in values
    assert (values["c6a2Label"], values["c6a2"]) == ("Source IPv6 Address", "2001:db8::1")


def test_test_event_is_flagged() -> None:
    record = normalize_event(make_test_event())
    header, pairs = parse(format_cef(record, SETTINGS))
    assert header[4] == "siem_test"
    values = dict(pairs)
    assert (values["cs6Label"], values["cs6"]) == ("netsentryFlags", "test")


def test_header_fields_are_escaped() -> None:
    record = _record(event_type="WEIRD|TYPE\\X")
    message = format_cef(record, SETTINGS)
    assert b"|WEIRD\\|TYPE\\\\X|" in message
    header, _ = parse(message)
    assert header[4] == "WEIRD|TYPE\\X"
    assert len(header) == 7


@pytest.mark.parametrize(
    "payload",
    [
        "evil.com cs6Label=injected cs6=owned",
        "evil.com\nCEF:0|Fake|Fake|1|X|forged|10|src=6.6.6.6",
        "evil.com\r\nforged",
        "back\\slash=and|pipe",
        'q"uote]bracket',
    ],
)
def test_log_injection_cannot_add_keys_or_lines(payload: str) -> None:
    record = _record(details=payload)
    record["sensor"] = payload
    record["source_country"] = payload
    message = format_cef(record, FormatSettings(hostname=payload, version=payload))
    assert b"\n" not in message and b"\r" not in message
    header, pairs = parse(message)
    assert len(header) == 7
    keys = [key for key, _ in pairs]
    assert len(keys) == len(set(keys)), keys  # nothing duplicated or forged
    assert "cs6" not in keys or dict(pairs)["cs6"] != "owned"
    # each value round-trips as exactly one value; line breaks travel as
    # CEF's \n / \r escapes, never as real ones (CRLF is sent as one \n)
    expected = payload.replace("\r\n", "\n")
    assert dict(pairs)["dvchost"] == expected
    assert dict(pairs)["cs2"] == expected


def test_equals_signs_in_values_are_escaped() -> None:
    message = format_cef(_record(details="a=b"), SETTINGS)
    assert b"msg=a\\=b" in message
    assert dict(parse(message)[1])["msg"] == "a=b"


def test_oversized_message_is_truncated_and_marked() -> None:
    message = format_cef(_record(details="=" * 4000), SETTINGS, max_bytes=1500)
    assert len(message) <= 1500
    values = dict(parse(message)[1])
    assert values["cs6"] == "truncated"
    assert values["msg"].endswith("[truncated]")
    assert values["src"] == "45.33.12.9"


def test_invalid_utf8_is_encoded_safely() -> None:
    raw = b"\xff\xfe host".decode("utf-8", errors="surrogateescape")
    format_cef(_record(details=raw), SETTINGS).decode("utf-8")


def test_threat_intel_for_the_destination() -> None:
    event = Event(
        event_type="BEACONING", source_ip="10.0.0.5", details="x", timestamp=WHEN, destination_ip="8.8.8.8"
    )
    record = normalize_event(event, threat=ThreatIntelResult(source_ip="8.8.8.8", abuseipdb_score=3))
    values = dict(parse(format_cef(record, SETTINGS))[1])
    assert (values["cn3Label"], values["cn3"]) == ("destinationAbuseScore", "3")
