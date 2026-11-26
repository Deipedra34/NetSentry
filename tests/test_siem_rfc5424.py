"""Tests for :mod:`src.siem.rfc5424` and the size limit in
:mod:`src.siem.formatting`."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import pytest

from src.database import Event
from src.siem.formatting import FormatSettings
from src.siem.normalize import normalize_event
from src.siem.rfc5424 import SD_ID, format_rfc5424, summary
from tests.conftest import make_packet

SETTINGS = FormatSettings(hostname="sensor-1", app_name="netsentry", facility=16, procid="4242")
WHEN = datetime(2026, 11, 26, 9, 15, 2, 123000, tzinfo=timezone.utc)

# RFC 5424 section 6: HEADER SP STRUCTURED-DATA [SP MSG]
HEADER = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
)
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,6}Z$")


def _record(details: str = "20 ports in 10s", **kwargs: Any) -> Dict[str, Any]:
    event = Event(
        event_type=kwargs.pop("event_type", "PORT_SCAN"),
        source_ip=kwargs.pop("source_ip", "45.33.12.9"),
        details=details,
        timestamp=WHEN,
        id=kwargs.pop("id", 11),
        **kwargs,
    )
    return normalize_event(event, packet=make_packet(1.0, src_ip=event.source_ip, dst_port=22), sensor="sensor-1")


def parse(message: bytes) -> Tuple[Dict[str, str], List[Tuple[str, str]], str]:
    """A small strict RFC 5424 parser: (header fields, SD params, MSG).
    Fails the test on anything malformed."""
    text = message.decode("utf-8")
    match = HEADER.match(text)
    assert match, text
    rest = text[match.end():]
    assert rest.startswith(f"[{SD_ID}"), rest
    index = len(SD_ID) + 1
    params: List[Tuple[str, str]] = []
    while True:
        if rest[index] == "]":
            index += 1
            break
        assert rest[index] == " ", rest[index:]
        index += 1
        equals = rest.index("=", index)
        name = rest[index:equals]
        assert re.fullmatch(r'[^= \]"]{1,32}', name), name
        assert rest[equals + 1] == '"'
        index = equals + 2
        value = []
        while rest[index] != '"':
            if rest[index] == "\\" and rest[index + 1] in '"\\]':
                value.append(rest[index + 1])
                index += 2
                continue
            assert rest[index] not in '"]', rest[index:]
            value.append(rest[index])
            index += 1
        index += 1
        params.append((name, "".join(value)))
    message_text = rest[index:]
    assert message_text.startswith(" ") or message_text == ""
    return match.groupdict(), params, message_text[1:]


def test_header_fields() -> None:
    header, _, _ = parse(format_rfc5424(_record(), SETTINGS))
    assert header["pri"] == str(16 * 8 + 5)  # local0, low -> notice
    assert TIMESTAMP.match(header["ts"])
    assert header["ts"] == "2026-11-26T09:15:02.123Z"
    assert header["host"] == "sensor-1"
    assert header["app"] == "netsentry"
    assert header["procid"] == "4242"
    assert header["msgid"] == "PORT_SCAN"


@pytest.mark.parametrize(
    ("event_type", "facility", "pri"),
    [("SYN_FLOOD", 16, 130), ("DNS_TUNNEL", 4, 35), ("TRAFFIC_ANOMALY", 23, 188), ("ICMP_OVERSIZED", 0, 5)],
)
def test_pri_from_facility_and_severity(event_type: str, facility: int, pri: int) -> None:
    settings = FormatSettings(hostname="h", facility=facility, procid="1")
    header, _, _ = parse(format_rfc5424(_record(event_type=event_type), settings))
    assert header["pri"] == str(pri)


def test_structured_data_carries_the_normalized_fields() -> None:
    _, params, message = parse(format_rfc5424(_record(), SETTINGS))
    values = dict(params)
    assert values["event_type"] == "PORT_SCAN"
    assert values["severity"] == "low"
    assert values["source_ip"] == "45.33.12.9"
    assert values["destination_port"] == "22"
    assert values["schema_version"] == "1"
    assert "details" not in values
    assert message == "Port scan from 45.33.12.9: 20 ports in 10s"


def test_only_present_fields_are_sent() -> None:
    _, params, _ = parse(format_rfc5424(_record(source_ip=""), SETTINGS))
    names = [name for name, _ in params]
    assert "source_ip" not in names and "source_country" not in names
    assert all(value not in ("None", "") for _, value in params)


def test_structured_data_values_are_escaped() -> None:
    record = _record()
    record["sensor"] = 'q"uote back\\slash br]acket'
    message = format_rfc5424(record, SETTINGS)
    assert b'sensor="q\\"uote back\\\\slash br\\]acket"' in message
    _, params, _ = parse(message)
    assert dict(params)["sensor"] == 'q"uote back\\slash br]acket'


@pytest.mark.parametrize(
    "payload",
    [
        'evil.com"] [origin@1 ip="6.6.6.6',
        "evil.com\n<13>1 2026-01-01T00:00:00Z attacker app - - - forged line",
        "evil.com\r\n<13>1 forged",
        "a=b|c\\d]e\"f",
        " forged ",
    ],
)
def test_log_injection_through_any_field(payload: str) -> None:
    record = _record(details=payload)
    record["sensor"] = payload
    record["source_country"] = payload
    message = format_rfc5424(record, FormatSettings(hostname=payload, app_name=payload, procid=payload))
    assert b"\n" not in message and b"\r" not in message
    assert " ".encode("utf-8") not in message
    header, params, _ = parse(message)
    # exactly one structured data element, with exactly our parameters
    assert [name for name, _ in params].count("sensor") == 1
    assert "origin@1" not in [name for name, _ in params]
    assert " " not in header["host"] and " " not in header["app"]


def test_invalid_utf8_is_encoded_safely() -> None:
    raw = b"name \xff\xfe".decode("utf-8", errors="surrogateescape")
    message = format_rfc5424(_record(details=raw), SETTINGS)
    message.decode("utf-8")  # valid UTF-8 throughout


def test_non_ascii_message_starts_with_a_bom() -> None:
    message = format_rfc5424(_record(details="São Paulo"), SETTINGS)
    _, _, text = parse(message)
    assert text.startswith("﻿")
    ascii_message = format_rfc5424(_record(), SETTINGS)
    assert not parse(ascii_message)[2].startswith("﻿")


def test_oversized_message_is_truncated_and_marked() -> None:
    message = format_rfc5424(_record(details="A" * 4000), SETTINGS, max_bytes=1024)
    assert len(message) <= 1024
    _, params, text = parse(message)
    assert dict(params)["truncated"] == "true"
    assert text.startswith("Port scan from 45.33.12.9: AAAA")
    assert text.endswith("[truncated]")


def test_a_message_that_fits_is_not_marked() -> None:
    _, params, _ = parse(format_rfc5424(_record(), SETTINGS))
    assert "truncated" not in dict(params)


def test_details_are_cut_before_anything_else() -> None:
    record = _record(details="é" * 4000)  # 2 bytes each
    message = format_rfc5424(record, SETTINGS, max_bytes=2048)
    assert len(message) <= 2048
    _, params, _ = parse(message)
    assert dict(params)["source_ip"] == "45.33.12.9"


def test_even_a_tiny_limit_is_respected() -> None:
    message = format_rfc5424(_record(details="x" * 5000), SETTINGS, max_bytes=200)
    assert len(message) <= 200
    message.decode("utf-8")


def test_summary_falls_back_to_the_mac_or_the_name() -> None:
    assert summary({"event_name": "DHCP starvation", "source_mac": "de:ad:be:ef:00:01"}) == (
        "DHCP starvation from de:ad:be:ef:00:01"
    )
    assert summary({"event_name": "SIEM test", "details": "hello"}) == "SIEM test: hello"
