"""Unit tests for :class:`src.detectors.TLSAnomalyDetector` and the TLS
handshake parsing it relies on (:mod:`src.tls_parser`)."""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from src import tls_parser
from src.detectors import TLSAnomalyDetector
from tests.conftest import make_packet

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def tls_packet(
    timestamp: float,
    src_ip: Optional[str] = "10.0.0.1",
    ja3: Optional[str] = None,
    cert_subject: Optional[str] = None,
    cert_issuer: Optional[str] = None,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
):
    """Build a synthetic TLS packet (TCP/443) with pre-parsed fields already
    attached, the same way tests/test_dns_tunnel.py sets dns_qname/dns_qtype
    directly rather than feeding raw bytes through the real parser."""
    packet = make_packet(
        timestamp=timestamp,
        src_ip=src_ip,
        protocol="TCP",
        src_port=51000,
        dst_port=443,
        tcp_flags="A",
    )
    packet.tls_ja3 = ja3
    packet.tls_cert_subject = cert_subject
    packet.tls_cert_issuer = cert_issuer
    packet.tls_cert_not_before = not_before
    packet.tls_cert_not_after = not_after
    return packet


def _blocklist(tmp_path: Path, *hashes: str) -> str:
    path = tmp_path / "ja3_blocklist.txt"
    path.write_text("# test blocklist\n" + "\n".join(hashes) + "\n")
    return str(path)


# ---------------------------------------------------------------------------
# TLSAnomalyDetector
# ---------------------------------------------------------------------------


def test_packet_without_tls_fields_is_ignored(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(ja3_blocklist_path=_blocklist(tmp_path))
    packet = tls_packet(timestamp=1000.0)
    assert detector.process_packet(packet) == []


def test_normal_handshake_does_not_trigger(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(ja3_blocklist_path=_blocklist(tmp_path, "a" * 32))
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        ja3="b" * 32,
        cert_subject="CN=example.com",
        cert_issuer="CN=Example Trusted CA",
        not_before=NOW - timedelta(days=400),
        not_after=NOW + timedelta(days=300),
    )
    assert detector.process_packet(packet) == []


def test_ja3_blocklist_match_triggers(tmp_path: Path) -> None:
    bad_hash = "deadbeefdeadbeefdeadbeefdeadbeef"
    detector = TLSAnomalyDetector(ja3_blocklist_path=_blocklist(tmp_path, bad_hash))
    packet = tls_packet(timestamp=1000.0, src_ip="10.0.0.9", ja3=bad_hash)

    events = detector.process_packet(packet)

    assert len(events) == 1
    assert events[0].event_type == "TLS_ANOMALY"
    assert events[0].source_ip == "10.0.0.9"
    assert bad_hash in events[0].details


def test_ja3_blocklist_is_case_insensitive(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(
        ja3_blocklist_path=_blocklist(tmp_path, "DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    )
    packet = tls_packet(timestamp=1000.0, ja3="deadbeefdeadbeefdeadbeefdeadbeef")
    assert len(detector.process_packet(packet)) == 1


def test_missing_blocklist_file_just_means_no_matches(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(ja3_blocklist_path=str(tmp_path / "does_not_exist.txt"))
    packet = tls_packet(timestamp=1000.0, ja3="anything")
    assert detector.process_packet(packet) == []


def test_self_signed_triggers_when_enabled(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(
        ja3_blocklist_path=_blocklist(tmp_path),
        flag_self_signed=True,
    )
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        src_ip="10.0.0.5",
        cert_subject="CN=totally-legit.example",
        cert_issuer="CN=totally-legit.example",
        not_before=NOW - timedelta(days=400),
        not_after=NOW + timedelta(days=300),
    )

    events = detector.process_packet(packet)

    assert len(events) == 1
    assert events[0].source_ip == "10.0.0.5"
    assert "self-signed" in events[0].details


def test_self_signed_does_not_trigger_when_disabled(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(
        ja3_blocklist_path=_blocklist(tmp_path),
        flag_self_signed=False,
    )
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        cert_subject="CN=totally-legit.example",
        cert_issuer="CN=totally-legit.example",
        not_before=NOW - timedelta(days=400),
        not_after=NOW + timedelta(days=300),
    )
    assert detector.process_packet(packet) == []


def test_expired_certificate_triggers(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(ja3_blocklist_path=_blocklist(tmp_path))
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        src_ip="10.0.0.7",
        cert_subject="CN=example.com",
        cert_issuer="CN=Example Trusted CA",
        not_before=NOW - timedelta(days=400),
        not_after=NOW - timedelta(days=10),
    )

    events = detector.process_packet(packet)

    assert len(events) == 1
    assert events[0].source_ip == "10.0.0.7"
    assert "expired" in events[0].details


def test_short_validity_period_triggers(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(
        ja3_blocklist_path=_blocklist(tmp_path), flag_short_validity_days=7
    )
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        cert_subject="CN=example.com",
        cert_issuer="CN=Example Trusted CA",
        # issued long enough ago to dodge the "recently issued" check, and
        # still currently valid -- isolates the short-validity signal
        not_before=NOW - timedelta(days=3),
        not_after=NOW + timedelta(days=1),
    )
    events = detector.process_packet(packet)
    assert len(events) == 1
    assert "short validity" in events[0].details


def test_recently_issued_certificate_triggers(tmp_path: Path) -> None:
    detector = TLSAnomalyDetector(
        ja3_blocklist_path=_blocklist(tmp_path), flag_recently_issued_days=2
    )
    packet = tls_packet(
        timestamp=NOW.timestamp(),
        cert_subject="CN=example.com",
        cert_issuer="CN=Example Trusted CA",
        not_before=NOW - timedelta(hours=6),
        not_after=NOW + timedelta(days=300),
    )
    events = detector.process_packet(packet)
    assert len(events) == 1
    assert "recently issued" in events[0].details


def test_cooldown_suppresses_repeat_alerts(tmp_path: Path) -> None:
    bad_hash = "deadbeefdeadbeefdeadbeefdeadbeef"
    detector = TLSAnomalyDetector(ja3_blocklist_path=_blocklist(tmp_path, bad_hash), cooldown=60.0)

    first = detector.process_packet(tls_packet(timestamp=1000.0, ja3=bad_hash))
    second = detector.process_packet(tls_packet(timestamp=1010.0, ja3=bad_hash))
    third = detector.process_packet(tls_packet(timestamp=1100.0, ja3=bad_hash))

    assert len(first) == 1
    assert second == []
    assert len(third) == 1


# ---------------------------------------------------------------------------
# src.tls_parser -- malformed/unparseable data must be skipped, never raised
# ---------------------------------------------------------------------------


def test_parse_client_hello_returns_none_for_non_tls_bytes() -> None:
    assert tls_parser.parse_client_hello(b"not even close to TLS") is None
    assert tls_parser.parse_client_hello(b"") is None


def test_parse_client_hello_returns_none_for_truncated_record() -> None:
    # Claims a 500-byte handshake record but only provides a few bytes.
    truncated = b"\x16\x03\x03" + struct.pack(">H", 500) + b"\x01\x00\x00\x10"
    assert tls_parser.parse_client_hello(truncated) is None


def test_parse_certificate_returns_none_for_non_tls_bytes() -> None:
    assert tls_parser.parse_certificate(b"garbage") is None


def test_parse_certificate_returns_none_for_bad_der() -> None:
    body = _uint24(3 + 4) + _uint24(4) + b"\x00\x01\x02\x03"
    record = _handshake_record(0x0B, body)
    assert tls_parser.parse_certificate(record) is None


# ---------------------------------------------------------------------------
# src.tls_parser -- correctness of the actual parsing/JA3 computation
# ---------------------------------------------------------------------------


def _uint24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def _handshake_record(handshake_type: int, body: bytes, version: int = 0x0303) -> bytes:
    handshake = bytes([handshake_type]) + _uint24(len(body)) + body
    return bytes([0x16]) + struct.pack(">H", version) + struct.pack(">H", len(handshake)) + handshake


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _client_hello_body(version: int, ciphers, extensions_data: bytes) -> bytes:
    body = struct.pack(">H", version)
    body += b"\x00" * 32  # random -- content is irrelevant to JA3
    body += b"\x00"  # session_id length 0
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    body += struct.pack(">H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"  # one compression method (null)
    body += struct.pack(">H", len(extensions_data)) + extensions_data
    return body


def test_parse_client_hello_computes_expected_ja3_hash() -> None:
    ciphers = [0x1301, 0x1302, 0xC02B]  # 4865, 4866, 49195
    extensions_data = (
        _extension(0x0000, b"")  # server_name
        + _extension(0x000A, struct.pack(">H", 4) + struct.pack(">H", 29) + struct.pack(">H", 23))
        + _extension(0x000B, bytes([1, 0]))
    )
    record = _handshake_record(
        0x01, _client_hello_body(0x0303, ciphers, extensions_data)
    )

    ja3 = tls_parser.parse_client_hello(record)

    expected_string = "771,4865-4866-49195,0-10-11,29-23,0"
    assert ja3 == hashlib.md5(expected_string.encode("ascii")).hexdigest()


def test_parse_client_hello_excludes_grease_values() -> None:
    # 0x0A0A/0x2A2A are GREASE placeholders and must be dropped, not hashed.
    ciphers = [0x0A0A, 0x1301, 0x2A2A]
    extensions_data = _extension(0x0A0A, b"") + _extension(0x0000, b"")
    record = _handshake_record(
        0x01, _client_hello_body(0x0303, ciphers, extensions_data)
    )

    ja3 = tls_parser.parse_client_hello(record)

    expected_string = "771,4865,0,,"
    assert ja3 == hashlib.md5(expected_string.encode("ascii")).hexdigest()


def test_parse_certificate_extracts_subject_issuer_and_validity() -> None:
    cryptography = _pytest_importorskip_cryptography()
    x509 = cryptography["x509"]
    hashes = cryptography["hashes"]
    rsa = cryptography["rsa"]
    NameOID = cryptography["NameOID"]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "self-signed.example")]
    )
    not_before = NOW - timedelta(days=1)
    not_after = NOW + timedelta(days=6)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(cryptography["Encoding"].DER)

    cert_entry = _uint24(len(der)) + der
    body = _uint24(len(cert_entry)) + cert_entry
    record = _handshake_record(0x0B, body)

    info = tls_parser.parse_certificate(record)

    assert info is not None
    assert info.subject == info.issuer  # self-signed
    assert "self-signed.example" in info.subject
    assert info.not_before == not_before
    assert info.not_after == not_after


def _pytest_importorskip_cryptography():
    import pytest

    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    return {
        "x509": x509,
        "hashes": hashes,
        "rsa": rsa,
        "NameOID": NameOID,
        "Encoding": serialization.Encoding,
    }
