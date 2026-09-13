"""Minimal parsing of plaintext TLS handshake messages.

Only extracts exactly what `TLSAnomalyDetector` (src/detectors.py) needs: a
JA3 fingerprint from a ClientHello, and issuer/subject/validity from a
server Certificate message.

This deliberately hand-rolls the TLS record/handshake framing instead of
reaching for Scapy's TLS layer (`scapy.layers.tls`, present in this
environment) -- that layer is built around constructing and decrypting full
TLS sessions and pulls in a lot of state-machine machinery just to read a
handful of plaintext ClientHello fields; the reference JA3 implementation
(https://github.com/salesforce/ja3) does the same kind of manual struct
parsing for exactly that reason, and it keeps this module trivially unit
testable with hand-built byte strings. Certificate parsing does lean on
`cryptography` (already a NetSentry dependency, used by web.py for
self-signed cert generation) since hand-rolling ASN.1/X.509 parsing would be
far more fragile than TLS's own rigid handshake framing.

Note: TLS 1.3 encrypts every handshake message after ServerHello, so a
Certificate message only ever appears in cleartext -- and is only ever
parseable this way -- on a TLS 1.2 (or earlier) connection. That's a
protocol fact, not a limitation of this parser.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger("netsentry.tls_parser")

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_CERTIFICATE = 0x0B
_EXT_SUPPORTED_GROUPS = 0x000A  # a.k.a. "elliptic curves"
_EXT_EC_POINT_FORMATS = 0x000B

# GREASE values (RFC 8701): placeholder cipher/extension/group IDs some
# clients insert to catch middleboxes that choke on unrecognized values.
# They're randomized per-connection, so JA3 excludes them -- otherwise the
# same client would fingerprint differently on every single handshake.
_GREASE_VALUES = frozenset(
    (b << 12) | 0x0A0A | (b << 4) for b in range(16)
)


@dataclass
class CertificateInfo:
    """Just the fields TLSAnomalyDetector cares about from a leaf cert."""

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime


def _iter_handshake_messages(payload: bytes):
    """Yields (handshake_type, body) for each TLS handshake message found in
    `payload`, which is expected to start with a TLS record header.

    Stops silently the moment anything looks truncated or malformed -- a
    handshake message can legitimately be split across multiple TCP
    segments/TLS records, and reassembling that is out of scope here, so a
    cut-off message is simply not yielded rather than raising.
    """
    offset = 0
    while offset + 5 <= len(payload):
        content_type = payload[offset]
        record_len = int.from_bytes(payload[offset + 3:offset + 5], "big")
        offset += 5
        if content_type != _CONTENT_TYPE_HANDSHAKE:
            return
        if offset + record_len > len(payload):
            return
        record = payload[offset:offset + record_len]
        offset += record_len

        pos = 0
        while pos + 4 <= len(record):
            hs_type = record[pos]
            hs_len = int.from_bytes(record[pos + 1:pos + 4], "big")
            pos += 4
            if pos + hs_len > len(record):
                return
            yield hs_type, record[pos:pos + hs_len]
            pos += hs_len


def parse_client_hello(payload: bytes) -> Optional[str]:
    """Returns the JA3 MD5 hash for the ClientHello found in `payload` (a raw
    TCP payload, TLS record header included), or None if `payload` doesn't
    contain a well-formed one."""
    try:
        for hs_type, body in _iter_handshake_messages(payload):
            if hs_type == _HANDSHAKE_CLIENT_HELLO:
                return _ja3_from_client_hello(body)
    except Exception as exc:  # noqa: BLE001 - malformed/fragmented TLS data must not crash capture
        logger.debug("Failed to parse TLS ClientHello: %s", exc)
    return None


def _ja3_from_client_hello(body: bytes) -> Optional[str]:
    """Builds the JA3 string (SSLVersion,Ciphers,Extensions,EllipticCurves,
    EllipticCurvePointFormats) from a ClientHello body and MD5-hashes it."""
    pos = 2  # skip client_version
    pos += 32  # skip random

    session_id_len = body[pos]
    pos += 1 + session_id_len

    cipher_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    ciphers = [
        int.from_bytes(body[pos + i:pos + i + 2], "big")
        for i in range(0, cipher_len, 2)
    ]
    pos += cipher_len

    compression_len = body[pos]
    pos += 1 + compression_len

    extensions: List[int] = []
    curves: List[int] = []
    point_formats: List[int] = []

    if pos < len(body):
        ext_total_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        ext_end = pos + ext_total_len
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            ext_data = body[pos + 4:pos + 4 + ext_len]
            extensions.append(ext_type)

            if ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                list_len = int.from_bytes(ext_data[0:2], "big")
                curves = [
                    int.from_bytes(ext_data[2 + i:2 + i + 2], "big")
                    for i in range(0, list_len, 2)
                ]
            elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                fmt_len = ext_data[0]
                point_formats = list(ext_data[1:1 + fmt_len])

            pos += 4 + ext_len

    ciphers = [c for c in ciphers if c not in _GREASE_VALUES]
    extensions = [e for e in extensions if e not in _GREASE_VALUES]
    curves = [c for c in curves if c not in _GREASE_VALUES]

    ja3_string = "{},{},{},{},{}".format(
        int.from_bytes(body[0:2], "big"),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in point_formats),
    )
    return hashlib.md5(ja3_string.encode("ascii")).hexdigest()


def parse_certificate(payload: bytes) -> Optional[CertificateInfo]:
    """Returns issuer/subject/validity for the leaf certificate in the TLS
    Certificate handshake message found in `payload`, or None if `payload`
    doesn't contain one, or the DER blob doesn't parse as a certificate."""
    try:
        from cryptography import x509

        for hs_type, body in _iter_handshake_messages(payload):
            if hs_type != _HANDSHAKE_CERTIFICATE:
                continue
            der = _first_certificate_der(body)
            if der is None:
                continue
            cert = x509.load_der_x509_certificate(der)
            return CertificateInfo(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
            )
    except Exception as exc:  # noqa: BLE001 - malformed/fragmented TLS data must not crash capture
        logger.debug("Failed to parse TLS Certificate message: %s", exc)
    return None


def _first_certificate_der(body: bytes) -> Optional[bytes]:
    """`body` is a TLS 1.2-style Certificate handshake message: a 3-byte
    total length for the certificate list, followed by one or more (3-byte
    length, DER bytes) entries. Returns the first (leaf/server)
    certificate's DER bytes.
    """
    if len(body) < 6:
        return None
    cert_list_len = int.from_bytes(body[0:3], "big")
    if 3 + cert_list_len > len(body):
        return None
    cert_len = int.from_bytes(body[3:6], "big")
    if 6 + cert_len > len(body):
        return None
    return body[6:6 + cert_len]
