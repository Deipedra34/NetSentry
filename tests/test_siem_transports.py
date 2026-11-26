"""Tests for :mod:`src.siem.transports`, against local test sockets only."""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path
from typing import Any, List

import pytest

from src.siem.transports import (
    TcpTransport,
    TlsTransport,
    UdpTransport,
    describe_error,
    frame,
    resolve,
    tls_context,
)
from tests.siem_helpers import Collector, SiemPki, UdpCollector, ipv4_only_resolver, make_pki


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> SiemPki:
    return make_pki(tmp_path_factory.mktemp("pki"))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- framing -------------------------------------------------------------


def test_octet_counting_frame() -> None:
    assert frame(b"<13>1 hello", "octet_counting") == b"11 <13>1 hello"
    # the count is in bytes, not characters
    assert frame("é".encode("utf-8"), "octet_counting") == b"2 \xc3\xa9"


def test_newline_frame() -> None:
    assert frame(b'{"a":1}', "newline") == b'{"a":1}\n'


# --- UDP -----------------------------------------------------------------


def test_udp_delivers_one_datagram_per_message() -> None:
    collector = UdpCollector()
    try:
        transport = UdpTransport("127.0.0.1", collector.port)
        transport.send(b"<13>1 first")
        transport.send(b"<13>1 second")
        assert collector.wait_for(2)
        assert collector.datagrams == [b"<13>1 first", b"<13>1 second"]
        transport.close()
        assert not transport.connected
    finally:
        collector.stop()


def test_udp_caps_the_datagram_size() -> None:
    collector = UdpCollector()
    try:
        transport = UdpTransport("127.0.0.1", collector.port)
        transport.send(b"x" * 20000)
        assert collector.wait_for(1)
        assert len(collector.datagrams[0]) == transport.max_bytes == 8192
    finally:
        collector.stop()


# --- TCP -----------------------------------------------------------------


def test_tcp_uses_octet_counting() -> None:
    collector = Collector()
    try:
        transport = TcpTransport("127.0.0.1", collector.port)
        transport.send(b"<13>1 one")
        transport.send(b"<13>1 two with\nnewline")
        assert collector.wait_for(lambda c: len(c.messages()) == 2)
        assert collector.messages() == [b"<13>1 one", b"<13>1 two with\nnewline"]
        assert collector.data.startswith(b"9 <13>1 one")
    finally:
        collector.stop()


def test_tcp_newline_framing() -> None:
    collector = Collector()
    try:
        transport = TcpTransport("127.0.0.1", collector.port, framing="newline")
        transport.send(b'{"a":1}')
        transport.send(b'{"b":2}')
        assert collector.wait_for(lambda c: c.data.count(b"\n") == 2)
        assert collector.data == b'{"a":1}\n{"b":2}\n'
    finally:
        collector.stop()


def test_tcp_reconnects_after_the_collector_drops_the_connection() -> None:
    collector = Collector()
    try:
        transport = TcpTransport("127.0.0.1", collector.port)
        transport.send(b"before")
        assert collector.wait_for(lambda c: c.messages() == [b"before"])
        collector.drop_connections()
        assert collector.wait_for(lambda c: c.connections == 1)
        transport.send(b"after")
        assert collector.wait_for(lambda c: c.messages() == [b"before", b"after"])
        assert collector.connections == 2
    finally:
        collector.stop()


def test_tcp_collector_down_then_back_on_the_same_port() -> None:
    port = _free_port()
    transport = TcpTransport("127.0.0.1", port)
    with pytest.raises(ConnectionRefusedError):
        transport.send(b"lost")
    assert not transport.connected
    collector = Collector(port=port)
    try:
        transport.send(b"restored")
        assert collector.wait_for(lambda c: c.messages() == [b"restored"])
    finally:
        collector.stop()


def test_tcp_tries_every_resolved_address() -> None:
    collector = Collector()
    refused = _free_port()

    def resolver(host: str, port: int, *args: Any) -> List[Any]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", refused)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", collector.port)),
        ]

    try:
        transport = TcpTransport("collector.test", collector.port, resolver=resolver)
        transport.send(b"second address")
        assert collector.wait_for(lambda c: c.messages() == [b"second address"])
    finally:
        collector.stop()


# --- resolution ----------------------------------------------------------


def test_resolve_takes_ip_addresses_as_they_are() -> None:
    calls: List[Any] = []

    def resolver(*args: Any) -> List[Any]:
        calls.append(args)
        return [("addr",)]

    assert resolve("10.0.0.5", 514, socket.SOCK_DGRAM, resolver=resolver) == [("addr",)]
    assert calls[0][-1] == socket.AI_NUMERICHOST


def test_resolve_times_out_on_a_stuck_dns_server() -> None:
    release = threading.Event()

    def resolver(host: str, port: int, family: int = 0, socktype: int = 0, proto: int = 0, flags: int = 0) -> Any:
        if flags & socket.AI_NUMERICHOST:
            raise socket.gaierror("not numeric")
        release.wait(10)
        return []

    try:
        with pytest.raises(socket.timeout, match="resolving collector.test timed out"):
            resolve("collector.test", 514, socket.SOCK_STREAM, timeout=0.05, resolver=resolver)
    finally:
        release.set()


def test_resolve_passes_lookup_errors_on() -> None:
    def resolver(*args: Any) -> Any:
        raise socket.gaierror("Name or service not known")

    with pytest.raises(socket.gaierror):
        resolve("no-such-host.invalid", 514, socket.SOCK_STREAM, resolver=resolver)


# --- errors --------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ConnectionRefusedError(), "connection refused"),
        (socket.timeout(), "timed out"),
        (TimeoutError(), "timed out"),
        (socket.gaierror(), "hostname could not be resolved"),
        (ConnectionResetError(), "connection lost"),
        (BrokenPipeError(), "connection lost"),
        (OSError(28, "No space left on device"), "No space left on device"),
        (ValueError("x"), "ValueError"),
    ],
)
def test_describe_error(error: BaseException, reason: str) -> None:
    assert describe_error(error) == reason


# --- TLS -----------------------------------------------------------------


def test_tls_context_requires_tls12_and_verifies_by_default(pki: SiemPki) -> None:
    context = tls_context(ca_file=str(pki.ca_file))
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_tls_delivery_with_a_verified_certificate(pki: SiemPki) -> None:
    collector = Collector(context=pki.server_context())
    try:
        transport = TlsTransport(
            "localhost", collector.port, tls_context(ca_file=str(pki.ca_file)), resolver=ipv4_only_resolver
        )
        transport.send(b"<13>1 over tls")
        assert collector.wait_for(lambda c: c.messages() == [b"<13>1 over tls"])
    finally:
        collector.stop()


def test_tls_fails_on_the_wrong_hostname(pki: SiemPki) -> None:
    collector = Collector(context=pki.server_context())
    try:
        # the certificate names "localhost" only
        transport = TlsTransport("127.0.0.1", collector.port, tls_context(ca_file=str(pki.ca_file)))
        with pytest.raises(ssl.SSLCertVerificationError) as raised:
            transport.send(b"never sent")
        assert describe_error(raised.value).startswith("TLS certificate verification failed")
        assert "mismatch" in describe_error(raised.value).lower() or "match" in describe_error(raised.value)
        assert not transport.connected
    finally:
        collector.stop()


def test_tls_fails_against_an_unknown_ca(pki: SiemPki, tmp_path: Path) -> None:
    other = make_pki(tmp_path)
    collector = Collector(context=pki.server_context())
    try:
        transport = TlsTransport(
            "localhost", collector.port, tls_context(ca_file=str(other.ca_file)), resolver=ipv4_only_resolver
        )
        with pytest.raises(ssl.SSLCertVerificationError):
            transport.send(b"never sent")
    finally:
        collector.stop()


def test_tls_without_verification_accepts_any_certificate(pki: SiemPki) -> None:
    collector = Collector(context=pki.server_context())
    try:
        transport = TlsTransport("127.0.0.1", collector.port, tls_context(verify=False))
        transport.send(b"unverified")
        assert collector.wait_for(lambda c: c.messages() == [b"unverified"])
    finally:
        collector.stop()


def test_mutual_tls_sends_the_client_certificate(pki: SiemPki) -> None:
    collector = Collector(context=pki.server_context(require_client_cert=True))
    try:
        context = tls_context(
            ca_file=str(pki.ca_file), client_cert=str(pki.client_cert), client_key=str(pki.client_key)
        )
        transport = TlsTransport("localhost", collector.port, context, resolver=ipv4_only_resolver)
        transport.send(b"mutual")
        assert collector.wait_for(lambda c: c.messages() == [b"mutual"])
        subject = dict(item[0] for item in collector.peer_certs[0]["subject"])
        assert subject["commonName"] == "netsentry-sensor"
    finally:
        collector.stop()


def test_tls_reconnects_after_the_collector_drops_the_connection(pki: SiemPki) -> None:
    collector = Collector(context=pki.server_context())
    try:
        transport = TlsTransport(
            "localhost", collector.port, tls_context(ca_file=str(pki.ca_file)), resolver=ipv4_only_resolver
        )
        transport.send(b"one")
        assert collector.wait_for(lambda c: c.messages() == [b"one"])
        collector.drop_connections()
        assert collector.wait_for(lambda c: c.connections == 1)
        transport.send(b"two")
        assert collector.wait_for(lambda c: c.messages() == [b"one", b"two"])
        assert collector.connections == 2
    finally:
        collector.stop()


@pytest.mark.parametrize("setting", ["ca_file", "client_cert", "client_key"])
def test_tls_context_names_a_missing_file(tmp_path: Path, pki: SiemPki, setting: str) -> None:
    files = {"ca_file": str(pki.ca_file), "client_cert": str(pki.client_cert), "client_key": str(pki.client_key)}
    files[setting] = str(tmp_path / "missing.pem")
    with pytest.raises(FileNotFoundError) as raised:
        tls_context(**files)
    assert raised.value.filename == files[setting]
    assert describe_error(raised.value) == f"{setting} not found"
