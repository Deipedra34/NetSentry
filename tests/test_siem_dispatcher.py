"""Tests for :mod:`src.siem.dispatcher`."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.config import Config, SiemDestinationConfig
from src.database import Event
from src.siem.dispatcher import SiemForwarder, framing_for, make_transport
from src.siem.file_output import FileTransport
from src.siem.transports import TcpTransport, TlsTransport, Transport, UdpTransport
from tests.siem_helpers import Collector, FakeClock, SiemPki, UdpCollector, make_pki, split_octet_counted


class _FakeSocket:
    def close(self) -> None:
        pass


class MemoryTransport(Transport):
    """Collects payloads in memory; can be switched off."""

    kind = "tcp"

    def __init__(self, name: str) -> None:
        super().__init__(f"{name}.test", 514)
        self.payloads: List[bytes] = []
        self.up = True

    def connect(self) -> None:
        if not self.up:
            raise ConnectionRefusedError()
        self._sock = _FakeSocket()

    def send(self, payload: bytes) -> None:
        if not self.up:
            self._sock = None
            raise ConnectionRefusedError()
        self.payloads.append(payload)


def _config(destinations: List[Dict[str, Any]], **siem: Any) -> Config:
    config = Config()
    config.siem.enabled = True
    config.siem.destinations = destinations
    config.siem.hostname = "sensor-1"
    for key, value in siem.items():
        setattr(config.siem, key, value)
    return config


def _dest(name: str, fmt: str = "json", **extra: Any) -> Dict[str, Any]:
    entry = {"name": name, "format": fmt, "transport": "tcp", "host": f"{name}.test"}
    entry.update(extra)
    return entry


def _memory_forwarder(config: Config, clock: FakeClock | None = None) -> tuple[SiemForwarder, Dict[str, MemoryTransport]]:
    transports: Dict[str, MemoryTransport] = {}

    def factory(destination: SiemDestinationConfig) -> Transport:
        transports[destination.name] = MemoryTransport(destination.name)
        return transports[destination.name]

    forwarder = SiemForwarder(config, transport_factory=factory, start=False, clock=clock or FakeClock())
    return forwarder, transports


def _drain(forwarder: SiemForwarder) -> None:
    for destination in forwarder.destinations:
        if destination.sender is not None:
            while destination.sender.step():
                pass


def _event(event_type: str = "PORT_SCAN") -> Event:
    return Event(event_type=event_type, source_ip="45.33.12.9", details="probe")


def test_disabled_by_default_and_does_nothing() -> None:
    forwarder = SiemForwarder(Config(), start=False)
    assert forwarder.enabled is False
    assert forwarder.active is False
    forwarder.forward(_event())  # no destinations, no error
    assert forwarder.status() == {"enabled": False, "running": True, "destinations": []}


def test_each_destination_gets_its_own_format() -> None:
    config = _config([_dest("syslog", "rfc5424"), _dest("cef", "cef"), _dest("json", "json")])
    forwarder, transports = _memory_forwarder(config)
    forwarder.forward(_event())
    _drain(forwarder)
    assert transports["syslog"].payloads[0].startswith(b"<133>1 ")
    assert transports["cef"].payloads[0].startswith(b"CEF:0|NetSentry|NetSentry|")
    assert json.loads(transports["json"].payloads[0])["event_type"] == "PORT_SCAN"
    assert b"sensor-1" in transports["syslog"].payloads[0]


def test_min_severity_is_per_destination() -> None:
    config = _config([_dest("all"), _dest("serious", min_severity="high")])
    forwarder, transports = _memory_forwarder(config)
    forwarder.forward(_event("PORT_SCAN"))  # low
    forwarder.forward(_event("SYN_FLOOD"))  # critical
    _drain(forwarder)
    assert [json.loads(p)["event_type"] for p in transports["all"].payloads] == ["PORT_SCAN", "SYN_FLOOD"]
    assert [json.loads(p)["event_type"] for p in transports["serious"].payloads] == ["SYN_FLOOD"]


def test_one_failing_destination_does_not_affect_another() -> None:
    clock = FakeClock()
    forwarder, transports = _memory_forwarder(_config([_dest("down"), _dest("up")]), clock)
    transports["down"].up = False
    for _ in range(5):
        forwarder.forward(_event())
        clock.advance(1)
        _drain(forwarder)
    assert len(transports["up"].payloads) == 5
    status = {d["name"]: d for d in forwarder.status()["destinations"]}
    assert status["up"]["state"] == "connected" and status["up"]["sent"] == 5
    assert status["down"]["state"] == "retrying" and status["down"]["queued"] == 5
    assert status["down"]["last_error"] == "connection refused"


def test_invalid_destination_is_skipped_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    config = _config([_dest("good"), {"name": "bad", "format": "leef", "transport": "tcp", "host": "x"}])
    with caplog.at_level(logging.ERROR, logger="netsentry.siem"):
        forwarder, transports = _memory_forwarder(config)
    assert list(transports) == ["good"]
    assert [d["name"] for d in forwarder.status()["destinations"]] == ["good"]
    assert "siem destination 'bad' is invalid and skipped: format must be one of" in caplog.text


def test_unloadable_tls_files_disable_only_that_destination(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    missing = tmp_path / "secret-dir" / "ca.pem"
    config = _config([
        {"name": "tls", "format": "json", "transport": "tls", "host": "h.test", "ca_file": str(missing)},
        {"name": "file", "format": "json", "transport": "file", "path": str(tmp_path / "events.ndjson")},
    ])
    with caplog.at_level(logging.ERROR, logger="netsentry.siem"):
        forwarder = SiemForwarder(config, start=False)
    status = {d["name"]: d for d in forwarder.status()["destinations"]}
    assert status["tls"]["state"] == "disabled"
    assert status["tls"]["last_error"].startswith("TLS files could not be loaded")
    assert "secret-dir" not in json.dumps(forwarder.status())  # no paths on the dashboard
    assert str(missing) in caplog.text  # but the log says which file
    assert status["file"]["state"] == "connecting"
    assert forwarder.active


def test_unverified_tls_logs_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    config = _config([{"name": "lab", "format": "rfc5424", "transport": "tls", "host": "h.test", "verify": False}])
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        SiemForwarder(config, start=False)
    assert "TLS certificate verification is OFF (verify: false)" in caplog.text


def test_verified_tls_logs_no_warning(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    pki = make_pki(tmp_path)
    config = _config([{"name": "tls", "format": "json", "transport": "tls", "host": "h.test", "ca_file": str(pki.ca_file)}])
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        SiemForwarder(config, start=False)
    assert "verification is OFF" not in caplog.text


def test_bad_facility_and_queue_size_fall_back(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="netsentry.siem"):
        forwarder, _ = _memory_forwarder(_config([_dest("a")], facility="local9", queue_size=0))
    assert forwarder.settings.facility == 16
    assert forwarder.queue_size == 10000
    assert "unknown syslog facility 'local9'" in caplog.text


def test_hostname_defaults_to_the_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.siem.dispatcher.socket.gethostname", lambda: "this-machine")
    config = _config([], hostname="")
    assert SiemForwarder(config, start=False).hostname == "this-machine"


def test_include_details_false_and_ecs_fields() -> None:
    forwarder, transports = _memory_forwarder(_config([_dest("e")], include_details=False, ecs_fields=True))
    forwarder.forward(_event())
    _drain(forwarder)
    document = json.loads(transports["e"].payloads[0])
    assert document["event"]["code"] == "PORT_SCAN"
    assert document["message"] == "Port scan from 45.33.12.9"


def test_geoip_fields_come_from_the_lookup() -> None:
    class Geo:
        enabled = True

        def locate(self, ip: str) -> Dict[str, Any]:
            return {"country_name": "Germany"} if ip == "45.33.12.9" else {}

    transports: Dict[str, MemoryTransport] = {}

    def factory(destination: SiemDestinationConfig) -> Transport:
        transports[destination.name] = MemoryTransport(destination.name)
        return transports[destination.name]

    forwarder = SiemForwarder(_config([_dest("j")]), geoip=Geo(), transport_factory=factory, start=False)
    forwarder.forward(_event())
    _drain(forwarder)
    assert json.loads(transports["j"].payloads[0])["source_country"] == "Germany"


def test_status_hides_credentials_in_hosts() -> None:
    forwarder, _ = _memory_forwarder(_config([_dest("x", host="user:secret@collector.test")]))
    entry = forwarder.status()["destinations"][0]
    assert "secret" not in json.dumps(entry)


@pytest.mark.parametrize(
    ("fmt", "framing", "expected"),
    [("rfc5424", "auto", "octet_counting"), ("cef", "auto", "octet_counting"), ("json", "auto", "newline"),
     ("json", "octet_counting", "octet_counting"), ("rfc5424", "newline", "newline")],
)
def test_framing_for(fmt: str, framing: str, expected: str) -> None:
    destination = SiemDestinationConfig(name="x", format=fmt, transport="tcp", host="h", framing=framing)
    assert framing_for(destination) == expected


def test_make_transport(tmp_path: Path) -> None:
    def build(**kwargs: Any) -> Transport:
        return make_transport(SiemDestinationConfig(name="x", format="json", host="h", port=1, **kwargs))

    assert isinstance(build(transport="udp"), UdpTransport)
    tcp = build(transport="tcp")
    assert isinstance(tcp, TcpTransport) and tcp.framing == "newline"
    assert isinstance(build(transport="tls", verify=False), TlsTransport)
    file_transport = build(transport="file", path=str(tmp_path / "e.ndjson"), max_size_mb=1, backup_count=2)
    assert isinstance(file_transport, FileTransport)
    assert (file_transport.max_size_bytes, file_transport.backup_count) == (1024 * 1024, 2)


def test_end_to_end_over_real_sockets(tmp_path: Path) -> None:
    pki: SiemPki = make_pki(tmp_path)
    udp = UdpCollector()
    tcp = Collector()
    tls = Collector(context=pki.server_context())
    try:
        config = _config([
            {"name": "udp", "format": "rfc5424", "transport": "udp", "host": "127.0.0.1", "port": udp.port},
            {"name": "tcp", "format": "cef", "transport": "tcp", "host": "127.0.0.1", "port": tcp.port},
            # verified against the test CA; the certificate is for "localhost"
            {"name": "tls", "format": "json", "transport": "tls", "host": "localhost", "port": tls.port,
             "ca_file": str(pki.ca_file), "framing": "octet_counting"},
            {"name": "file", "format": "json", "transport": "file", "path": str(tmp_path / "out" / "events.ndjson")},
        ])

        def factory(destination: SiemDestinationConfig) -> Transport:
            transport = make_transport(destination)
            if destination.name == "tls":
                from tests.siem_helpers import ipv4_only_resolver

                transport.resolver = ipv4_only_resolver
            return transport

        forwarder = SiemForwarder(config, transport_factory=factory)
        forwarder.forward(_event("SYN_FLOOD"))
        assert udp.wait_for(1)
        assert tcp.wait_for(lambda c: len(c.messages()) == 1)
        assert tls.wait_for(lambda c: len(c.messages()) == 1)
        forwarder.close(flush_timeout=5.0)

        assert udp.datagrams[0].startswith(b"<130>1 ")
        assert tcp.messages()[0].startswith(b"CEF:0|NetSentry|NetSentry|")
        assert json.loads(split_octet_counted(tls.data)[0])["severity"] == "critical"
        lines = (tmp_path / "out" / "events.ndjson").read_bytes().splitlines()
        assert json.loads(lines[0])["event_type"] == "SYN_FLOOD"
        assert all(d["state"] == "stopped" for d in forwarder.status()["destinations"])
    finally:
        udp.stop()
        tcp.stop()
        tls.stop()
