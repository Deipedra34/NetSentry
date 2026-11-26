"""Tests for the SIEM forwarding hook in :mod:`src.engine`."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock

from src.config import Config, SiemDestinationConfig
from src.database import Database, Event, ThreatIntelResult
from src.engine import DetectionEngine, build_detectors
from src.siem.dispatcher import SiemForwarder
from src.siem.transports import Transport
from tests.conftest import make_packet
from tests.siem_helpers import FakeClock


class _FakeSocket:
    def close(self) -> None:
        pass


class MemoryTransport(Transport):
    kind = "tcp"

    def __init__(self) -> None:
        super().__init__("collector.test", 514)
        self.payloads: List[bytes] = []
        self.release = threading.Event()
        self.release.set()
        self.blocked = threading.Event()

    def connect(self) -> None:
        if not self.release.is_set():
            self.blocked.set()
            self.release.wait(10)
        self._sock = _FakeSocket()

    def send(self, payload: bytes) -> None:
        self.payloads.append(payload)


def _forwarder(start: bool = False) -> tuple[SiemForwarder, MemoryTransport]:
    config = Config()
    config.siem.enabled = True
    config.siem.hostname = "sensor-1"
    config.siem.destinations = [{"name": "json", "format": "json", "transport": "tcp", "host": "collector.test"}]
    transport = MemoryTransport()

    def factory(destination: SiemDestinationConfig) -> Transport:
        return transport

    return SiemForwarder(config, transport_factory=factory, start=start, clock=FakeClock()), transport


def _drain(forwarder: SiemForwarder) -> List[Dict[str, Any]]:
    sender = forwarder.destinations[0].sender
    assert sender is not None
    while sender.step():
        pass
    transport = forwarder.destinations[0].transport
    assert isinstance(transport, MemoryTransport)
    return [json.loads(payload) for payload in transport.payloads]


def _port_scan_engine(db: Database, **kwargs: Any) -> DetectionEngine:
    config = Config()
    config.port_scan.port_threshold = 3
    return DetectionEngine(db, build_detectors(config, enabled=["port_scan"]), **kwargs)


def _scan(engine: DetectionEngine, src_ip: str = "45.33.12.9", start: float = 1.0) -> None:
    for port in range(5):
        engine.handle_packet(make_packet(timestamp=start + port, src_ip=src_ip, dst_port=port + 20))


def test_detected_events_are_forwarded_after_being_stored(in_memory_db: Database) -> None:
    forwarder, _ = _forwarder()
    engine = _port_scan_engine(in_memory_db, siem=forwarder)
    _scan(engine)
    documents = _drain(forwarder)
    assert len(documents) == 1 == in_memory_db.count_events()
    document = documents[0]
    stored = in_memory_db.get_events()[0]
    assert document["event_type"] == "PORT_SCAN"
    assert document["event_id"] == stored.id
    assert document["details"] == stored.details
    assert document["source_ip"] == "45.33.12.9"
    assert document["destination_ip"] == "10.0.0.2"
    assert document["destination_port"] == 22  # the packet that tripped it
    assert document["sensor"] == "sensor-1"


def test_whitelisted_sources_are_never_forwarded(in_memory_db: Database) -> None:
    forwarder, _ = _forwarder()
    engine = _port_scan_engine(in_memory_db, siem=forwarder, whitelist=["45.33.12.0/24"])
    _scan(engine)
    assert _drain(forwarder) == []


def test_threat_intel_and_geoip_details_are_included(in_memory_db: Database) -> None:
    forwarder, _ = _forwarder()
    threat_intel = MagicMock()

    def enrich(event: Event) -> ThreatIntelResult:
        event.details += " [AbuseIPDB: 87% confidence, 42 reports]"
        return ThreatIntelResult(source_ip=event.source_ip, abuseipdb_score=87, abuseipdb_reports=42)

    threat_intel.enrich.side_effect = enrich
    engine = _port_scan_engine(in_memory_db, siem=forwarder, threat_intel=threat_intel)
    _scan(engine)
    document = _drain(forwarder)[0]
    assert document["source_abuse_score"] == 87
    assert document["details"].endswith("[AbuseIPDB: 87% confidence, 42 reports]")


def test_a_broken_forwarder_never_affects_capture_or_notifications(in_memory_db: Database) -> None:
    siem = MagicMock()
    siem.forward.side_effect = RuntimeError("boom")
    notifier = MagicMock()
    engine = _port_scan_engine(in_memory_db, siem=siem, notifier=notifier)
    _scan(engine)
    assert engine.event_count == 1
    assert in_memory_db.count_events() == 1
    notifier.notify.assert_called_once()


def test_packet_processing_never_waits_for_a_down_collector(in_memory_db: Database) -> None:
    forwarder, transport = _forwarder(start=True)
    transport.release.clear()  # the collector never answers
    notifier = MagicMock()
    engine = _port_scan_engine(in_memory_db, siem=forwarder, notifier=notifier)
    try:
        _scan(engine, "45.33.12.1")
        assert transport.blocked.wait(5)  # the sender thread is stuck now
        started = time.perf_counter()
        for n in range(2, 202):
            _scan(engine, f"45.33.12.{n % 250 + 2}", start=10.0 * n)
        elapsed = time.perf_counter() - started
        # 1000 packets with 200 events, while the only collector hangs
        assert elapsed < 5.0
        assert engine.event_count == 201
        assert notifier.notify.call_count == 201
        sender = forwarder.destinations[0].sender
        assert sender is not None and sender.queued == 200
    finally:
        transport.release.set()
        forwarder.close(flush_timeout=5.0)
    assert len(transport.payloads) == 201


def test_engine_without_siem_is_unchanged(in_memory_db: Database) -> None:
    engine = _port_scan_engine(in_memory_db)
    _scan(engine)
    assert engine.event_count == 1
