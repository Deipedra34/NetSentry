"""Unit tests for :mod:`src.engine`."""

from __future__ import annotations

import pytest

from src.config import Config
from src.database import Database
from src.engine import DetectionEngine, build_detectors
from tests.conftest import make_packet


def test_build_detectors_respects_config_enabled_flags() -> None:
    config = Config()
    config.arp_spoof.enabled = False
    detectors = build_detectors(config)
    names = {d.name for d in detectors}
    assert "ARP_SPOOF" not in names
    assert "PORT_SCAN" in names
    assert "SYN_FLOOD" in names
    assert "TRAFFIC_ANOMALY" in names


def test_build_detectors_explicit_selection_overrides_config() -> None:
    config = Config()
    detectors = build_detectors(config, enabled=["port_scan", "dos"])
    names = {d.name for d in detectors}
    assert names == {"PORT_SCAN", "SYN_FLOOD"}


def test_build_detectors_rejects_unknown_name() -> None:
    with pytest.raises(ValueError):
        build_detectors(Config(), enabled=["not_a_real_detector"])


def test_engine_persists_events_and_counts(in_memory_db: Database) -> None:
    config = Config()
    config.port_scan.port_threshold = 3
    config.port_scan.time_window = 10.0
    detectors = build_detectors(config, enabled=["port_scan"])
    engine = DetectionEngine(in_memory_db, detectors)

    for port in range(5):
        engine.handle_packet(make_packet(timestamp=1.0 + port, dst_port=port))

    assert engine.packet_count == 5
    assert engine.event_count == 1
    assert in_memory_db.count_events() == 1


def test_engine_survives_detector_exception(in_memory_db: Database) -> None:
    class ExplodingDetector:
        name = "EXPLODING"

        def process_packet(self, packet: object) -> list:
            raise RuntimeError("boom")

    engine = DetectionEngine(in_memory_db, [ExplodingDetector()])
    # Must not raise even though the detector always errors.
    engine.handle_packet(make_packet(timestamp=1.0))
    assert engine.packet_count == 1
    assert engine.event_count == 0


def test_whitelist_exact_ip_skips_detection(in_memory_db: Database) -> None:
    config = Config()
    config.port_scan.port_threshold = 1
    detectors = build_detectors(config, enabled=["port_scan"])
    engine = DetectionEngine(in_memory_db, detectors, whitelist=["10.0.0.1"])

    engine.handle_packet(make_packet(timestamp=1.0, src_ip="10.0.0.1", dst_port=1))

    assert engine.packet_count == 1
    assert engine.event_count == 0


def test_whitelist_cidr_range_skips_detection(in_memory_db: Database) -> None:
    config = Config()
    config.port_scan.port_threshold = 1
    detectors = build_detectors(config, enabled=["port_scan"])
    engine = DetectionEngine(in_memory_db, detectors, whitelist=["10.0.0.0/24"])

    engine.handle_packet(make_packet(timestamp=1.0, src_ip="10.0.0.42", dst_port=1))

    assert engine.packet_count == 1
    assert engine.event_count == 0


def test_whitelist_non_matching_ip_still_processed(in_memory_db: Database) -> None:
    config = Config()
    config.port_scan.port_threshold = 1
    detectors = build_detectors(config, enabled=["port_scan"])
    engine = DetectionEngine(in_memory_db, detectors, whitelist=["192.168.1.1", "10.0.0.0/24"])

    engine.handle_packet(make_packet(timestamp=1.0, src_ip="203.0.113.5", dst_port=1))

    assert engine.packet_count == 1
    assert engine.event_count == 1
