"""Unit tests for :class:`src.detectors.BruteForceDetector`."""

from __future__ import annotations

from src.config import Config
from src.detectors import BruteForceDetector
from src.engine import build_detectors
from tests.conftest import make_packet


def test_few_ssh_connections_do_not_alert() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0)
    events = []
    for i in range(3):
        events += detector.process_packet(
            make_packet(timestamp=100.0 + i, dst_port=22, tcp_flags="S")
        )
    assert events == []


def test_many_syns_to_one_host_port_alert_single_target() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0)
    events = []
    for i in range(10):
        events += detector.process_packet(
            make_packet(timestamp=100.0 + i, dst_ip="192.168.1.10", dst_port=22, tcp_flags="S")
        )
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "BRUTE_FORCE"
    assert event.source_ip == "10.0.0.1"
    assert "SSH brute force: 10 attempts to 192.168.1.10:22 in 60s" in event.details
    assert "single-target" in event.details


def test_established_session_packets_are_not_counted() -> None:
    detector = BruteForceDetector(max_attempts=5, window_seconds=60.0)
    events = []
    # one connection's handshake reply + a long run of established traffic
    for i in range(50):
        events += detector.process_packet(make_packet(timestamp=1.0 + i * 0.1, dst_port=22, tcp_flags="SA"))
        events += detector.process_packet(make_packet(timestamp=1.0 + i * 0.1, dst_port=22, tcp_flags="A"))
        events += detector.process_packet(make_packet(timestamp=1.0 + i * 0.1, dst_port=22, tcp_flags="PA"))
    assert events == []


def test_attempts_spread_across_hosts_alert_multi_target() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0, multi_target_threshold=20)
    events = []
    # 4 attempts to each of 6 hosts: never 10 against any one target, 24 total
    for i in range(24):
        events += detector.process_packet(
            make_packet(timestamp=100.0 + i, dst_ip=f"192.168.1.{10 + i % 6}", dst_port=22, tcp_flags="S")
        )
    assert len(events) == 1
    details = events[0].details
    assert "multi-target" in details
    assert "SSH" in details
    assert "20 attempts across 6 targets" in details
    assert "192.168.1.10:22" in details


def test_attempts_across_services_on_one_host_alert_multi_target() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0, multi_target_threshold=20)
    events = []
    for i in range(20):
        port = (22, 3389, 445, 3306)[i % 4]
        events += detector.process_packet(make_packet(timestamp=100.0 + i, dst_port=port, tcp_flags="S"))
    assert len(events) == 1
    assert "multi-target" in events[0].details
    assert "MySQL/RDP/SMB/SSH" in events[0].details


def test_attempts_older_than_window_expire() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0)
    events = []
    for i in range(9):
        events += detector.process_packet(make_packet(timestamp=0.0 + i, dst_port=22, tcp_flags="S"))
    assert events == []
    # Big gap: the earlier attempts fall out of the window before the threshold is hit.
    for i in range(9):
        events += detector.process_packet(make_packet(timestamp=200.0 + i, dst_port=22, tcp_flags="S"))
    assert events == []


def test_cooldown_suppresses_repeat_alerts() -> None:
    detector = BruteForceDetector(max_attempts=5, window_seconds=60.0, cooldown=60.0)
    events = []
    for i in range(6):
        events += detector.process_packet(make_packet(timestamp=1.0 + i, dst_port=22, tcp_flags="S"))
    assert len(events) == 1
    for i in range(20):
        events += detector.process_packet(make_packet(timestamp=10.0 + i, dst_port=22, tcp_flags="S"))
    assert len(events) == 1
    # once the cooldown has passed, a still-ongoing attack alerts again
    for i in range(6):
        events += detector.process_packet(make_packet(timestamp=70.0 + i, dst_port=22, tcp_flags="S"))
    assert len(events) == 2


def test_non_monitored_ports_are_ignored() -> None:
    detector = BruteForceDetector(max_attempts=5, window_seconds=60.0, multi_target_threshold=5)
    events = []
    for i in range(50):
        events += detector.process_packet(make_packet(timestamp=1.0 + i * 0.1, dst_port=9999, tcp_flags="S"))
    assert events == []


def test_http_ports_ignored_unless_monitor_http_enabled() -> None:
    config = Config()
    config.brute_force.max_attempts = 5
    packets = [make_packet(timestamp=1.0 + i, dst_port=443, tcp_flags="S") for i in range(10)]

    detector = build_detectors(config, enabled=["brute_force"])[0]
    assert [e for p in packets for e in detector.process_packet(p)] == []

    config.brute_force.monitor_http = True
    detector = build_detectors(config, enabled=["brute_force"])[0]
    events = [e for p in packets for e in detector.process_packet(p)]
    assert len(events) == 1
    assert "HTTPS brute force" in events[0].details


def test_per_service_threshold_overrides_max_attempts() -> None:
    detector = BruteForceDetector(
        max_attempts=10, window_seconds=60.0, per_service_thresholds={"rdp": 3}
    )
    events = []
    for i in range(3):
        events += detector.process_packet(make_packet(timestamp=1.0 + i, dst_port=3389, tcp_flags="S"))
    assert len(events) == 1
    assert "RDP brute force: 3 attempts" in events[0].details
    assert "(threshold: 3)" in events[0].details


def test_tracked_keys_are_capped() -> None:
    detector = BruteForceDetector(max_attempts=10, window_seconds=60.0)
    detector.MAX_TRACKED_KEYS = 100
    # a flood of spoofed source IPs, one SYN each
    for i in range(1000):
        detector.process_packet(
            make_packet(timestamp=1.0 + i * 0.001, src_ip=f"10.{i // 250}.{i % 250}.1", dst_port=22, tcp_flags="S")
        )
    assert len(detector._attempts) <= 100
    assert len(detector._source_attempts) <= 100
