"""Unit tests for :class:`src.detectors.PortScanDetector`."""

from __future__ import annotations

from src.detectors import PortScanDetector
from tests.conftest import make_packet


def test_no_alert_below_threshold() -> None:
    detector = PortScanDetector(port_threshold=15, time_window=10.0, cooldown=30.0)
    events = []
    for port in range(10):
        events += detector.process_packet(
            make_packet(timestamp=1000.0 + port * 0.1, dst_port=1000 + port)
        )
    assert events == []


def test_alert_when_threshold_reached() -> None:
    detector = PortScanDetector(port_threshold=15, time_window=10.0, cooldown=30.0)
    events = []
    for port in range(20):
        events += detector.process_packet(
            make_packet(timestamp=1000.0 + port * 0.1, dst_port=1000 + port)
        )
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "PORT_SCAN"
    assert event.source_ip == "10.0.0.1"
    assert "distinct ports" in event.details


def test_cooldown_suppresses_repeat_alerts() -> None:
    detector = PortScanDetector(port_threshold=5, time_window=10.0, cooldown=30.0)
    events = []
    for port in range(5):
        events += detector.process_packet(make_packet(timestamp=100.0 + port, dst_port=port))
    assert len(events) == 1

    # More ports arrive well within the cooldown window: no second alert yet.
    for port in range(5, 10):
        events += detector.process_packet(make_packet(timestamp=110.0 + port, dst_port=port))
    assert len(events) == 1

    # Once the cooldown has elapsed, a fresh burst raises another alert.
    for port in range(10, 15):
        events += detector.process_packet(make_packet(timestamp=200.0 + port, dst_port=port))
    assert len(events) == 2


def test_sliding_window_expires_old_ports() -> None:
    detector = PortScanDetector(port_threshold=5, time_window=5.0, cooldown=30.0)
    events = []
    # Two ports at t=0, then a long gap, then 3 more ports -- the first two
    # should have fallen out of the window and no alert should fire.
    events += detector.process_packet(make_packet(timestamp=0.0, dst_port=1))
    events += detector.process_packet(make_packet(timestamp=0.5, dst_port=2))
    for i, port in enumerate([3, 4, 5]):
        events += detector.process_packet(make_packet(timestamp=20.0 + i, dst_port=port))
    assert events == []


def test_ignores_non_tcp_udp_traffic() -> None:
    detector = PortScanDetector(port_threshold=2, time_window=10.0, cooldown=30.0)
    events = []
    for port in range(5):
        events += detector.process_packet(
            make_packet(timestamp=1.0 + port, protocol="ARP", dst_port=port, is_arp=True)
        )
    assert events == []


def test_different_source_ips_tracked_independently() -> None:
    detector = PortScanDetector(port_threshold=3, time_window=10.0, cooldown=30.0)
    events = []
    for port in range(2):
        events += detector.process_packet(
            make_packet(timestamp=1.0 + port, src_ip="10.0.0.1", dst_port=port)
        )
    for port in range(2):
        events += detector.process_packet(
            make_packet(timestamp=1.0 + port, src_ip="10.0.0.2", dst_port=port)
        )
    assert events == []
