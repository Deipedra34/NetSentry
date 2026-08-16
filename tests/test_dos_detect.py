"""Unit tests for :class:`src.detectors.DosDetector`."""

from __future__ import annotations

from src.detectors import DosDetector
from tests.conftest import make_packet


def test_no_alert_below_syn_threshold() -> None:
    detector = DosDetector(syn_threshold=100, time_window=5.0, cooldown=30.0)
    events = []
    for i in range(50):
        events += detector.process_packet(
            make_packet(timestamp=100.0 + i * 0.01, tcp_flags="S")
        )
    assert events == []


def test_alert_on_syn_flood() -> None:
    detector = DosDetector(syn_threshold=100, time_window=5.0, cooldown=30.0)
    events = []
    for i in range(150):
        events += detector.process_packet(
            make_packet(timestamp=100.0 + i * 0.01, tcp_flags="S")
        )
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "SYN_FLOOD"
    assert event.source_ip == "10.0.0.1"
    assert "SYN" in event.details


def test_only_syn_flags_counted_not_established_connections() -> None:
    detector = DosDetector(syn_threshold=10, time_window=5.0, cooldown=30.0)
    events = []
    # SYN-ACK and ACK packets should not count toward the SYN flood threshold.
    for i in range(50):
        events += detector.process_packet(
            make_packet(timestamp=1.0 + i * 0.01, tcp_flags="SA")
        )
        events += detector.process_packet(
            make_packet(timestamp=1.0 + i * 0.01, tcp_flags="A")
        )
    assert events == []


def test_sliding_window_expires_old_syns() -> None:
    detector = DosDetector(syn_threshold=10, time_window=2.0, cooldown=30.0)
    events = []
    for i in range(9):
        events += detector.process_packet(make_packet(timestamp=0.0 + i * 0.1, tcp_flags="S"))
    assert events == []
    # Big gap: earlier SYNs fall out of the window before the threshold is hit.
    for i in range(9):
        events += detector.process_packet(make_packet(timestamp=10.0 + i * 0.1, tcp_flags="S"))
    assert events == []


def test_cooldown_suppresses_repeat_alerts() -> None:
    detector = DosDetector(syn_threshold=5, time_window=5.0, cooldown=30.0)
    events = []
    for i in range(6):
        events += detector.process_packet(make_packet(timestamp=1.0 + i * 0.1, tcp_flags="S"))
    assert len(events) == 1
    for i in range(6):
        events += detector.process_packet(make_packet(timestamp=3.0 + i * 0.1, tcp_flags="S"))
    assert len(events) == 1
