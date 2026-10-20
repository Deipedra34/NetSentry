"""Unit tests for :class:`src.detectors.ICMPDetector`."""

from __future__ import annotations

from src.detectors import ICMPDetector
from src.packet_info import PacketInfo
from tests.conftest import make_packet


def make_ping(
    timestamp: float,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    icmp_type: int = 8,
    length: int = 98,
) -> PacketInfo:
    """An ICMP packet (an echo request unless icmp_type says otherwise)."""
    return make_packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="ICMP",
        src_port=None,
        dst_port=None,
        tcp_flags=None,
        icmp_type=icmp_type,
        icmp_code=0,
        length=length,
    )


def test_few_pings_do_not_alert() -> None:
    detector = ICMPDetector()
    events = []
    for i in range(4):
        events += detector.process_packet(make_ping(timestamp=100.0 + i))
    assert events == []


def test_alert_on_icmp_flood() -> None:
    detector = ICMPDetector(flood_max_packets=100, flood_window_seconds=10.0)
    events = []
    for i in range(150):
        events += detector.process_packet(make_ping(timestamp=100.0 + i * 0.01))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "ICMP_FLOOD"
    assert event.source_ip == "10.0.0.1"
    assert "ICMP flood: 100 echo requests in 10s" in event.details


def test_echo_replies_and_other_icmp_types_are_not_counted() -> None:
    detector = ICMPDetector(flood_max_packets=10, sweep_max_hosts=5)
    events = []
    # a busy host answering pings, plus unreachable / time-exceeded errors,
    # sent to lots of different hosts
    for i in range(50):
        for icmp_type in (0, 3, 11):
            events += detector.process_packet(
                make_ping(timestamp=1.0 + i * 0.01, dst_ip=f"10.0.1.{i}", icmp_type=icmp_type)
            )
    assert events == []


def test_alert_on_ping_sweep() -> None:
    detector = ICMPDetector(sweep_max_hosts=15, sweep_window_seconds=30.0)
    events = []
    for i in range(38):
        events += detector.process_packet(make_ping(timestamp=100.0 + i * 0.5, dst_ip=f"192.168.1.{i + 1}"))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "PING_SWEEP"
    assert "Ping sweep: 15 distinct hosts probed in 30s" in event.details
    assert "192.168.1.15" in event.details


def test_repeated_pings_to_one_host_flood_but_do_not_sweep() -> None:
    detector = ICMPDetector(flood_max_packets=100, sweep_max_hosts=15)
    events = []
    for i in range(200):
        events += detector.process_packet(make_ping(timestamp=100.0 + i * 0.01, dst_ip="192.168.1.10"))
    assert [e.event_type for e in events] == ["ICMP_FLOOD"]


def test_old_echo_requests_expire_from_flood_window() -> None:
    detector = ICMPDetector(flood_max_packets=10, flood_window_seconds=10.0)
    events = []
    for i in range(9):
        events += detector.process_packet(make_ping(timestamp=0.0 + i * 0.1))
    assert events == []
    # Big gap: the earlier requests fall out of the window before the threshold is hit.
    for i in range(9):
        events += detector.process_packet(make_ping(timestamp=50.0 + i * 0.1))
    assert events == []


def test_old_hosts_expire_from_sweep_window() -> None:
    detector = ICMPDetector(sweep_max_hosts=10, sweep_window_seconds=30.0)
    events = []
    for i in range(9):
        events += detector.process_packet(make_ping(timestamp=0.0 + i, dst_ip=f"192.168.1.{i + 1}"))
    for i in range(9):
        events += detector.process_packet(make_ping(timestamp=100.0 + i, dst_ip=f"192.168.2.{i + 1}"))
    assert events == []


def test_oversized_echo_request_alerts_when_enabled() -> None:
    detector = ICMPDetector(flag_large_packets=True, large_packet_bytes=1000)
    events = detector.process_packet(make_ping(timestamp=1.0, length=1480))
    assert len(events) == 1
    assert events[0].event_type == "ICMP_OVERSIZED"
    assert "1480 bytes" in events[0].details
    assert "(threshold: 1000 bytes)" in events[0].details
    # a normal-sized ping right after is fine
    assert detector.process_packet(make_ping(timestamp=2.0, dst_ip="10.0.0.3")) == []


def test_oversized_echo_request_ignored_when_disabled() -> None:
    detector = ICMPDetector(flag_large_packets=False, large_packet_bytes=1000)
    assert detector.process_packet(make_ping(timestamp=1.0, length=1480)) == []


def test_oversized_echo_reply_is_ignored() -> None:
    detector = ICMPDetector(flag_large_packets=True, large_packet_bytes=1000)
    assert detector.process_packet(make_ping(timestamp=1.0, icmp_type=0, length=1480)) == []


def test_cooldown_suppresses_repeat_alerts_per_event_type() -> None:
    detector = ICMPDetector(flood_max_packets=10, sweep_max_hosts=10, cooldown=60.0)
    events = []
    # flood one host -> one ICMP_FLOOD, the rest suppressed by cooldown
    for i in range(30):
        events += detector.process_packet(make_ping(timestamp=1.0 + i * 0.01, dst_ip="192.168.1.1"))
    assert [e.event_type for e in events] == ["ICMP_FLOOD"]
    # the same IP then sweeping still raises a PING_SWEEP -- the flood
    # cooldown doesn't cover it -- but only once
    for i in range(30):
        events += detector.process_packet(make_ping(timestamp=2.0 + i * 0.01, dst_ip=f"192.168.2.{i + 1}"))
    assert [e.event_type for e in events] == ["ICMP_FLOOD", "PING_SWEEP"]
    # once the cooldown has passed, a still-ongoing flood alerts again
    for i in range(30):
        events += detector.process_packet(make_ping(timestamp=70.0 + i * 0.01, dst_ip="192.168.1.1"))
    assert [e.event_type for e in events].count("ICMP_FLOOD") == 2


def test_non_icmp_packets_are_ignored() -> None:
    detector = ICMPDetector(flood_max_packets=5, sweep_max_hosts=5, large_packet_bytes=100)
    events = []
    for i in range(50):
        events += detector.process_packet(
            make_packet(timestamp=1.0 + i * 0.01, dst_ip=f"10.0.1.{i}", protocol="TCP", tcp_flags="S", length=1500)
        )
        events += detector.process_packet(
            make_packet(timestamp=1.0 + i * 0.01, dst_ip=f"10.0.1.{i}", protocol="UDP", tcp_flags=None, length=1500)
        )
    assert events == []


def test_private_source_ips_are_detected() -> None:
    detector = ICMPDetector(sweep_max_hosts=5)
    events = []
    for i in range(5):
        events += detector.process_packet(make_ping(timestamp=1.0 + i, src_ip="192.168.1.50", dst_ip=f"192.168.1.{i + 1}"))
    assert [e.source_ip for e in events] == ["192.168.1.50"]


def test_tracked_sources_and_hosts_are_capped() -> None:
    detector = ICMPDetector(sweep_max_hosts=5, sweep_window_seconds=1000.0)
    detector.MAX_TRACKED_SOURCES = 100
    detector._max_hosts = 50
    # a flood of spoofed source IPs, one ping each...
    for i in range(1000):
        detector.process_packet(make_ping(timestamp=1.0 + i * 0.001, src_ip=f"10.{i // 250}.{i % 250}.1"))
    assert len(detector._echo_times) <= 100
    assert len(detector._hosts_by_ip) <= 100
    # ...and one source pinging a huge number of hosts
    for i in range(1000):
        detector.process_packet(make_ping(timestamp=2.0 + i * 0.001, src_ip="10.9.9.9", dst_ip=f"172.16.{i // 250}.{i % 250}"))
    assert len(detector._hosts_by_ip["10.9.9.9"]) <= 50
