"""Unit tests for :class:`src.detectors.DNSTunnelDetector`."""

from __future__ import annotations

from typing import Optional

from src.detectors import DNSTunnelDetector
from tests.conftest import make_packet


def dns_query(
    timestamp: float,
    qname: str,
    qtype: str = "A",
    src_ip: Optional[str] = "10.0.0.1",
):
    """Build a synthetic DNS *query* packet (UDP/53) for the detector."""
    packet = make_packet(
        timestamp=timestamp,
        src_ip=src_ip,
        protocol="UDP",
        src_port=40000,
        dst_port=53,
        tcp_flags=None,
    )
    packet.dns_qname = qname
    packet.dns_qtype = qtype
    return packet


def test_normal_dns_query_does_not_trigger() -> None:
    detector = DNSTunnelDetector()
    events = []
    for i, name in enumerate(
        ["www.google.com", "mail.google.com", "api.github.com", "cdn.example.net"]
    ):
        events += detector.process_packet(dns_query(timestamp=1000.0 + i, qname=name))
    assert events == []


def test_long_high_entropy_subdomain_triggers() -> None:
    detector = DNSTunnelDetector()
    # 63-char hex-ish label: over the length limit *and* high entropy.
    label = ("0123456789abcdef" * 4)[:63]
    events = detector.process_packet(
        dns_query(timestamp=1000.0, qname=f"{label}.example.com")
    )
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "DNS_TUNNEL"
    assert event.source_ip == "10.0.0.1"
    assert "subdomain length: 63" in event.details
    assert "entropy" in event.details


def test_high_query_rate_triggers() -> None:
    detector = DNSTunnelDetector(max_queries_per_minute=60)
    events = []
    # 65 short, innocuous-looking queries inside a single 60s window.
    for i in range(65):
        events += detector.process_packet(
            dns_query(timestamp=1000.0 + i * 0.5, qname=f"n{i}.example.com")
        )
    assert len(events) == 1
    assert events[0].event_type == "DNS_TUNNEL"
    assert "query rate" in events[0].details


def test_suspicious_query_type_contributes_to_trigger() -> None:
    # A moderately long (but sub-threshold), low-entropy label on its own
    # is only an "elevated" signal and must not alert...
    qname = "aaaaaaaaaabbbbbbbbbbccccccccccddddd.example.com"
    quiet = DNSTunnelDetector()
    assert quiet.process_packet(dns_query(timestamp=1000.0, qname=qname, qtype="A")) == []

    # ...but the same query as a TXT lookup tips it over.
    noisy = DNSTunnelDetector()
    events = noisy.process_packet(dns_query(timestamp=1000.0, qname=qname, qtype="TXT"))
    assert len(events) == 1
    assert "query type: TXT" in events[0].details


def test_cooldown_suppresses_repeat_alerts() -> None:
    detector = DNSTunnelDetector(cooldown=60.0)
    label = ("0123456789abcdef" * 4)[:63]
    first = detector.process_packet(dns_query(timestamp=1000.0, qname=f"{label}.a.com"))
    second = detector.process_packet(dns_query(timestamp=1010.0, qname=f"{label}.a.com"))
    third = detector.process_packet(dns_query(timestamp=1100.0, qname=f"{label}.a.com"))
    assert len(first) == 1
    assert second == []
    assert len(third) == 1


def test_non_dns_traffic_is_ignored() -> None:
    detector = DNSTunnelDetector()
    packet = make_packet(timestamp=1.0, protocol="TCP", dst_port=443, tcp_flags="S")
    assert detector.process_packet(packet) == []
