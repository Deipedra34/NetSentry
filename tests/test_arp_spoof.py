"""Unit tests for :class:`src.detectors.ArpSpoofDetector`."""

from __future__ import annotations

from src.detectors import ArpSpoofDetector
from tests.conftest import make_packet


def test_no_alert_for_single_mac_binding() -> None:
    detector = ArpSpoofDetector(cooldown=60.0)
    events = []
    for t in range(5):
        events += detector.process_packet(
            make_packet(
                timestamp=float(t),
                src_ip="192.168.1.10",
                src_mac="aa:aa:aa:aa:aa:aa",
                is_arp=True,
                arp_op=2,
            )
        )
    assert events == []


def test_alert_when_ip_maps_to_two_macs() -> None:
    detector = ArpSpoofDetector(cooldown=60.0)
    events = []
    events += detector.process_packet(
        make_packet(
            timestamp=1.0, src_ip="192.168.1.10", src_mac="aa:aa:aa:aa:aa:aa",
            is_arp=True, arp_op=2,
        )
    )
    events += detector.process_packet(
        make_packet(
            timestamp=2.0, src_ip="192.168.1.10", src_mac="ff:ff:ff:ff:ff:ff",
            is_arp=True, arp_op=2,
        )
    )
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "ARP_SPOOF"
    assert event.source_ip == "192.168.1.10"
    assert "aa:aa:aa:aa:aa:aa" in event.details
    assert "ff:ff:ff:ff:ff:ff" in event.details


def test_non_arp_packets_are_ignored() -> None:
    detector = ArpSpoofDetector(cooldown=60.0)
    events = []
    events += detector.process_packet(
        make_packet(timestamp=1.0, src_ip="192.168.1.10", protocol="TCP", is_arp=False)
    )
    events += detector.process_packet(
        make_packet(
            timestamp=2.0, src_ip="192.168.1.10", src_mac="ff:ff:ff:ff:ff:ff",
            protocol="TCP", is_arp=False,
        )
    )
    assert events == []


def test_arp_probes_from_unassigned_address_ignored() -> None:
    detector = ArpSpoofDetector(cooldown=60.0)
    events = []
    for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"):
        events += detector.process_packet(
            make_packet(timestamp=1.0, src_ip="0.0.0.0", src_mac=mac, is_arp=True, arp_op=1)
        )
    assert events == []


def test_cooldown_suppresses_repeat_alerts_for_same_binding() -> None:
    detector = ArpSpoofDetector(cooldown=60.0)
    events = []
    events += detector.process_packet(
        make_packet(timestamp=1.0, src_ip="192.168.1.10", src_mac="aa:aa:aa:aa:aa:aa", is_arp=True)
    )
    events += detector.process_packet(
        make_packet(timestamp=2.0, src_ip="192.168.1.10", src_mac="bb:bb:bb:bb:bb:bb", is_arp=True)
    )
    assert len(events) == 1
    # Same conflicting MAC seen again shortly after: still within cooldown.
    events += detector.process_packet(
        make_packet(timestamp=5.0, src_ip="192.168.1.10", src_mac="bb:bb:bb:bb:bb:bb", is_arp=True)
    )
    assert len(events) == 1
