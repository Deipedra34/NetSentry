"""Unit tests for :mod:`src.sniffer` packet parsing.

These tests craft packets in memory with Scapy (no live capture, no
root/Administrator privileges, and no network access required) and verify
they are translated into the expected :class:`PacketInfo` objects.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from src.sniffer import NetworkSniffer, parse_packet  # noqa: E402


def test_parse_tcp_syn_packet() -> None:
    pkt = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / IP(
        src="10.0.0.1", dst="10.0.0.2"
    ) / TCP(sport=1234, dport=80, flags="S")

    info = parse_packet(pkt)

    assert info is not None
    assert info.protocol == "TCP"
    assert info.src_ip == "10.0.0.1"
    assert info.dst_ip == "10.0.0.2"
    assert info.src_port == 1234
    assert info.dst_port == 80
    assert info.is_syn is True
    assert info.src_mac == "aa:aa:aa:aa:aa:aa"


def test_parse_udp_packet() -> None:
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=12345)
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "UDP"
    assert info.src_port == 53
    assert info.dst_port == 12345


def test_parse_arp_reply() -> None:
    pkt = Ether() / ARP(
        op=2, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="aa:aa:aa:aa:aa:aa", hwdst="bb:bb:bb:bb:bb:bb"
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.is_arp is True
    assert info.arp_op == 2
    assert info.src_ip == "10.0.0.1"
    assert info.src_mac == "aa:aa:aa:aa:aa:aa"


def test_syn_ack_is_not_syn() -> None:
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="SA")
    info = parse_packet(pkt)
    assert info is not None
    assert info.is_syn is False


def test_on_packet_dispatches_to_handler() -> None:
    received = []
    sniffer = NetworkSniffer(interface=None, packet_handler=received.append)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=1, dport=2, flags="S")

    sniffer._on_packet(pkt)

    assert len(received) == 1
    assert received[0].src_ip == "10.0.0.5"


def test_on_packet_swallows_handler_exceptions() -> None:
    def bad_handler(_info: object) -> None:
        raise RuntimeError("boom")

    sniffer = NetworkSniffer(interface=None, packet_handler=bad_handler)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=1, dport=2, flags="S")

    # Must not raise -- a broken handler shouldn't kill packet capture.
    sniffer._on_packet(pkt)
