"""Unit tests for :mod:`src.sniffer` packet parsing.

These tests craft packets in memory with Scapy (no live capture, no
root/Administrator privileges, and no network access required) and verify
they are translated into the expected :class:`PacketInfo` objects.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all")

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
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


def test_parse_dns_query_extracts_name_and_type() -> None:
    pkt = IP(
        bytes(
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="data.tunnel.example.com", qtype="TXT"))
        )
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.dns_qname == "data.tunnel.example.com"
    assert info.dns_qtype == "TXT"


def test_parse_dns_response_is_not_treated_as_query() -> None:
    pkt = IP(
        bytes(
            IP(src="8.8.8.8", dst="10.0.0.1")
            / UDP(sport=53, dport=40000)
            / DNS(qr=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.dns_qname is None


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


def test_on_packet_tags_packetinfo_with_interface() -> None:
    received = []
    sniffer = NetworkSniffer(interface=None, packet_handler=received.append)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=1, dport=2, flags="S")

    sniffer._on_packet(pkt, interface="eth0")

    assert len(received) == 1
    assert received[0].interface == "eth0"


class TestInterfaceNormalization:
    """A single string is normalized into a one-item list, same as
    config.py does for config.yaml -- see src/config.py::_normalize_interfaces."""

    def test_single_string_is_normalized_to_list(self) -> None:
        sniffer = NetworkSniffer(interface="eth0", packet_handler=lambda _info: None)
        assert sniffer.interfaces == ["eth0"]

    def test_list_is_passed_through(self) -> None:
        sniffer = NetworkSniffer(interface=["eth0", "wlan0"], packet_handler=lambda _info: None)
        assert sniffer.interfaces == ["eth0", "wlan0"]

    def test_none_normalizes_to_empty_list(self) -> None:
        sniffer = NetworkSniffer(interface=None, packet_handler=lambda _info: None)
        assert sniffer.interfaces == []


class TestMultiInterfaceStart:
    """start() runs one capture thread per interface; a bad interface logs
    a warning and the rest keep going, and it's only fatal if every
    interface fails. The real scapy sniff() blocks forever on success, so
    these tests fake it out entirely -- no real interfaces or privileges
    needed."""

    def test_one_bad_interface_does_not_block_the_others(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_sniff(iface=None, prn=None, filter=None, store=False, stop_filter=None):  # noqa: ANN001
            if iface == "bad0":
                raise OSError("No such device")
            return None

        monkeypatch.setattr(scapy, "sniff", fake_sniff)

        sniffer = NetworkSniffer(interface=["good0", "bad0"], packet_handler=lambda _info: None)
        sniffer.start()  # must not raise -- good0 succeeded

        assert "bad0" in sniffer._failures
        assert "good0" not in sniffer._failures

    def test_all_interfaces_failing_is_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_sniff(iface=None, prn=None, filter=None, store=False, stop_filter=None):  # noqa: ANN001
            raise OSError(f"No such device: {iface}")

        monkeypatch.setattr(scapy, "sniff", fake_sniff)

        sniffer = NetworkSniffer(interface=["bad0", "bad1"], packet_handler=lambda _info: None)
        with pytest.raises(RuntimeError):
            sniffer.start()

    def test_all_interfaces_failing_with_permission_error_raises_permission_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_sniff(iface=None, prn=None, filter=None, store=False, stop_filter=None):  # noqa: ANN001
            raise PermissionError("Operation not permitted")

        monkeypatch.setattr(scapy, "sniff", fake_sniff)

        sniffer = NetworkSniffer(interface="bad0", packet_handler=lambda _info: None)
        with pytest.raises(PermissionError):
            sniffer.start()
