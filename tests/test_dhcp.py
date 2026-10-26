"""Unit tests for :class:`src.detectors.DHCPDetector` and DHCP parsing."""

from __future__ import annotations

import logging
from typing import Optional
from unittest.mock import patch

import pytest

from src.auto_block import AutoBlocker
from src.config import Config
from src.database import Database
from src.detectors import DHCPDetector
from src.engine import DetectionEngine
from src.packet_info import PacketInfo
from src.threat_intel import ThreatIntelLookup
from tests.conftest import make_packet

ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"


def client_msg(
    timestamp: float,
    chaddr: str = "11:22:33:44:55:66",
    src_mac: str = ATTACKER_MAC,
    message_type: str = "DISCOVER",
    src_port: int = 68,
) -> PacketInfo:
    """A DHCP client message (DISCOVER by default) from 0.0.0.0."""
    return make_packet(
        timestamp=timestamp,
        src_ip="0.0.0.0",
        dst_ip="255.255.255.255",
        protocol="UDP",
        src_port=src_port,
        dst_port=67,
        tcp_flags=None,
        src_mac=src_mac,
        dhcp_message_type=message_type,
        dhcp_chaddr=chaddr,
    )


def server_msg(
    timestamp: float,
    server: str = "192.168.1.1",
    message_type: str = "OFFER",
    server_id: Optional[str] = "same",
    src_mac: str = "00:11:22:33:44:01",
) -> PacketInfo:
    """A DHCP server reply (OFFER by default); server_id defaults to the
    server's own IP, pass None to leave option 54 out."""
    return make_packet(
        timestamp=timestamp,
        src_ip=server,
        dst_ip="255.255.255.255",
        protocol="UDP",
        src_port=67,
        dst_port=68,
        tcp_flags=None,
        src_mac=src_mac,
        dhcp_message_type=message_type,
        dhcp_chaddr="11:22:33:44:55:66",
        dhcp_server_id=server if server_id == "same" else server_id,
    )


def mac(i: int) -> str:
    return f"02:00:00:00:{i // 256:02x}:{i % 256:02x}"


def run(detector: DHCPDetector, packets: list) -> list:
    return [event for packet in packets for event in detector.process_packet(packet)]


def test_normal_dhcp_exchange_does_not_alert() -> None:
    for detector in (DHCPDetector(), DHCPDetector(trusted_servers=["192.168.1.1"])):
        events = run(
            detector,
            [
                client_msg(1.0, message_type="DISCOVER"),
                server_msg(1.1, message_type="OFFER"),
                client_msg(1.2, message_type="REQUEST"),
                server_msg(1.3, message_type="ACK"),
            ],
        )
        assert events == []


def test_many_distinct_client_macs_trigger_starvation() -> None:
    detector = DHCPDetector(starvation_max_clients=20, starvation_window_seconds=30.0)
    events = run(detector, [client_msg(100.0 + i * 0.1, chaddr=mac(i)) for i in range(87)])
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "DHCP_STARVATION"
    assert event.source_ip == "0.0.0.0"
    assert f"DHCP starvation: 20 distinct client MACs from {ATTACKER_MAC} in 30s" in event.details


def test_requests_count_toward_starvation_too() -> None:
    detector = DHCPDetector(starvation_max_clients=5)
    events = run(detector, [client_msg(1.0 + i, chaddr=mac(i), message_type="REQUEST") for i in range(5)])
    assert [e.event_type for e in events] == ["DHCP_STARVATION"]


def test_repeated_chaddr_is_not_counted_as_distinct() -> None:
    detector = DHCPDetector(starvation_max_clients=5)
    events = run(detector, [client_msg(1.0 + i * 0.1) for i in range(100)])
    assert events == []


def test_relayed_requests_do_not_count_as_starvation() -> None:
    # a relay agent forwards every client's request from port 67 under its own MAC
    detector = DHCPDetector(starvation_max_clients=5)
    events = run(detector, [client_msg(1.0 + i, chaddr=mac(i), src_port=67) for i in range(50)])
    assert events == []


def test_offer_and_ack_from_trusted_server_are_fine() -> None:
    detector = DHCPDetector(trusted_servers=["192.168.1.1"])
    events = run(detector, [server_msg(1.0), server_msg(2.0, message_type="ACK")])
    assert events == []


def test_offer_from_untrusted_server_triggers_rogue_event() -> None:
    detector = DHCPDetector(trusted_servers=["192.168.1.1"])
    events = detector.process_packet(server_msg(1.0, server="192.168.1.66", src_mac="de:ad:be:ef:00:01"))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "ROGUE_DHCP_SERVER"
    assert event.source_ip == "192.168.1.66"
    assert event.details.startswith("Rogue DHCP server 192.168.1.66 offered a lease (trusted: 192.168.1.1)")
    assert "de:ad:be:ef:00:01" in event.details


def test_rogue_server_identified_by_ip_source_when_option_54_missing() -> None:
    detector = DHCPDetector(trusted_servers=["192.168.1.1"])
    events = detector.process_packet(server_msg(1.0, server="192.168.1.66", message_type="ACK", server_id=None))
    assert len(events) == 1
    assert events[0].details.startswith("Rogue DHCP server 192.168.1.66 acknowledged a lease")


def test_learning_trusts_first_server_and_alerts_on_second(caplog: pytest.LogCaptureFixture) -> None:
    detector = DHCPDetector(learn_trusted_server=True, learning_seconds=120.0)
    with caplog.at_level(logging.WARNING, logger="netsentry.detectors"):
        assert detector.process_packet(server_msg(1.0, server="192.168.1.1")) == []
    assert detector.learned_server == "192.168.1.1"
    assert "learned DHCP server 192.168.1.1" in caplog.text
    # the learned server keeps answering: fine
    assert detector.process_packet(server_msg(5.0, server="192.168.1.1", message_type="ACK")) == []
    # a second server shows up, even during the learning window: rogue
    events = detector.process_packet(server_msg(10.0, server="192.168.1.66"))
    assert len(events) == 1
    assert "(trusted: 192.168.1.1 (learned))" in events[0].details


def test_explicit_trusted_list_disables_learning() -> None:
    detector = DHCPDetector(trusted_servers=["192.168.1.1"], learn_trusted_server=True)
    events = detector.process_packet(server_msg(1.0, server="192.168.1.66"))
    assert detector.learned_server is None
    assert [e.event_type for e in events] == ["ROGUE_DHCP_SERVER"]


def test_nothing_learned_after_learning_window_falls_back_to_multiple_servers() -> None:
    detector = DHCPDetector(learn_trusted_server=True, learning_seconds=120.0)
    detector.process_packet(make_packet(timestamp=0.0))  # capture starts
    assert detector.process_packet(server_msg(200.0, server="192.168.1.1")) == []
    assert detector.learned_server is None
    events = detector.process_packet(server_msg(210.0, server="192.168.1.66"))
    assert len(events) == 1
    assert "Multiple DHCP servers answering" in events[0].details
    assert "192.168.1.1" in events[0].details


def test_multiple_servers_alert_can_be_turned_off() -> None:
    detector = DHCPDetector(learn_trusted_server=False, alert_on_multiple_servers=False)
    events = run(detector, [server_msg(1.0, server="192.168.1.1"), server_msg(2.0, server="192.168.1.66")])
    assert events == []


def test_whitelisted_server_is_trusted() -> None:
    detector = DHCPDetector(trusted_servers=["192.168.1.1"], whitelist=["192.168.1.0/28"])
    assert detector.process_packet(server_msg(1.0, server="192.168.1.5")) == []
    assert len(detector.process_packet(server_msg(2.0, server="192.168.1.66"))) == 1


def test_malformed_dhcp_fields_are_ignored() -> None:
    detector = DHCPDetector(starvation_max_clients=2, trusted_servers=["192.168.1.1"])
    packets = [
        # parse failure upstream: DHCP ports but no DHCP fields filled in
        make_packet(timestamp=1.0, protocol="UDP", src_port=68, dst_port=67, tcp_flags=None),
        # client message without a chaddr, server reply without any server address
        client_msg(2.0, chaddr=""),
        make_packet(timestamp=3.0, src_ip=None, protocol="UDP", src_port=67, dst_port=68,
                    tcp_flags=None, dhcp_message_type="OFFER"),
        # message types neither check cares about
        client_msg(4.0, chaddr=mac(1), message_type="RELEASE"),
        client_msg(5.0, chaddr=mac(2), message_type="INFORM"),
        server_msg(6.0, server="192.168.1.66", message_type="NAK"),
    ]
    assert run(detector, packets) == []


def test_old_client_macs_expire_from_window() -> None:
    detector = DHCPDetector(starvation_max_clients=20, starvation_window_seconds=30.0)
    events = run(detector, [client_msg(0.0 + i, chaddr=mac(i)) for i in range(19)])
    # Big gap: the earlier client MACs fall out of the window before the threshold is hit.
    events += run(detector, [client_msg(100.0 + i, chaddr=mac(100 + i)) for i in range(19)])
    assert events == []


def test_cooldown_suppresses_repeats_per_event_type() -> None:
    detector = DHCPDetector(starvation_max_clients=5, trusted_servers=["192.168.1.1"], cooldown=60.0)
    events = run(detector, [client_msg(1.0 + i * 0.1, chaddr=mac(i)) for i in range(50)])
    assert [e.event_type for e in events] == ["DHCP_STARVATION"]
    # the same attacker machine running a rogue server still raises that,
    # starvation's cooldown doesn't cover it -- but only once
    events += run(detector, [server_msg(10.0 + i, server="192.168.1.66", src_mac=ATTACKER_MAC) for i in range(5)])
    assert [e.event_type for e in events] == ["DHCP_STARVATION", "ROGUE_DHCP_SERVER"]
    # once the cooldown has passed, both alert again
    events += run(detector, [client_msg(80.0 + i * 0.1, chaddr=mac(500 + i)) for i in range(5)])
    events += detector.process_packet(server_msg(80.0, server="192.168.1.66"))
    assert [e.event_type for e in events].count("DHCP_STARVATION") == 2
    assert [e.event_type for e in events].count("ROGUE_DHCP_SERVER") == 2


def test_non_dhcp_packets_are_ignored() -> None:
    detector = DHCPDetector(starvation_max_clients=2, trusted_servers=["192.168.1.1"])
    packets = []
    for i in range(20):
        packets.append(make_packet(timestamp=1.0 + i, src_ip=f"10.0.0.{i}", protocol="TCP", dst_port=67))
        packets.append(make_packet(timestamp=1.0 + i, src_ip=f"10.0.0.{i}", protocol="UDP", tcp_flags=None, dst_port=53))
        packets.append(make_packet(timestamp=1.0 + i, protocol="ARP", is_arp=True, src_mac=mac(i)))
    assert run(detector, packets) == []


def test_tracked_sources_and_clients_are_capped() -> None:
    detector = DHCPDetector(starvation_max_clients=5, starvation_window_seconds=1000.0)
    detector.MAX_TRACKED_SOURCES = 100
    detector._max_clients = 50
    run(detector, [client_msg(1.0 + i * 0.001, src_mac=mac(i), chaddr=mac(i)) for i in range(1000)])
    assert len(detector._clients_by_mac) <= 100
    run(detector, [client_msg(2.0 + i * 0.001, chaddr=mac(i)) for i in range(1000)])
    assert len(detector._clients_by_mac[ATTACKER_MAC]) <= 50


def test_starvation_from_0_0_0_0_never_reaches_threat_intel_or_auto_block(in_memory_db: Database) -> None:
    config = Config()
    config.dhcp.starvation_max_clients = 5
    config.auto_block.enabled = True
    config.auto_block.dry_run = False  # live: would really call the firewall
    config.auto_block.min_severity = "low"
    config.threat_intel.enabled = True
    config.threat_intel.min_severity = "low"
    config.threat_intel.abuseipdb.enabled = True
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    engine = DetectionEngine(
        in_memory_db,
        [DHCPDetector(starvation_max_clients=5)],
        auto_blocker=AutoBlocker(config, in_memory_db),
        threat_intel=ThreatIntelLookup(config, in_memory_db),
    )
    with patch("src.auto_block.subprocess.run") as mock_run, patch("src.threat_intel.requests.get") as mock_get:
        for i in range(10):
            engine.handle_packet(client_msg(1.0 + i, chaddr=mac(i)))
    events = in_memory_db.get_events()
    assert [(e.event_type, e.source_ip) for e in events] == [("DHCP_STARVATION", "0.0.0.0")]
    mock_run.assert_not_called()
    mock_get.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


# --- parsing (src/sniffer.py) ---------------------------------------------


def _dhcp_bytes(options: list, op: int = 1, sport: int = 68, dport: int = 67) -> bytes:
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    pkt = (
        Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=sport, dport=dport)
        / BOOTP(op=op, chaddr=bytes.fromhex("112233445566"))
        / DHCP(options=options)
    )
    return bytes(pkt)


def test_parse_dhcp_discover_and_offer() -> None:
    pytest.importorskip("scapy.all")
    from scapy.layers.l2 import Ether

    from src.sniffer import parse_packet

    discover = parse_packet(Ether(_dhcp_bytes([("message-type", "discover"), "end"])))
    assert discover is not None
    assert discover.dhcp_message_type == "DISCOVER"
    assert discover.dhcp_chaddr == "11:22:33:44:55:66"
    assert discover.dhcp_server_id is None
    assert discover.src_mac == ATTACKER_MAC

    offer = parse_packet(
        Ether(_dhcp_bytes([("message-type", "offer"), ("server_id", "192.168.1.1"), "end"], op=2, sport=67, dport=68))
    )
    assert offer is not None
    assert offer.dhcp_message_type == "OFFER"
    assert offer.dhcp_server_id == "192.168.1.1"


@pytest.mark.parametrize(
    "mangle",
    [
        lambda raw: raw[:250],  # truncated inside the BOOTP header's file field
        lambda raw: raw[:60],  # truncated right after the UDP header
        lambda raw: raw[:282] + b"\x35\x05\x63",  # option 53 with a bogus length
        lambda raw: raw[:282] + b"\xff",  # magic cookie but no options at all
    ],
)
def test_parse_malformed_dhcp_is_skipped_without_crashing(mangle) -> None:
    pytest.importorskip("scapy.all")
    from scapy.layers.l2 import Ether

    from src.sniffer import parse_packet

    info = parse_packet(Ether(mangle(_dhcp_bytes([("message-type", "discover"), "end"]))))
    assert info is not None
    assert info.dhcp_message_type is None
    assert info.dhcp_chaddr is None
    assert DHCPDetector().process_packet(info) == []


def test_non_dhcp_udp_leaves_dhcp_fields_empty() -> None:
    pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    from src.sniffer import parse_packet

    info = parse_packet(Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53))
    assert info is not None
    assert (info.dhcp_message_type, info.dhcp_chaddr, info.dhcp_server_id) == (None, None, None)
