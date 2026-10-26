"""Plain representation of a packet, no scapy involved.

Detectors never see raw scapy objects -- sniffer.py converts them into
PacketInfo first. Mostly did this so detector unit tests can just construct
plain dataclasses instead of needing an actual capture running (or root),
plus it decouples the detectors from whatever capture library we're using
under the hood.

The one exception is `raw_packet`: it optionally carries the original Scapy
packet object through for src/pcap_export.py, which needs real packets (not
just their parsed fields) to write .pcap files. Detectors themselves ignore
it entirely, so nothing else in the codebase ends up depending on Scapy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass
class PacketInfo:
    """Just the fields the detectors actually need out of a packet.

    Most of these are Optional because not every packet has every layer --
    an ARP frame won't have ports, plain IP without TCP/UDP won't have
    tcp_flags, etc. timestamp is unix epoch (float), length is total bytes.
    arp_op is 1 for request (who-has) and 2 for reply (is-at), only set when
    is_arp is True.
    """

    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    # ICMP type/code, only set when protocol == "ICMP" -- e.g. type 8 is an
    # echo request (ping), 0 an echo reply, 3 destination unreachable
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    is_arp: bool = False
    arp_op: Optional[int] = None
    # DNS query fields, only set for DNS query packets (qr == 0) -- see
    # sniffer.py. dns_qname is the queried domain (e.g. "www.example.com"),
    # dns_qtype the record type as a string (e.g. "A", "TXT", "CNAME").
    dns_qname: Optional[str] = None
    dns_qtype: Optional[str] = None
    # TLS handshake fields, only set for packets carrying a parseable
    # ClientHello or Certificate message -- see src/tls_parser.py and
    # sniffer.py. tls_ja3 is the client's JA3 fingerprint (MD5 hex string);
    # the tls_cert_* fields describe the server's leaf certificate.
    tls_ja3: Optional[str] = None
    tls_cert_subject: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_not_before: Optional[datetime] = None
    tls_cert_not_after: Optional[datetime] = None
    # DHCP fields, only set for well-formed DHCP packets on UDP 67/68 -- see
    # sniffer.py. dhcp_message_type is option 53 as an uppercase name (e.g.
    # "DISCOVER", "OFFER", "REQUEST", "ACK", "NAK"), dhcp_chaddr the client
    # hardware address from the BOOTP header, dhcp_server_id option 54 (the
    # server's IP) when present. The Ethernet source MAC is src_mac as usual.
    dhcp_message_type: Optional[str] = None
    dhcp_chaddr: Optional[str] = None
    dhcp_server_id: Optional[str] = None
    length: int = 0
    # original Scapy packet object, if this PacketInfo came from a live
    # capture (sniffer.py sets it) -- None for hand-built test packets
    raw_packet: Optional[Any] = None
    # name of the interface this packet was captured on, when known (set by
    # sniffer.py when capturing on multiple interfaces at once). Purely
    # informational for logging/debugging -- detectors don't depend on it.
    interface: Optional[str] = None

    @property
    def is_syn(self) -> bool:
        """true if SYN flag is set and ACK isn't -- i.e. a connection attempt,
        not part of the handshake response"""
        return bool(self.tcp_flags) and "S" in self.tcp_flags and "A" not in self.tcp_flags
