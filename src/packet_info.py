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
    is_arp: bool = False
    arp_op: Optional[int] = None
    length: int = 0
    # original Scapy packet object, if this PacketInfo came from a live
    # capture (sniffer.py sets it) -- None for hand-built test packets
    raw_packet: Optional[Any] = None

    @property
    def is_syn(self) -> bool:
        """true if SYN flag is set and ACK isn't -- i.e. a connection attempt,
        not part of the handshake response"""
        return bool(self.tcp_flags) and "S" in self.tcp_flags and "A" not in self.tcp_flags
