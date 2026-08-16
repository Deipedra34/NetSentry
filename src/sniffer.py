"""Live capture + turning raw scapy packets into PacketInfo objects.

This is the only file that imports scapy directly (on purpose). Keeping it
isolated here means the rest of the codebase, and all the detector tests,
don't need scapy actually working / root privileges just to run.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, List, Optional

from src.packet_info import PacketInfo

logger = logging.getLogger("netsentry.sniffer")


def parse_packet(packet: object) -> Optional[PacketInfo]:
    """Converts a raw scapy packet (from sniff()'s prn callback usually) into
    our PacketInfo format. Returns None if packet is empty/None -- shouldn't
    normally happen but better safe.
    """
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    if packet is None:
        return None

    timestamp = float(getattr(packet, "time", time.time()))
    info = PacketInfo(timestamp=timestamp, length=len(packet))

    if Ether in packet:
        info.src_mac = packet[Ether].src
        info.dst_mac = packet[Ether].dst

    if ARP in packet:
        arp = packet[ARP]
        info.is_arp = True
        info.arp_op = int(arp.op)
        info.protocol = "ARP"
        info.src_ip = arp.psrc
        info.dst_ip = arp.pdst
        info.src_mac = arp.hwsrc
        info.dst_mac = arp.hwdst
        return info

    if IP in packet:
        ip = packet[IP]
        info.src_ip = ip.src
        info.dst_ip = ip.dst

        if TCP in packet:
            tcp = packet[TCP]
            info.protocol = "TCP"
            info.src_port = int(tcp.sport)
            info.dst_port = int(tcp.dport)
            info.tcp_flags = str(tcp.flags)
        elif UDP in packet:
            udp = packet[UDP]
            info.protocol = "UDP"
            info.src_port = int(udp.sport)
            info.dst_port = int(udp.dport)
        else:
            info.protocol = "IP"

    return info


def list_interfaces() -> List[str]:
    """Names of every interface scapy can see. Raises RuntimeError if scapy
    itself isn't installed (happens if someone skipped requirements.txt)."""
    try:
        from scapy.all import get_if_list
    except ImportError as exc:  # pragma: no cover - exercised only without scapy
        raise RuntimeError(
            "Scapy is not installed. Install project dependencies with "
            "'pip install -r requirements.txt'."
        ) from exc
    return list(get_if_list())


class NetworkSniffer:
    """Captures packets on an interface and hands them off one by one.

    Each packet gets parsed into PacketInfo and passed to whatever handler
    was given at construction time. start() blocks the calling thread until
    stop() gets called from somewhere else (has to be a different thread
    obviously, since this one's stuck in the capture loop).
    """

    def __init__(
        self,
        interface: Optional[str],
        packet_handler: Callable[[PacketInfo], None],
        bpf_filter: Optional[str] = "ip or arp",
    ) -> None:
        # interface=None lets scapy just pick whatever the default is.
        # bpf_filter is a standard BPF expression, defaults to ip+arp only so
        # we're not drowning in ipv6/other noise we don't care about anyway
        self.interface = interface
        self.packet_handler = packet_handler
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()

    def _on_packet(self, packet: object) -> None:
        try:
            info = parse_packet(packet)
        except Exception:  # noqa: BLE001 - a weird/malformed packet shouldn't kill the whole capture
            logger.exception("Failed to parse a captured packet; skipping it")
            return
        if info is not None:
            try:
                self.packet_handler(info)
            except Exception:  # noqa: BLE001 - same deal, a bug in the handler shouldn't crash capture
                logger.exception("Packet handler raised an exception; continuing capture")

    def start(self) -> None:
        """Kicks off capture, blocks the thread until stop() is called.
        Raises RuntimeError if scapy's missing or the interface is bad, and
        PermissionError if we don't have the rights to actually open it
        (need root/admin for raw sockets, no way around that).
        """
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed. Install project dependencies with "
                "'pip install -r requirements.txt'."
            ) from exc

        self._stop_event.clear()
        logger.info(
            "Starting capture on interface=%s filter=%r",
            self.interface or "<default>",
            self.bpf_filter,
        )
        try:
            sniff(
                iface=self.interface,
                prn=self._on_packet,
                filter=self.bpf_filter,
                store=False,
                stop_filter=lambda _pkt: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            raise PermissionError(
                "Insufficient privileges to capture packets. Re-run as "
                "root (Linux/macOS) or Administrator (Windows), and make "
                "sure Npcap/libpcap is installed."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Failed to start capture on interface '{self.interface}': {exc}. "
                "Run with --list-interfaces to see available interface names."
            ) from exc

    def stop(self) -> None:
        """Tells the capture loop to stop -- it'll finish up after the next
        packet comes in (scapy checks stop_filter per-packet, can't interrupt
        it mid-wait unfortunately)."""
        self._stop_event.set()
