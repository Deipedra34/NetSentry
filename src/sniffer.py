"""Live capture + turning raw scapy packets into PacketInfo objects.

This is the only file that imports scapy directly (on purpose). Keeping it
isolated here means the rest of the codebase, and all the detector tests,
don't need scapy actually working / root privileges just to run.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Union

from src import tls_parser
from src.packet_info import PacketInfo

logger = logging.getLogger("netsentry.sniffer")


def parse_packet(packet: object) -> Optional[PacketInfo]:
    """Converts a raw scapy packet (from sniff()'s prn callback usually) into
    our PacketInfo format. Returns None if packet is empty/None -- shouldn't
    normally happen but better safe.
    """
    from scapy.layers.dns import DNS, dnsqtypes
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    if packet is None:
        return None

    timestamp = float(getattr(packet, "time", time.time()))
    info = PacketInfo(timestamp=timestamp, length=len(packet), raw_packet=packet)

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

            # Cheap pre-check (TLS record content type is always the first
            # byte) so plain TCP traffic doesn't pay for handshake parsing.
            payload = bytes(tcp.payload)
            if payload[:1] == b"\x16":
                info.tls_ja3 = tls_parser.parse_client_hello(payload)
                if info.tls_ja3 is None:
                    cert_info = tls_parser.parse_certificate(payload)
                    if cert_info is not None:
                        info.tls_cert_subject = cert_info.subject
                        info.tls_cert_issuer = cert_info.issuer
                        info.tls_cert_not_before = cert_info.not_before
                        info.tls_cert_not_after = cert_info.not_after
        elif UDP in packet:
            udp = packet[UDP]
            info.protocol = "UDP"
            info.src_port = int(udp.sport)
            info.dst_port = int(udp.dport)
        else:
            info.protocol = "IP"

        # Pull the queried name/type out of DNS *queries* (qr == 0) so the
        # DNS tunnel detector can inspect them without re-parsing raw packets.
        if DNS in packet:
            dns = packet[DNS]
            question = dns.qd
            # dns.qd is a list on modern Scapy, a chained packet on older ones
            if isinstance(question, list):
                question = question[0] if question else None
            if int(getattr(dns, "qr", 0) or 0) == 0 and question is not None:
                qname = getattr(question, "qname", b"") or b""
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", "replace")
                info.dns_qname = qname.rstrip(".") or None
                info.dns_qtype = dnsqtypes.get(int(question.qtype), str(question.qtype))

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
    """Captures packets on one or more interfaces and hands them off one by
    one.

    Each packet gets parsed into PacketInfo and passed to whatever handler
    was given at construction time. start() blocks the calling thread until
    stop() gets called from somewhere else (has to be a different thread
    obviously, since this one's stuck waiting on the capture threads).

    Multiple interfaces are captured concurrently, one `threading.Thread`
    per interface (each running its own blocking Scapy `sniff()` loop), all
    feeding the same `packet_handler`. A single bad interface just logs a
    warning and the rest keep going; it's only fatal if every interface
    fails to open.
    """

    # how long to give each interface's sniff() call to fail before we
    # assume it opened fine -- scapy raises immediately (socket open time)
    # for a bad interface name/permission, well before it starts blocking
    # on packets, so this only needs to cover that startup window.
    _OPEN_GRACE_SECONDS = 1.5

    def __init__(
        self,
        interface: Union[str, List[str], None],
        packet_handler: Callable[[PacketInfo], None],
        bpf_filter: Optional[str] = "ip or arp",
    ) -> None:
        # interface=None (or []) lets scapy just pick whatever the default
        # is. A single string is normalized into a one-item list here, same
        # as config.py does for config.yaml, so the rest of this class only
        # ever deals with a list. bpf_filter is a standard BPF expression,
        # defaults to ip+arp only so we're not drowning in ipv6/other noise
        # we don't care about anyway.
        self.interfaces: List[str] = self._normalize_interface(interface)
        self.packet_handler = packet_handler
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._failures: Dict[Optional[str], Exception] = {}

    @staticmethod
    def _normalize_interface(interface: Union[str, List[str], None]) -> List[str]:
        if interface is None:
            return []
        if isinstance(interface, str):
            return [interface]
        return list(interface)

    def _on_packet(self, packet: object, interface: Optional[str] = None) -> None:
        try:
            info = parse_packet(packet)
        except Exception:  # noqa: BLE001 - a weird/malformed packet shouldn't kill the whole capture
            logger.exception("Failed to parse a captured packet; skipping it")
            return
        if info is not None:
            if interface is not None:
                info.interface = interface
            try:
                self.packet_handler(info)
            except Exception:  # noqa: BLE001 - same deal, a bug in the handler shouldn't crash capture
                logger.exception("Packet handler raised an exception; continuing capture")

    def _capture_loop(self, iface: Optional[str]) -> None:
        """Runs on its own thread, one per interface. Blocks in scapy's
        sniff() until stop() is called (shared stop_event) or the interface
        fails to open, in which case the failure is recorded for start() to
        inspect."""
        from scapy.all import sniff

        try:
            sniff(
                iface=iface,
                prn=lambda pkt: self._on_packet(pkt, iface),
                filter=self.bpf_filter,
                store=False,
                stop_filter=lambda _pkt: self._stop_event.is_set(),
            )
        except (PermissionError, OSError) as exc:
            self._failures[iface] = exc

    def start(self) -> None:
        """Kicks off capture on every configured interface, blocks the
        calling thread until stop() is called (or all capture threads exit
        on their own). Raises RuntimeError if scapy's missing or every
        interface fails to open, and PermissionError if that failure was a
        permissions issue on every interface (need root/admin for raw
        sockets, no way around that). A subset of interfaces failing to open
        is not fatal -- it's logged as a warning and capture continues on
        the rest.
        """
        try:
            from scapy.all import sniff  # noqa: F401 - import check only, see below
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed. Install project dependencies with "
                "'pip install -r requirements.txt'."
            ) from exc

        self._stop_event.clear()
        self._failures = {}
        # None here means "let scapy pick the OS default" -- same meaning a
        # bare `interface=None` used to have before multi-interface support.
        interfaces: List[Optional[str]] = list(self.interfaces) or [None]

        logger.info(
            "Starting capture on interface(s)=%s filter=%r",
            ", ".join(iface or "<default>" for iface in interfaces),
            self.bpf_filter,
        )

        self._threads = [
            threading.Thread(
                target=self._capture_loop,
                args=(iface,),
                name=f"netsentry-sniff-{iface or 'default'}",
                daemon=True,
            )
            for iface in interfaces
        ]
        for thread in self._threads:
            thread.start()

        # give each thread a moment to fail fast (bad name / no permission)
        # before we treat it as successfully capturing.
        for thread in self._threads:
            thread.join(timeout=self._OPEN_GRACE_SECONDS)

        failed = dict(self._failures)
        succeeded = [iface for iface in interfaces if iface not in failed]

        for iface, exc in failed.items():
            logger.warning("Interface %r failed to start: %s", iface or "<default>", exc)

        if not succeeded:
            reasons = "; ".join(f"{iface or '<default>'}: {exc}" for iface, exc in failed.items())
            if failed and all(isinstance(exc, PermissionError) for exc in failed.values()):
                raise PermissionError(
                    "Insufficient privileges to capture packets on any interface "
                    f"({reasons}). Re-run as root (Linux/macOS) or Administrator "
                    "(Windows), and make sure Npcap/libpcap is installed."
                )
            raise RuntimeError(
                f"Failed to start capture on any interface ({reasons}). Run with "
                "--list-interfaces to see available interface names."
            )

        if failed:
            logger.warning(
                "Continuing capture on %d of %d interface(s); failed: %s",
                len(succeeded), len(interfaces), ", ".join(str(iface) for iface in failed),
            )
        logger.info(
            "Started capture on: %s", ", ".join(iface or "<default>" for iface in succeeded)
        )

        try:
            for thread in self._threads:
                thread.join()
        except KeyboardInterrupt:
            self.stop()
            for thread in self._threads:
                thread.join(timeout=5)
            raise

    def stop(self) -> None:
        """Tells every capture thread to stop -- each one finishes up after
        its next packet comes in (scapy checks stop_filter per-packet,
        can't interrupt it mid-wait unfortunately)."""
        self._stop_event.set()
