"""Automatic .pcap export for suspicious traffic.

PcapExporter keeps a short rolling buffer of raw Scapy packet objects (fed
by the engine on every packet it sees) so that when a critical event fires,
the resulting .pcap captures a few seconds of context *before* the event
too, not just the single packet that tripped the alert. Mirrors the
disabled-by-default, best-effort, cooldown-throttled pattern already used by
NotificationDispatcher in src/notifications.py -- a full disk or a bad
output_dir writing captures should never take down packet capture.

Like sniffer.py, this module needs Scapy directly (wrpcap can't write a
.pcap from anything else); everywhere else in the codebase keeps working
against the Scapy-free PacketInfo dataclass.
"""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Tuple

from src.config import Config
from src.database import Event
from src.notifications import CRITICAL_EVENT_TYPES
from src.packet_info import PacketInfo

logger = logging.getLogger("netsentry.pcap_export")

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize(value: str) -> str:
    """Replaces anything that isn't filesystem-safe with an underscore, so
    event types/IPs can't escape output_dir or otherwise produce a bad path
    (e.g. an IPv6 address's colons)."""
    cleaned = _UNSAFE_CHARS.sub("_", value).strip("_")
    return cleaned or "unknown"


class PcapExporter:
    """Buffers recent raw packets and dumps them to a .pcap when a critical
    event fires.

    add_packet() should be called for every packet the engine sees. Packets
    without a raw Scapy object attached (PacketInfo.raw_packet is None --
    e.g. hand-built packets in tests) are simply not buffered. export() is
    then called once a detector raises an event; it's a no-op for anything
    that isn't in CRITICAL_EVENT_TYPES or is still on cooldown for its
    (event_type, source_ip) pair.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self._buffer: Deque[Tuple[float, Any]] = deque()
        # (event_type, source_ip) -> last export timestamp. Reuses the same
        # cooldown window as notifications, since it's the same "don't spam
        # per packet during a sustained attack" problem.
        self._last_export: Dict[Tuple[str, str], float] = {}
        if self.config.pcap_export.enabled:
            try:
                Path(self.config.pcap_export.output_dir).mkdir(parents=True, exist_ok=True)
            except OSError as exc:  # noqa: BLE001 - startup hiccup shouldn't crash the app
                logger.warning("Could not create pcap_export.output_dir: %s", exc)

    def add_packet(self, packet: PacketInfo) -> None:
        """Appends `packet`'s raw Scapy object to the rolling buffer (if it
        has one) and drops anything now older than capture_window_seconds,
        so the buffer only ever holds enough context to cover that window."""
        if not self.config.pcap_export.enabled:
            return
        if packet.raw_packet is not None:
            self._buffer.append((packet.timestamp, packet.raw_packet))
        cutoff = packet.timestamp - self.config.pcap_export.capture_window_seconds
        while self._buffer and self._buffer[0][0] < cutoff:
            self._buffer.popleft()

    def export(self, event: Event, packet: PacketInfo) -> None:
        """Writes the current buffer (context packets plus whatever's
        already been added for the triggering packet) out to a .pcap, if
        `event` is critical and not currently on cooldown. Never raises --
        write failures (full disk, bad permissions, etc) are logged as a
        warning and swallowed so a pcap problem can never take down the
        detection engine."""
        if not self.config.pcap_export.enabled:
            return
        if event.event_type not in CRITICAL_EVENT_TYPES:
            return
        if not self._should_export(event):
            return

        packets = [pkt for _, pkt in self._buffer]
        if not packets:
            logger.warning(
                "No buffered raw packets available to export for %s from %s",
                event.event_type, event.source_ip,
            )
            return

        try:
            self._write(event, packets)
        except Exception as exc:  # noqa: BLE001 - a pcap write failure must not take down the engine
            logger.warning(
                "PCAP export failed for %s from %s: %s", event.event_type, event.source_ip, exc
            )

    def _should_export(self, event: Event) -> bool:
        """True if we haven't exported for this event_type/source_ip combo
        within the configured cooldown window. Records the attempt
        immediately (not just on success) so a persistently failing export
        doesn't get retried every single event."""
        key = (event.event_type, event.source_ip)
        now = time.time()
        last = self._last_export.get(key, float("-inf"))
        if now - last < self.config.notifications.cooldown:
            return False
        self._last_export[key] = now
        return True

    def _write(self, event: Event, packets: List[Any]) -> None:
        """Actually writes `packets` out under output_dir, rotating across
        multiple files if they'd exceed max_file_size_mb."""
        output_dir = Path(self.config.pcap_export.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = "{}_{}_{}.pcap".format(
            _sanitize(event.event_type),
            _sanitize(event.source_ip),
            event.timestamp.strftime("%Y%m%dT%H%M%S"),
        )
        base_path = output_dir / filename

        written = self._write_rotated(packets, base_path)
        logger.info(
            "Exported %d packet(s) for %s from %s to %s",
            len(packets),
            event.event_type,
            event.source_ip,
            ", ".join(str(path) for path in written),
        )

    def _write_rotated(self, packets: List[Any], base_path: Path) -> List[Path]:
        """Writes `packets` to one or more .pcap files, starting a new file
        (suffixed _partN) whenever the current one would grow past
        max_file_size_mb. Returns every file actually written."""
        from scapy.utils import wrpcap

        max_bytes = self.config.pcap_export.max_file_size_mb * 1024 * 1024
        written: List[Path] = []
        chunk: List[Any] = []
        chunk_bytes = 0
        part = 1

        def flush() -> None:
            nonlocal chunk, chunk_bytes, part
            if not chunk:
                return
            path = (
                base_path
                if part == 1
                else base_path.with_name(f"{base_path.stem}_part{part}{base_path.suffix}")
            )
            wrpcap(str(path), chunk)
            written.append(path)
            chunk = []
            chunk_bytes = 0
            part += 1

        for pkt in packets:
            try:
                pkt_bytes = len(bytes(pkt))
            except Exception:  # noqa: BLE001 - a weird packet shouldn't block the whole export
                pkt_bytes = 0
            if chunk and chunk_bytes + pkt_bytes > max_bytes:
                flush()
            chunk.append(pkt)
            chunk_bytes += pkt_bytes
        flush()

        return written
