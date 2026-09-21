"""Per-source-IP traffic feature extraction for MLAnomalyDetector.

Computes a fixed-length numeric feature vector per source IP over a rolling
`feature_window_seconds` window, using only the header-level fields already
available on `PacketInfo` (src/packet_info.py) -- no payload inspection, same
lightweight approach the rest of NetSentry's detectors use.

FEATURE_NAMES below is the single source of truth for the vector's order and
meaning. It's used both when training a model (scripts/train_ml_model.py)
and when scoring live traffic (MLAnomalyDetector in src/detectors.py) -- the
two have to agree exactly, or a trained model silently scores the wrong
inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from src.packet_info import PacketInfo

# Order matters. Each entry is (feature vector index) -> meaning:
#   0. packet_rate            packets/second from this source IP during the window
#   1. unique_dst_ports       count of distinct destination ports contacted
#   2. unique_dst_ips         count of distinct destination IPs contacted
#   3. avg_packet_size        mean packet length in bytes
#   4. tcp_ratio              share of packets in the window that were TCP
#   5. udp_ratio              share of packets in the window that were UDP
#   6. other_protocol_ratio   share of packets that were neither TCP nor UDP
#                             (ARP, plain IP, etc.) -- tcp_ratio + udp_ratio +
#                             other_protocol_ratio always sums to 1.0
#   7. syn_ratio              share of this window's TCP packets that were
#                             SYN-only (PacketInfo.is_syn) -- 0.0 if the
#                             window had no TCP packets at all
FEATURE_NAMES: List[str] = [
    "packet_rate",
    "unique_dst_ports",
    "unique_dst_ips",
    "avg_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "other_protocol_ratio",
    "syn_ratio",
]
FEATURE_COUNT = len(FEATURE_NAMES)


@dataclass
class _WindowAccumulator:
    """Running totals for one source IP's currently-open window."""

    start: float
    packet_count: int = 0
    total_length: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    syn_count: int = 0
    dst_ports: Set[int] = field(default_factory=set)
    dst_ips: Set[str] = field(default_factory=set)

    def add(self, packet: PacketInfo) -> None:
        self.packet_count += 1
        self.total_length += packet.length
        if packet.protocol == "TCP":
            self.tcp_count += 1
            if packet.is_syn:
                self.syn_count += 1
        elif packet.protocol == "UDP":
            self.udp_count += 1
        if packet.dst_port is not None:
            self.dst_ports.add(packet.dst_port)
        if packet.dst_ip is not None:
            self.dst_ips.add(packet.dst_ip)

    def to_feature_vector(self, window_seconds: float) -> List[float]:
        """Computes the FEATURE_NAMES vector from this window's totals."""
        count = self.packet_count
        if count == 0 or window_seconds <= 0:
            return [0.0] * FEATURE_COUNT
        other_count = count - self.tcp_count - self.udp_count
        return [
            count / window_seconds,
            float(len(self.dst_ports)),
            float(len(self.dst_ips)),
            self.total_length / count,
            self.tcp_count / count,
            self.udp_count / count,
            other_count / count,
            (self.syn_count / self.tcp_count) if self.tcp_count else 0.0,
        ]


class SourceIPFeatureWindows:
    """Tracks a rolling per-source-IP window of traffic stats and hands back
    a completed feature vector each time a source IP's window closes.

    Mirrors TrafficAnomalyDetector's fixed-window bucketing
    (src/detectors.py) but keyed per source IP instead of globally: each IP
    gets its own `feature_window_seconds`-wide window, closed out and reset
    the first time a packet from that IP arrives `feature_window_seconds` (or
    more) after the window started.
    """

    def __init__(self, window_seconds: float, min_packets: int = 5) -> None:
        # min_packets -- windows with fewer packets than this are too sparse
        # to produce a meaningful feature vector, so they're dropped instead
        # of scored (a couple of stray packets isn't "traffic", it's noise).
        self.window_seconds = window_seconds
        self.min_packets = min_packets
        self._windows: Dict[str, _WindowAccumulator] = {}

    def add_packet(self, packet: PacketInfo) -> Optional[List[float]]:
        """Adds `packet` to its source IP's current window. Returns the
        completed feature vector if this packet closed out a window that had
        at least `min_packets` packets in it, otherwise None."""
        if not packet.src_ip:
            return None

        window = self._windows.get(packet.src_ip)
        if window is not None and packet.timestamp - window.start >= self.window_seconds:
            vector = (
                window.to_feature_vector(self.window_seconds)
                if window.packet_count >= self.min_packets
                else None
            )
            window = None
        else:
            vector = None

        if window is None:
            window = _WindowAccumulator(start=packet.timestamp)
            self._windows[packet.src_ip] = window

        window.add(packet)
        return vector
