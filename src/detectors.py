"""All the traffic detectors live in here.

Each one takes PacketInfo objects one at a time and spits out Event objects
when it spots something sketchy. They keep their own internal state
(counters, sliding windows etc) but don't know anything about the db, Flask,
or how packets are actually captured -- makes it way easier to test them
with just made-up packets instead of a real capture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from typing import Deque, Dict, List, Optional

from src.database import Event
from src.packet_info import PacketInfo
from src.utils import to_datetime

__all__ = [
    "Detector",
    "PortScanDetector",
    "ArpSpoofDetector",
    "DosDetector",
    "TrafficAnomalyDetector",
]


class Detector(ABC):
    """Every detector implements this. process_packet gets called once per
    packet and can keep whatever state it wants between calls (that's how
    the sliding-window stuff works in the concrete detectors)."""

    # used as the event_type string when this detector fires
    name: str = "GENERIC"

    @abstractmethod
    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Look at one packet, return a list of events (empty most of the
        time -- only non-empty when something actually triggers)."""
        raise NotImplementedError


class PortScanDetector(Detector):
    """Counts distinct destination ports contacted per source ip.

    If a source ip is hitting a ton of different destination ports in a
    short window, that's almost certainly a scan (nmap and friends do
    exactly this to map out what's open on a target).
    """

    name = "PORT_SCAN"

    def __init__(
        self,
        port_threshold: int = 15,
        time_window: float = 10.0,
        cooldown: float = 30.0,
    ) -> None:
        # port_threshold distinct ports within time_window secs = scan alert
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.cooldown = cooldown
        # src_ip -> {dst_port: last_seen_timestamp}
        self._ports_by_ip: Dict[str, Dict[int, float]] = defaultdict(dict)
        self._last_alert: Dict[str, float] = {}

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Records the dest port this packet hit, checks if this source ip
        has touched too many distinct ports lately."""
        if not packet.src_ip or packet.dst_port is None:
            return []
        if packet.protocol not in ("TCP", "UDP"):
            return []

        now = packet.timestamp
        ports = self._ports_by_ip[packet.src_ip]
        ports[packet.dst_port] = now

        cutoff = now - self.time_window
        for port in [p for p, seen_at in ports.items() if seen_at < cutoff]:
            del ports[port]

        if len(ports) < self.port_threshold:
            return []

        last_alert = self._last_alert.get(packet.src_ip, float("-inf"))
        if now - last_alert < self.cooldown:
            return []

        self._last_alert[packet.src_ip] = now
        details = (
            f"{len(ports)} distinct ports contacted within {self.time_window:.0f}s "
            f"(threshold: {self.port_threshold}); recent ports: "
            f"{sorted(ports.keys())[:20]}"
        )
        return [
            Event(
                event_type=self.name,
                source_ip=packet.src_ip,
                details=details,
                timestamp=to_datetime(now),
            )
        ]


class ArpSpoofDetector(Detector):
    """Tracks ip -> mac bindings, flags when one ip has more than one mac.

    Basic idea: if one IP suddenly shows up bound to two (or more) different
    MAC addresses, that's a pretty strong sign of ARP cache poisoning --
    that's literally what tools like arpspoof/ettercap do under the hood.
    """

    name = "ARP_SPOOF"

    def __init__(self, cooldown: float = 60.0) -> None:
        # cooldown = how long to wait before re-alerting on the same ip, so we
        # don't spam the log every single packet while an attack's ongoing
        self.cooldown = cooldown
        # ip -> {mac: last_seen_timestamp}
        self._bindings: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._last_alert: Dict[str, float] = {}

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Updates the ip/mac bindings table and flags it if an ip has
        picked up a second (different) mac address."""
        if not packet.is_arp or not packet.src_ip or not packet.src_mac:
            return []
        # 0.0.0.0 shows up during legit ARP probes (DHCP does this), not spoofing
        if packet.src_ip == "0.0.0.0":
            return []

        now = packet.timestamp
        macs = self._bindings[packet.src_ip]
        is_new_mac = packet.src_mac not in macs
        macs[packet.src_mac] = now

        if len(macs) < 2:
            return []

        last_alert = self._last_alert.get(packet.src_ip, float("-inf"))
        if not is_new_mac and now - last_alert < self.cooldown:
            return []

        self._last_alert[packet.src_ip] = now
        mac_list = sorted(macs.keys())
        details = (
            f"IP {packet.src_ip} is associated with {len(mac_list)} MAC addresses: "
            f"{mac_list}"
        )
        return [
            Event(
                event_type=self.name,
                source_ip=packet.src_ip,
                details=details,
                timestamp=to_datetime(now),
            )
        ]


class DosDetector(Detector):
    """Keeps a sliding-window count of SYN packets per source ip.

    If one source ip is throwing way too many SYN packets at us in a short
    window, that's a SYN flood -- classic DoS technique, half-open
    connections piling up until the target runs out of resources.
    """

    name = "SYN_FLOOD"

    def __init__(
        self,
        syn_threshold: int = 100,
        time_window: float = 5.0,
        cooldown: float = 30.0,
    ) -> None:
        # syn_threshold SYNs within time_window secs from one ip = flood alert.
        # cooldown keeps us from re-firing every packet once we're over threshold
        self.syn_threshold = syn_threshold
        self.time_window = time_window
        self.cooldown = cooldown
        # src_ip -> deque of SYN packet timestamps
        self._syn_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Bumps the SYN count for this packet's source ip and checks if
        it's crossed the threshold within the window."""
        if not packet.src_ip or packet.protocol != "TCP" or not packet.is_syn:
            return []

        now = packet.timestamp
        times = self._syn_times[packet.src_ip]
        times.append(now)

        cutoff = now - self.time_window
        while times and times[0] < cutoff:
            times.popleft()

        if len(times) < self.syn_threshold:
            return []

        last_alert = self._last_alert.get(packet.src_ip, float("-inf"))
        if now - last_alert < self.cooldown:
            return []

        self._last_alert[packet.src_ip] = now
        rate = len(times) / self.time_window
        details = (
            f"{len(times)} SYN packets within {self.time_window:.0f}s "
            f"(~{rate:.1f} SYN/s, threshold: {self.syn_threshold})"
        )
        return [
            Event(
                event_type=self.name,
                source_ip=packet.src_ip,
                details=details,
                timestamp=to_datetime(now),
            )
        ]


class TrafficAnomalyDetector(Detector):
    """Flags traffic volume spikes against a rolling baseline average.

    Chops time into fixed windows, counts packets per window. Once we've got
    enough history to build a baseline, any window that's way above the
    average (more than `multiplier` times) gets flagged. This is meant to
    catch stuff the more specific detectors miss -- like a generic flood
    that isn't technically a SYN flood, or just a weird burst worth a human
    glancing at.
    """

    name = "TRAFFIC_ANOMALY"

    def __init__(
        self,
        window_seconds: float = 10.0,
        baseline_windows: int = 6,
        multiplier: float = 3.0,
        min_baseline_samples: int = 3,
    ) -> None:
        # window_seconds = how big each measurement bucket is.
        # baseline_windows = how many past buckets we average together.
        # multiplier = current window has to beat baseline_avg * multiplier
        # to count as an anomaly.
        # min_baseline_samples = don't even bother checking until we've got
        # at least this many windows recorded, otherwise the first few
        # windows trip false positives while the baseline's still empty
        self.window_seconds = window_seconds
        self.baseline_windows = baseline_windows
        self.multiplier = multiplier
        self.min_baseline_samples = min_baseline_samples

        self._window_start: Optional[float] = None
        self._window_count = 0
        self._window_ip_counts: Counter = Counter()
        self._baseline: Deque[int] = deque(maxlen=baseline_windows)

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Adds this packet to the current window. Once the window's full
        (time-wise) it closes it out and starts a fresh one."""
        if self._window_start is None:
            self._window_start = packet.timestamp

        events: List[Event] = []
        if packet.timestamp - self._window_start >= self.window_seconds:
            events = self._close_window(packet.timestamp)
            self._window_start = packet.timestamp
            self._window_count = 0
            self._window_ip_counts = Counter()

        self._window_count += 1
        if packet.src_ip:
            self._window_ip_counts[packet.src_ip] += 1

        return events

    def _close_window(self, closing_timestamp: float) -> List[Event]:
        """Wraps up the window that just ended -- checks it against the
        baseline first, then feeds its count into the baseline regardless
        (so the baseline keeps adapting even after we fire an alert)."""
        events: List[Event] = []
        count = self._window_count

        if len(self._baseline) >= self.min_baseline_samples:
            baseline_avg = sum(self._baseline) / len(self._baseline)
            if baseline_avg > 0 and count > self.multiplier * baseline_avg:
                top_ip, top_count = (
                    self._window_ip_counts.most_common(1)[0]
                    if self._window_ip_counts
                    else ("unknown", 0)
                )
                details = (
                    f"{count} packets in {self.window_seconds:.0f}s window exceeds "
                    f"{self.multiplier}x baseline average ({baseline_avg:.1f} packets); "
                    f"top source: {top_ip} ({top_count} packets)"
                )
                events.append(
                    Event(
                        event_type=self.name,
                        source_ip=top_ip,
                        details=details,
                        timestamp=to_datetime(closing_timestamp),
                    )
                )

        self._baseline.append(count)
        return events
