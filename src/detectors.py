"""All the traffic detectors live in here.

Each one takes PacketInfo objects one at a time and spits out Event objects
when it spots something sketchy. They keep their own internal state
(counters, sliding windows etc) but don't know anything about the db, Flask,
or how packets are actually captured -- makes it way easier to test them
with just made-up packets instead of a real capture.
"""

from __future__ import annotations

import logging
import math
from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, FrozenSet, List, Optional

from src.database import Event
from src.packet_info import PacketInfo
from src.utils import to_datetime

logger = logging.getLogger("netsentry.detectors")

__all__ = [
    "Detector",
    "PortScanDetector",
    "ArpSpoofDetector",
    "DosDetector",
    "TrafficAnomalyDetector",
    "DNSTunnelDetector",
    "TLSAnomalyDetector",
]


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of `text` in bits per character.

    Normal hostnames are mostly dictionary words and sit around 3-3.5 bits;
    base32/base64/hex-encoded tunnel payloads pack in far more randomness and
    push well above that, which is what `entropy_threshold` keys off of.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (n / length) * math.log2(n / length) for n in counts.values()
    )


def _subdomain_labels(qname: str) -> List[str]:
    """The subdomain portion of `qname` -- every label except the last two.

    "www.example.com" -> ["www"], "a.b.c.example.com" -> ["a", "b", "c"],
    "example.com" -> []. This is a deliberately cheap eTLD+1 approximation
    (no Public Suffix List), which is plenty for spotting the giant encoded
    labels tunneling tools stack in front of their own domain.
    """
    labels = [label for label in qname.split(".") if label]
    return labels[:-2] if len(labels) > 2 else []


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


class DNSTunnelDetector(Detector):
    """Flags DNS query patterns that look like tunneling (exfil / C2).

    Tools like iodine, dnscat2 and DNS-based C2 smuggle data through DNS by
    encoding it into the query name and leaning on record types that return
    arbitrary data (TXT, NULL, CNAME). That leaves four observable
    fingerprints, and this detector scores a query on all of them:

      1. an over-long subdomain label (`max_subdomain_length`)
      2. a high-Shannon-entropy subdomain (`entropy_threshold`) -- encoded
         payloads look far more random than real hostnames
      3. a high per-source query rate in a rolling 60s window
         (`max_queries_per_minute`)
      4. a suspicious record type (`suspicious_query_types`)

    No single weak signal fires an alert on its own; a strong signal, or a
    suspicious query type combined with any elevated signal, does. The event
    details spell out exactly which signals tripped. A per-source cooldown
    keeps a sustained tunnel to one alert per `cooldown` seconds.
    """

    name = "DNS_TUNNEL"

    # queries in the rolling window are always measured over 60 seconds --
    # `max_queries_per_minute` is a per-minute figure by definition
    WINDOW_SECONDS = 60.0
    # score needed to raise an alert; strong signals are worth 2, elevated
    # ("close but under threshold") signals and a suspicious query type 1
    TRIGGER_SCORE = 2.0

    def __init__(
        self,
        max_subdomain_length: int = 50,
        max_queries_per_minute: int = 60,
        entropy_threshold: float = 3.5,
        suspicious_query_types: Optional[List[str]] = None,
        cooldown: float = 60.0,
    ) -> None:
        self.max_subdomain_length = max_subdomain_length
        self.max_queries_per_minute = max_queries_per_minute
        self.entropy_threshold = entropy_threshold
        self.suspicious_query_types = [
            qtype.upper()
            for qtype in (
                suspicious_query_types
                if suspicious_query_types is not None
                else ["TXT", "NULL", "CNAME"]
            )
        ]
        self.cooldown = cooldown
        # src_ip -> deque of DNS query timestamps within the rolling window
        self._query_times: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Scores one DNS query against all four tunneling signals and emits
        an event if the combined score crosses ``TRIGGER_SCORE``."""
        if packet.protocol not in ("UDP", "TCP") or not packet.src_ip:
            return []
        # DNS runs on port 53; sniffer.py only fills dns_qname for actual
        # queries (qr == 0), so a missing name means "not a DNS query".
        if 53 not in (packet.src_port, packet.dst_port) or not packet.dns_qname:
            return []

        now = packet.timestamp
        times = self._query_times[packet.src_ip]
        times.append(now)
        cutoff = now - self.WINDOW_SECONDS
        while times and times[0] < cutoff:
            times.popleft()

        score = 0.0
        signals: List[str] = []

        labels = _subdomain_labels(packet.dns_qname)
        longest = max((len(label) for label in labels), default=0)
        if longest > self.max_subdomain_length:
            score += 2.0
            signals.append(f"subdomain length: {longest}")
        elif longest > self.max_subdomain_length * 0.6:
            score += 1.0
            signals.append(f"subdomain length: {longest} (elevated)")

        entropy = _shannon_entropy("".join(labels))
        if entropy > self.entropy_threshold:
            score += 2.0
            signals.append(f"entropy: {entropy:.1f}")
        elif entropy > self.entropy_threshold * 0.85:
            score += 1.0
            signals.append(f"entropy: {entropy:.1f} (elevated)")

        rate = len(times)
        if rate > self.max_queries_per_minute:
            score += 2.0
            signals.append(f"query rate: {rate}/min")
        elif rate > self.max_queries_per_minute * 0.75:
            score += 1.0
            signals.append(f"query rate: {rate}/min (elevated)")

        qtype = (packet.dns_qtype or "").upper()
        if qtype in self.suspicious_query_types:
            score += 1.0
            signals.append(f"query type: {qtype}")

        if score < self.TRIGGER_SCORE:
            return []

        last_alert = self._last_alert.get(packet.src_ip, float("-inf"))
        if now - last_alert < self.cooldown:
            return []

        self._last_alert[packet.src_ip] = now
        details = (
            f"Suspicious DNS query for '{packet.dns_qname}' -- "
            + ", ".join(signals)
            + f" (score {score:.0f}/{self.TRIGGER_SCORE:.0f})"
        )
        return [
            Event(
                event_type=self.name,
                source_ip=packet.src_ip,
                details=details,
                timestamp=to_datetime(now),
            )
        ]


def _load_ja3_blocklist(path: str) -> FrozenSet[str]:
    """Reads a plain-text JA3 blocklist: one hash per line, blank lines and
    `#`-prefixed comments ignored. Hashes are lowercased so lookups are
    case-insensitive. A missing file just means an empty blocklist -- it's
    the shipped default path and most installs won't have populated it yet
    (see data/ja3_blocklist.txt), so this logs a warning rather than raising.
    """
    file_path = Path(path)
    if not file_path.exists():
        logger.warning(
            "JA3 blocklist file %s not found; TLSAnomalyDetector will not "
            "flag any JA3 hashes until one is supplied",
            file_path,
        )
        return frozenset()

    hashes = set()
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hashes.add(line.lower())
    return frozenset(hashes)


class TLSAnomalyDetector(Detector):
    """Flags malicious-looking TLS handshakes: known-bad JA3 client
    fingerprints, and server certificates with C2-style red flags.

    JA3 (https://github.com/salesforce/ja3) fingerprints a TLS client by
    hashing its ClientHello -- SSL/TLS version, cipher list, extensions,
    elliptic curves, and elliptic curve point formats -- into a single MD5
    digest that's stable per TLS library/config, regardless of destination.
    Malware families and C2 frameworks tend to reuse the same TLS stack
    across infections, so a known-bad JA3 hash is a strong signal even when
    the destination IP/domain is brand new.

    Certificates get checked independently for signs of hastily-stood-up
    infrastructure: self-signed, expired/not-yet-valid, unusually
    short-lived, or very recently issued certs are all common on C2 servers,
    which don't tend to bother with (or can't get) a long-lived cert from a
    real CA the way a legitimate long-running service would.

    JA3 hashes and certificate fields are extracted upstream in
    src/sniffer.py (the actual TLS parsing lives in src/tls_parser.py) --
    this detector only deals with the already-parsed PacketInfo fields,
    mirroring how DNSTunnelDetector only looks at dns_qname/dns_qtype rather
    than parsing DNS packets itself.
    """

    name = "TLS_ANOMALY"

    def __init__(
        self,
        ja3_blocklist_path: str = "data/ja3_blocklist.txt",
        flag_self_signed: bool = True,
        flag_expired_certs: bool = True,
        flag_short_validity_days: int = 7,
        flag_recently_issued_days: int = 2,
        cooldown: float = 60.0,
    ) -> None:
        self.flag_self_signed = flag_self_signed
        self.flag_expired_certs = flag_expired_certs
        self.flag_short_validity_days = flag_short_validity_days
        self.flag_recently_issued_days = flag_recently_issued_days
        self.cooldown = cooldown
        # loaded once at construction -- see src/config.py, no config-reload
        # mechanism exists anywhere else in NetSentry either
        self._ja3_blocklist = _load_ja3_blocklist(ja3_blocklist_path)
        self._last_alert: Dict[str, float] = {}

    def process_packet(self, packet: PacketInfo) -> List[Event]:
        """Checks a JA3-carrying packet (ClientHello) against the blocklist,
        or a certificate-carrying packet (Certificate message) against the
        four cert red flags -- whichever this particular packet has."""
        if packet.tls_ja3:
            event = self._check_ja3(packet)
            if event is not None:
                return [event]
        if packet.tls_cert_subject is not None:
            event = self._check_certificate(packet)
            if event is not None:
                return [event]
        return []

    def _on_cooldown(self, src_ip: str, now: float) -> bool:
        last_alert = self._last_alert.get(src_ip, float("-inf"))
        return now - last_alert < self.cooldown

    def _check_ja3(self, packet: PacketInfo) -> Optional[Event]:
        if not packet.src_ip or packet.tls_ja3.lower() not in self._ja3_blocklist:
            return None
        if self._on_cooldown(packet.src_ip, packet.timestamp):
            return None

        self._last_alert[packet.src_ip] = packet.timestamp
        details = f"JA3 fingerprint {packet.tls_ja3} matches known-malicious blocklist"
        return Event(
            event_type=self.name,
            source_ip=packet.src_ip,
            details=details,
            timestamp=to_datetime(packet.timestamp),
        )

    def _check_certificate(self, packet: PacketInfo) -> Optional[Event]:
        signals: List[str] = []
        now = to_datetime(packet.timestamp)

        if self.flag_self_signed and packet.tls_cert_issuer == packet.tls_cert_subject:
            signals.append(f"self-signed certificate (subject: {packet.tls_cert_subject})")

        not_before = packet.tls_cert_not_before
        not_after = packet.tls_cert_not_after
        if self.flag_expired_certs and not_after is not None and not_after < now:
            signals.append(f"certificate expired (notAfter: {not_after.isoformat()})")
        if self.flag_expired_certs and not_before is not None and not_before > now:
            signals.append(f"certificate not yet valid (notBefore: {not_before.isoformat()})")

        if not_before is not None and not_after is not None:
            validity_days = (not_after - not_before).total_seconds() / 86400
            if validity_days < self.flag_short_validity_days:
                signals.append(
                    f"unusually short validity period ({validity_days:.1f} days)"
                )

            issued_days_ago = (now - not_before).total_seconds() / 86400
            if 0 <= issued_days_ago < self.flag_recently_issued_days:
                signals.append(f"recently issued ({issued_days_ago:.1f} days ago)")

        if not signals or not packet.src_ip:
            return None
        if self._on_cooldown(packet.src_ip, packet.timestamp):
            return None

        self._last_alert[packet.src_ip] = packet.timestamp
        details = "Suspicious TLS certificate -- " + "; ".join(signals)
        return Event(
            event_type=self.name,
            source_ip=packet.src_ip,
            details=details,
            timestamp=now,
        )
