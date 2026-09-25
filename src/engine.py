"""Glues the detectors, database and packet stream together.

DetectionEngine is basically the middleman -- the sniffer calls it for every
packet it captures, it runs that packet past every active detector, and
whatever events come out get saved to the db and logged. Nothing fancy.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Union

from src.auto_block import AutoBlocker
from src.config import Config
from src.database import Database
from src.detectors import (
    ArpSpoofDetector,
    Detector,
    DNSTunnelDetector,
    DosDetector,
    MLAnomalyDetector,
    PortScanDetector,
    TLSAnomalyDetector,
    TrafficAnomalyDetector,
)
from src.notifications import NotificationDispatcher
from src.packet_info import PacketInfo
from src.pcap_export import PcapExporter
from src.threat_intel import ThreatIntelLookup

logger = logging.getLogger("netsentry.engine")

# names the CLI --detectors flag and config.yaml both use to refer to detectors
DETECTOR_NAMES = (
    "port_scan",
    "arp_spoof",
    "dos",
    "traffic_anomaly",
    "dns_tunnel",
    "tls_anomaly",
    "ml_anomaly",
)


def build_detectors(config: Config, enabled: List[str] | None = None) -> List[Detector]:
    """Builds the list of detector instances we're actually going to run.

    If enabled is None we just go by whatever's turned on in the config file
    (enabled: true/false per section). If it's given explicitly (e.g. from
    --detectors on the CLI) that overrides the config entirely -- only the
    named ones get built, config's enabled flags are ignored for those.

    Raises ValueError if you pass a name that doesn't exist.
    """
    if enabled is not None:
        unknown = set(enabled) - set(DETECTOR_NAMES)
        if unknown:
            raise ValueError(
                f"Unknown detector name(s): {sorted(unknown)}. "
                f"Valid options: {list(DETECTOR_NAMES)}"
            )

    def wants(section_name: str, section_enabled: bool) -> bool:
        if enabled is not None:
            return section_name in enabled
        return section_enabled

    detectors: List[Detector] = []

    if wants("port_scan", config.port_scan.enabled):
        detectors.append(
            PortScanDetector(
                port_threshold=config.port_scan.port_threshold,
                time_window=config.port_scan.time_window,
                cooldown=config.port_scan.cooldown,
            )
        )
    if wants("arp_spoof", config.arp_spoof.enabled):
        detectors.append(ArpSpoofDetector(cooldown=config.arp_spoof.cooldown))
    if wants("dos", config.dos.enabled):
        detectors.append(
            DosDetector(
                syn_threshold=config.dos.syn_threshold,
                time_window=config.dos.time_window,
                cooldown=config.dos.cooldown,
            )
        )
    if wants("traffic_anomaly", config.traffic_anomaly.enabled):
        detectors.append(
            TrafficAnomalyDetector(
                window_seconds=config.traffic_anomaly.window_seconds,
                baseline_windows=config.traffic_anomaly.baseline_windows,
                multiplier=config.traffic_anomaly.multiplier,
                min_baseline_samples=config.traffic_anomaly.min_baseline_samples,
            )
        )
    if wants("dns_tunnel", config.dns_tunnel.enabled):
        detectors.append(
            DNSTunnelDetector(
                max_subdomain_length=config.dns_tunnel.max_subdomain_length,
                max_queries_per_minute=config.dns_tunnel.max_queries_per_minute,
                entropy_threshold=config.dns_tunnel.entropy_threshold,
                suspicious_query_types=config.dns_tunnel.suspicious_query_types,
                cooldown=config.dns_tunnel.cooldown,
            )
        )
    if wants("tls_anomaly", config.tls_anomaly.enabled):
        detectors.append(
            TLSAnomalyDetector(
                ja3_blocklist_path=config.tls_anomaly.ja3_blocklist_path,
                flag_self_signed=config.tls_anomaly.flag_self_signed,
                flag_expired_certs=config.tls_anomaly.flag_expired_certs,
                flag_short_validity_days=config.tls_anomaly.flag_short_validity_days,
                flag_recently_issued_days=config.tls_anomaly.flag_recently_issued_days,
                cooldown=config.tls_anomaly.cooldown,
            )
        )
    if wants("ml_anomaly", config.ml_anomaly.enabled):
        detectors.append(
            MLAnomalyDetector(
                model_path=config.ml_anomaly.model_path,
                algorithm=config.ml_anomaly.algorithm,
                anomaly_score_threshold=config.ml_anomaly.anomaly_score_threshold,
                feature_window_seconds=config.ml_anomaly.feature_window_seconds,
                cooldown=config.ml_anomaly.cooldown,
            )
        )

    return detectors


def _parse_whitelist(entries: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Turns whitelist strings (exact IPs or CIDR ranges) into ip_network objects
    we can do fast `in` checks against. strict=False so a bare IP like
    "10.0.0.5" doesn't blow up for not being a proper network address."""
    return [ipaddress.ip_network(entry, strict=False) for entry in entries]


class DetectionEngine:
    """Runs every packet past the active detectors, one at a time."""

    def __init__(
        self,
        database: Database,
        detectors: List[Detector],
        whitelist: List[str] | None = None,
        notifier: NotificationDispatcher | None = None,
        pcap_exporter: PcapExporter | None = None,
        auto_blocker: AutoBlocker | None = None,
        threat_intel: ThreatIntelLookup | None = None,
    ) -> None:
        # detectors should already be built/configured by build_detectors() before
        # they get here, this class doesn't do any of that itself
        self.database = database
        self.detectors = detectors
        self._whitelist_networks = _parse_whitelist(whitelist or [])
        self.notifier = notifier
        self.pcap_exporter = pcap_exporter
        self.auto_blocker = auto_blocker
        self.threat_intel = threat_intel
        self._packet_count = 0
        self._event_count = 0

    @property
    def packet_count(self) -> int:
        """how many packets we've seen so far"""
        return self._packet_count

    @property
    def event_count(self) -> int:
        """how many events have fired total"""
        return self._event_count

    def _is_whitelisted(self, src_ip: str | None) -> bool:
        """True if src_ip matches an exact IP or falls inside a CIDR range
        from the whitelist."""
        if src_ip is None or not self._whitelist_networks:
            return False
        try:
            addr = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        return any(addr in network for network in self._whitelist_networks)

    def handle_packet(self, packet: PacketInfo) -> None:
        """This is the callback the sniffer calls per packet. Runs it through
        every detector and logs whatever comes back."""
        self._packet_count += 1
        if self.pcap_exporter is not None:
            try:
                self.pcap_exporter.add_packet(packet)
            except Exception:  # noqa: BLE001 - buffering failures must not affect capture
                logger.exception("PcapExporter raised an exception buffering a packet")
        if self.auto_blocker is not None:
            try:
                self.auto_blocker.maybe_check_expired()
            except Exception:  # noqa: BLE001 - expiry-check failures must not affect capture
                logger.exception("AutoBlocker raised an exception checking for expired blocks")
        if self._is_whitelisted(packet.src_ip):
            logger.debug("Skipping detection for whitelisted source IP %s", packet.src_ip)
            return
        for detector in self.detectors:
            try:
                events = detector.process_packet(packet)
            except Exception:  # noqa: BLE001 - don't let one broken detector take down the whole capture
                logger.exception("Detector '%s' raised an exception", detector.name)
                continue
            for event in events:
                self.database.log_event(event)
                self._event_count += 1
                # runs before the alert log line + notifications so both
                # carry the enriched details
                if self.threat_intel is not None:
                    try:
                        self.threat_intel.enrich(event)
                    except Exception:  # noqa: BLE001 - threat intel failures must not affect capture
                        logger.exception("ThreatIntelLookup raised an exception")
                logger.warning(
                    "ALERT [%s] source=%s :: %s",
                    event.event_type,
                    event.source_ip,
                    event.details,
                )
                if self.notifier is not None:
                    try:
                        self.notifier.notify(event)
                    except Exception:  # noqa: BLE001 - notification failures must not affect capture
                        logger.exception("NotificationDispatcher raised an exception")
                if self.pcap_exporter is not None:
                    try:
                        self.pcap_exporter.export(event, packet)
                    except Exception:  # noqa: BLE001 - pcap export failures must not affect capture
                        logger.exception("PcapExporter raised an exception")
                if self.auto_blocker is not None:
                    try:
                        self.auto_blocker.maybe_block(event)
                    except Exception:  # noqa: BLE001 - auto-block failures must not affect capture
                        logger.exception("AutoBlocker raised an exception")
