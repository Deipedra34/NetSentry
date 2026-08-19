"""Glues the detectors, database and packet stream together.

DetectionEngine is basically the middleman -- the sniffer calls it for every
packet it captures, it runs that packet past every active detector, and
whatever events come out get saved to the db and logged. Nothing fancy.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Union

from src.config import Config
from src.database import Database
from src.detectors import ArpSpoofDetector, Detector, DosDetector, PortScanDetector, TrafficAnomalyDetector
from src.packet_info import PacketInfo

logger = logging.getLogger("netsentry.engine")

# names the CLI --detectors flag and config.yaml both use to refer to detectors
DETECTOR_NAMES = ("port_scan", "arp_spoof", "dos", "traffic_anomaly")


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

    return detectors


def _parse_whitelist(entries: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Turns whitelist strings (exact IPs or CIDR ranges) into ip_network objects
    we can do fast `in` checks against. strict=False so a bare IP like
    "10.0.0.5" doesn't blow up for not being a proper network address."""
    return [ipaddress.ip_network(entry, strict=False) for entry in entries]


class DetectionEngine:
    """Runs every packet past the active detectors, one at a time."""

    def __init__(self, database: Database, detectors: List[Detector], whitelist: List[str] | None = None) -> None:
        # detectors should already be built/configured by build_detectors() before
        # they get here, this class doesn't do any of that itself
        self.database = database
        self.detectors = detectors
        self._whitelist_networks = _parse_whitelist(whitelist or [])
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
                logger.warning(
                    "ALERT [%s] source=%s :: %s",
                    event.event_type,
                    event.source_ip,
                    event.details,
                )
