"""Offline GeoIP enrichment for event IPs.

GeoIPLookup appends where an event's source IP is -- and its destination
IP, for events that set one (beaconing, data exfiltration) -- to the
event's details, e.g. "[GeoIP: Frankfurt am Main, Germany (DE), AS24940
Hetzner Online GmbH]", so the context shows up everywhere details already
do: logs, notifications, dashboard.

Lookups run entirely offline against MaxMind-format (.mmdb) database files
the user downloads themselves -- MaxMind GeoLite2 (free account needed) or
DB-IP Lite (no account) both work, see README.md "GeoIP Enrichment". No
network calls, no quota, so unlike threat intel every event is enriched,
not just critical ones. Mirrors the disabled-by-default, best-effort
pattern of the other optional features: a missing or unreadable database
(or the maxminddb package not being installed) is logged once at startup
and the feature quietly does nothing, it never takes down packet capture.
Private/local/reserved addresses are never looked up -- they aren't in any
GeoIP database anyway.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from src.config import Config
from src.database import Database, Event
from src.threat_intel import _is_lookup_candidate

logger = logging.getLogger("netsentry.geoip")


def _open_database(path: str, label: str) -> Optional[Any]:
    """A maxminddb reader for path, or None (never raises) if the file is
    missing, unreadable, or maxminddb isn't installed."""
    file_path = Path(path)
    if not file_path.exists():
        logger.warning(
            "GeoIP %s database %s not found; %s lookups are disabled for this run. "
            "Download a GeoLite2 or DB-IP Lite .mmdb file and set its path in "
            "config.yaml -- see README.md \"GeoIP Enrichment\".",
            label,
            file_path,
            label,
        )
        return None
    try:
        import maxminddb
    except ImportError:
        logger.warning(
            "The maxminddb package is not installed; GeoIP lookups are disabled. "
            "Install project dependencies with 'pip install -r requirements.txt'."
        )
        return None
    try:
        return maxminddb.open_database(str(file_path))
    except Exception:  # noqa: BLE001 - any load failure just means no lookups
        logger.exception(
            "Failed to open GeoIP %s database %s; %s lookups are disabled for this run",
            label,
            file_path,
            label,
        )
        return None


def _name(section: Any) -> Optional[str]:
    """The English name of a city/country record section, if any."""
    if not isinstance(section, dict):
        return None
    names = section.get("names")
    return names.get("en") if isinstance(names, dict) else None


def _describe_location(record: Any) -> Optional[str]:
    """'Mountain View, United States (US)', 'United States (US)', or None.
    Falls back to the registered country for addresses (anycast, some
    cloud ranges) that only have that."""
    if not isinstance(record, dict):
        return None
    country = record.get("country") or record.get("registered_country")
    country_name = _name(country)
    iso_code = country.get("iso_code") if isinstance(country, dict) else None
    if country_name and iso_code:
        country_text: Optional[str] = f"{country_name} ({iso_code})"
    else:
        country_text = country_name or iso_code
    parts = [part for part in (_name(record.get("city")), country_text) if part]
    return ", ".join(parts) or None


def _describe_network(record: Any) -> Optional[str]:
    """'AS15169 Google LLC', or None."""
    if not isinstance(record, dict):
        return None
    number = record.get("autonomous_system_number")
    organization = record.get("autonomous_system_organization")
    if number and organization:
        return f"AS{number} {organization}"
    if number:
        return f"AS{number}"
    return organization or None


class GeoIPLookup:
    """Looks up event IPs in local GeoIP databases and appends the results
    to the event's details.

    enrich() should be called once per event the engine raises, right after
    it's written to the database and before NotificationDispatcher.notify()
    so alerts carry the extra context -- the same spot ThreatIntelLookup
    hooks in.
    """

    def __init__(self, config: Config, database: Database) -> None:
        self.config = config
        self.database = database
        settings = config.geoip
        # databases are opened once at construction -- see src/config.py, no
        # config-reload mechanism exists anywhere else in NetSentry either
        self._location_reader: Optional[Any] = None
        self._network_reader: Optional[Any] = None
        if settings.enabled:
            self._location_reader = _open_database(settings.database_path, "location")
            if settings.asn_database_path:
                self._network_reader = _open_database(settings.asn_database_path, "ASN")

    @property
    def enabled(self) -> bool:
        """True if at least one database is loaded."""
        return self._location_reader is not None or self._network_reader is not None

    def describe(self, ip: str) -> Optional[str]:
        """'Mountain View, United States (US), AS15169 Google LLC' for a
        public IP, or None if it isn't looked up or nothing is known about
        it. Never raises."""
        if not self.enabled or not ip or not _is_lookup_candidate(ip):
            return None
        parts = []
        for reader, describe in (
            (self._location_reader, _describe_location),
            (self._network_reader, _describe_network),
        ):
            if reader is None:
                continue
            try:
                text = describe(reader.get(ip))
            except Exception:  # noqa: BLE001 - a bad lookup must not affect capture
                logger.debug("GeoIP lookup for %s failed", ip, exc_info=True)
                continue
            if text:
                parts.append(text)
        return ", ".join(parts) or None

    def enrich(self, event: Event) -> Dict[str, str]:
        """Appends GeoIP context for event.source_ip and event.destination_ip
        to event.details (and to the stored event row, if it has an id).
        Returns {ip: description} for whichever IPs got one."""
        found: Dict[str, str] = {}
        source = self.describe(event.source_ip)
        if source:
            found[event.source_ip] = source
            event.details = f"{event.details} [GeoIP: {source}]"
        if event.destination_ip and event.destination_ip != event.source_ip:
            destination = self.describe(event.destination_ip)
            if destination:
                found[event.destination_ip] = destination
                event.details = (
                    f"{event.details} [GeoIP destination {event.destination_ip}: {destination}]"
                )
        if found and event.id is not None:
            self.database.update_event_details(event.id, event.details)
        return found
