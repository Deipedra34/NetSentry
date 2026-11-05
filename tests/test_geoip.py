"""Unit tests for :mod:`src.geoip`.

The maxminddb reader is replaced with an in-memory fake -- no real GeoIP
database file is needed (or shipped).
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.config import Config, load_config
from src.database import Database, Event
from src.engine import DetectionEngine
from src.geoip import GeoIPLookup
from src.threat_intel import ThreatIntelLookup
from tests.conftest import make_packet

PUBLIC_IP = "45.33.12.9"
OTHER_PUBLIC_IP = "8.8.8.8"

LOCATIONS: Dict[str, Any] = {
    PUBLIC_IP: {
        "city": {"names": {"en": "Frankfurt am Main", "de": "Frankfurt am Main"}},
        "country": {"iso_code": "DE", "names": {"en": "Germany", "de": "Deutschland"}},
    },
    OTHER_PUBLIC_IP: {
        "city": {"names": {"en": "Mountain View"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
    },
    # country-only database, or an address with no city
    "45.33.50.1": {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}}},
    # some anycast/cloud ranges only carry the registered country
    "45.33.60.1": {"registered_country": {"iso_code": "US", "names": {"en": "United States"}}},
}
NETWORKS: Dict[str, Any] = {
    PUBLIC_IP: {"autonomous_system_number": 24940, "autonomous_system_organization": "Hetzner Online GmbH"},
    OTHER_PUBLIC_IP: {"autonomous_system_number": 15169, "autonomous_system_organization": "Google LLC"},
}


def _fake_reader(records: Dict[str, Any]) -> MagicMock:
    reader = MagicMock()
    reader.get.side_effect = records.get
    return reader


def _lookup(
    tmp_path: Path,
    database: Database,
    asn: bool = False,
    enabled: bool = True,
) -> GeoIPLookup:
    """A GeoIPLookup whose database files exist on disk (empty) but are
    opened as the fake readers above."""
    location_file = tmp_path / "city.mmdb"
    location_file.write_bytes(b"")
    config = Config()
    config.geoip.enabled = enabled
    config.geoip.database_path = str(location_file)
    readers = {str(location_file): _fake_reader(LOCATIONS)}
    if asn:
        asn_file = tmp_path / "asn.mmdb"
        asn_file.write_bytes(b"")
        config.geoip.asn_database_path = str(asn_file)
        readers[str(asn_file)] = _fake_reader(NETWORKS)
    with patch("maxminddb.open_database", side_effect=lambda path: readers[path]):
        return GeoIPLookup(config, database)


def _event(source_ip: str = PUBLIC_IP, destination_ip: Optional[str] = None) -> Event:
    return Event(
        event_type="PORT_SCAN",
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        destination_ip=destination_ip,
    )


def test_config_defaults_and_yaml_overrides(tmp_path: Path) -> None:
    config = Config()
    assert config.geoip.enabled is False
    assert config.geoip.database_path == "data/GeoLite2-City.mmdb"
    assert config.geoip.asn_database_path == ""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
geoip:
  enabled: true
  database_path: data/dbip-city-lite.mmdb
  asn_database_path: data/dbip-asn-lite.mmdb
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.geoip.enabled is True
    assert config.geoip.database_path == "data/dbip-city-lite.mmdb"
    assert config.geoip.asn_database_path == "data/dbip-asn-lite.mmdb"


def test_disabled_by_default_never_opens_or_looks_anything_up(in_memory_db: Database) -> None:
    with patch("maxminddb.open_database") as mock_open:
        lookup = GeoIPLookup(Config(), in_memory_db)
    mock_open.assert_not_called()
    assert lookup.enabled is False
    event = _event()
    assert lookup.enrich(event) == {}
    assert event.details == "something sketchy happened"


def test_missing_database_file_disables_lookups(
    tmp_path: Path, in_memory_db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    config = Config()
    config.geoip.enabled = True
    config.geoip.database_path = str(tmp_path / "missing.mmdb")
    with caplog.at_level(logging.WARNING, logger="netsentry.geoip"):
        lookup = GeoIPLookup(config, in_memory_db)
    assert lookup.enabled is False
    assert "not found" in caplog.text
    assert lookup.enrich(_event()) == {}


def test_unreadable_database_file_disables_lookups(
    tmp_path: Path, in_memory_db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    garbage = tmp_path / "garbage.mmdb"
    garbage.write_bytes(b"this is not a MaxMind database")
    config = Config()
    config.geoip.enabled = True
    config.geoip.database_path = str(garbage)
    with caplog.at_level(logging.WARNING, logger="netsentry.geoip"):
        lookup = GeoIPLookup(config, in_memory_db)  # real maxminddb, real failure
    assert lookup.enabled is False
    assert "Failed to open GeoIP location database" in caplog.text


def test_missing_maxminddb_package_disables_lookups(
    tmp_path: Path, in_memory_db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    database_file = tmp_path / "city.mmdb"
    database_file.write_bytes(b"")
    config = Config()
    config.geoip.enabled = True
    config.geoip.database_path = str(database_file)
    with patch.dict(sys.modules, {"maxminddb": None}), caplog.at_level(logging.WARNING, logger="netsentry.geoip"):
        lookup = GeoIPLookup(config, in_memory_db)
    assert lookup.enabled is False
    assert "maxminddb package is not installed" in caplog.text


def test_source_ip_is_enriched_and_stored(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db)
    event = in_memory_db.log_event(_event())
    assert lookup.enrich(event) == {PUBLIC_IP: "Frankfurt am Main, Germany (DE)"}
    assert event.details == "something sketchy happened [GeoIP: Frankfurt am Main, Germany (DE)]"
    # the already-written db row is updated too, so the dashboard sees it
    assert in_memory_db.get_events()[0].details == event.details


def test_asn_database_adds_network_owner(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db, asn=True)
    assert lookup.describe(PUBLIC_IP) == "Frankfurt am Main, Germany (DE), AS24940 Hetzner Online GmbH"
    assert lookup.describe(OTHER_PUBLIC_IP) == "Mountain View, United States (US), AS15169 Google LLC"


def test_partial_records(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db, asn=True)
    assert lookup.describe("45.33.50.1") == "Netherlands (NL)"  # no city, no ASN
    assert lookup.describe("45.33.60.1") == "United States (US)"  # registered country only
    assert lookup.describe("45.33.70.1") is None  # not in the database at all


def test_private_and_local_ips_are_never_looked_up(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db)
    reader = lookup._location_reader
    for ip in ("192.168.1.50", "10.0.0.5", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.251", "not-an-ip"):
        assert lookup.describe(ip) is None
    reader.get.assert_not_called()


def test_destination_ip_is_enriched(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db)
    # the usual exfiltration/beaconing case: private source, public destination
    event = _event(source_ip="192.168.1.20", destination_ip=OTHER_PUBLIC_IP)
    assert lookup.enrich(event) == {OTHER_PUBLIC_IP: "Mountain View, United States (US)"}
    assert event.details == (
        "something sketchy happened [GeoIP destination 8.8.8.8: Mountain View, United States (US)]"
    )
    # both ends public: both are appended, source first
    event = _event(source_ip=PUBLIC_IP, destination_ip=OTHER_PUBLIC_IP)
    lookup.enrich(event)
    assert event.details == (
        "something sketchy happened [GeoIP: Frankfurt am Main, Germany (DE)] "
        "[GeoIP destination 8.8.8.8: Mountain View, United States (US)]"
    )


def test_reader_errors_never_raise(tmp_path: Path, in_memory_db: Database) -> None:
    lookup = _lookup(tmp_path, in_memory_db)
    lookup._location_reader.get.side_effect = ValueError("corrupt record")
    event = _event()
    assert lookup.enrich(event) == {}
    assert event.details == "something sketchy happened"


class _AlwaysFires:
    name = "ALWAYS"

    def process_packet(self, packet: Any) -> list:
        return [Event(event_type="PORT_SCAN", source_ip=packet.src_ip, details="probe", destination_ip=packet.dst_ip)]


def test_engine_enriches_before_threat_intel_and_notifications(tmp_path: Path, in_memory_db: Database) -> None:
    config = Config()
    config.threat_intel.enabled = True
    config.threat_intel.min_severity = "low"
    config.threat_intel.abuseipdb.enabled = True
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    response = MagicMock(status_code=200)
    response.json.return_value = {"data": {"abuseConfidenceScore": 87, "totalReports": 42}}
    notifier = MagicMock()
    engine = DetectionEngine(
        in_memory_db,
        [_AlwaysFires()],
        notifier=notifier,
        threat_intel=ThreatIntelLookup(config, in_memory_db),
        geoip=_lookup(tmp_path, in_memory_db),
    )
    with patch("src.threat_intel.requests.get", return_value=response):
        engine.handle_packet(make_packet(timestamp=1000.0, src_ip=PUBLIC_IP, dst_ip="10.0.0.2"))

    expected = (
        "probe [GeoIP: Frankfurt am Main, Germany (DE)] [AbuseIPDB: 87% confidence, 42 reports]"
    )
    assert notifier.notify.call_args.args[0].details == expected
    assert in_memory_db.get_events()[0].details == expected


def test_engine_survives_geoip_crash(in_memory_db: Database) -> None:
    geoip = MagicMock()
    geoip.enrich.side_effect = RuntimeError("boom")
    engine = DetectionEngine(in_memory_db, [_AlwaysFires()], geoip=geoip)
    engine.handle_packet(make_packet(timestamp=1000.0, src_ip=PUBLIC_IP))
    assert [e.details for e in in_memory_db.get_events()] == ["probe"]
