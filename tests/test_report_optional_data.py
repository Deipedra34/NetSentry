"""Unit tests for the optional report sections' queries in
:mod:`src.reports.data`: GeoIP countries, threat intel and blocked IPs --
including the "no data" cases where the report leaves a section out."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import pytest

from src.database import BlockedIP, Database, Event, ThreatIntelResult
from src.reports.data import blocks, countries, daily_period, flagged_ips

PERIOD = daily_period(date(2026, 11, 11), timezone.utc)


def at(hour: int, day: int = 11) -> datetime:
    return datetime(2026, 11, day, hour, tzinfo=timezone.utc)


def log(db: Database, when: datetime, details: str, source_ip: str = "45.33.1.1") -> None:
    db.log_event(Event(event_type="PORT_SCAN", source_ip=source_ip, details=details, timestamp=when))


def intel(ip: str, checked_at: datetime, abuse: Optional[int] = None, vt: Optional[int] = None) -> ThreatIntelResult:
    return ThreatIntelResult(
        source_ip=ip,
        checked_at=checked_at,
        abuseipdb_score=abuse,
        abuseipdb_reports=5 if abuse is not None else None,
        virustotal_malicious_count=vt,
        virustotal_total_engines=94 if vt is not None else None,
    )


@pytest.fixture()
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(tmp_path / "reports.db")
    yield database
    database.close()


# --- countries ----------------------------------------------------------------


def test_countries_from_geoip_tags(db: Database) -> None:
    log(db, at(1), "scan [GeoIP: Frankfurt am Main, Germany (DE), AS24940 Hetzner Online GmbH]")
    log(db, at(2), "scan [GeoIP: Germany (DE)] [AbuseIPDB: 87% confidence, 42 reports]")
    # internal source, external destination: counts for the destination
    log(db, at(3), "beacon [GeoIP destination 8.8.8.8: Mountain View, United States (US)]", "10.0.0.5")
    # both ends tagged: the source wins
    log(db, at(4), "x [GeoIP: Paris, France (FR)] [GeoIP destination 8.8.8.8: United States (US)]")
    # an ASN-only description has no country
    log(db, at(5), "x [GeoIP: AS13335 Cloudflare, Inc.]")
    log(db, at(6), "no enrichment at all")
    log(db, at(1, day=10), "previous day [GeoIP: Spain (ES)]")
    assert countries(db, PERIOD) == [("Germany (DE)", 2), ("France (FR)", 1), ("United States (US)", 1)]


def test_countries_empty_without_geoip_data(db: Database) -> None:
    log(db, at(1), "scan [AbuseIPDB: 87% confidence, 42 reports]")
    assert countries(db, PERIOD) == []


# --- threat intel -------------------------------------------------------------


def test_flagged_ips_lists_notable_results_for_active_ips_worst_first(db: Database) -> None:
    log(db, at(1), "scan", "45.33.1.1")
    log(db, at(2), "scan", "45.33.1.1")
    log(db, at(3), "scan", "45.33.2.2")
    log(db, at(4), "scan", "45.33.3.3")
    db.save_threat_intel(intel("45.33.1.1", at(1), abuse=40))
    db.save_threat_intel(intel("45.33.2.2", at(9, day=1), abuse=0, vt=3))  # old lookup, active IP
    db.save_threat_intel(intel("45.33.3.3", at(3), abuse=10, vt=0))  # clean: not notable
    db.save_threat_intel(intel("8.8.4.4", at(5), abuse=95))  # a destination looked up in the period
    db.save_threat_intel(intel("45.33.9.9", at(5, day=1), abuse=100))  # not active in the period
    result = flagged_ips(db, PERIOD)
    assert [(f.intel.source_ip, f.events) for f in result] == [
        ("8.8.4.4", 0),
        ("45.33.1.1", 2),
        ("45.33.2.2", 1),
    ]
    assert result[2].intel.virustotal_malicious_count == 3


def test_flagged_ips_empty_without_notable_results(db: Database) -> None:
    log(db, at(1), "scan")
    assert flagged_ips(db, PERIOD) == []
    db.save_threat_intel(intel("45.33.1.1", at(1), abuse=0, vt=0))
    assert flagged_ips(db, PERIOD) == []


def test_flagged_ips_empty_when_the_cache_table_is_missing(db: Database) -> None:
    db._conn.execute("DROP TABLE threat_intel_cache")
    assert flagged_ips(db, PERIOD) == []


# --- blocked IPs --------------------------------------------------------------


def test_blocks_current_and_applied_during_the_period(db: Database) -> None:
    db.add_blocked_ip(BlockedIP("45.33.1.1", "SYN_FLOOD", "rule-1", blocked_at=at(9, day=1)))
    db.add_blocked_ip(BlockedIP("45.33.2.2", "PORT_SCAN", "rule-2", blocked_at=at(10)))
    result = blocks(db, PERIOD)
    assert bool(result) is True
    assert sorted(b.source_ip for b in result.current) == ["45.33.1.1", "45.33.2.2"]
    assert [b.source_ip for b in result.during_period] == ["45.33.2.2"]


def test_blocks_empty_without_any_block(db: Database) -> None:
    result = blocks(db, PERIOD)
    assert bool(result) is False
    assert (result.current, result.during_period) == ([], [])


def test_blocks_empty_when_the_table_is_missing(db: Database) -> None:
    db._conn.execute("DROP TABLE blocked_ips")
    assert bool(blocks(db, PERIOD)) is False
