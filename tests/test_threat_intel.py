"""Unit tests for :mod:`src.threat_intel`.

Every HTTP call is mocked -- nothing here ever talks to AbuseIPDB or
VirusTotal for real.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.config import Config, load_config
from src.database import Database, Event
from src.engine import DetectionEngine
from src.threat_intel import ABUSEIPDB_URL, ThreatIntelLookup

from tests.conftest import make_packet

PUBLIC_IP = "45.33.12.9"
NOW = 1_800_000_000.0
HOUR = 3600.0

ABUSEIPDB_PAYLOAD = {"data": {"ipAddress": PUBLIC_IP, "abuseConfidenceScore": 87, "totalReports": 42}}
VIRUSTOTAL_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 0,
                "harmless": 60,
                "undetected": 22,
                "timeout": 0,
            }
        }
    }
}


def _make_event(event_type: str = "SYN_FLOOD", source_ip: str = PUBLIC_IP) -> Event:
    return Event(
        event_type=event_type,
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _config(abuseipdb: bool = True, virustotal: bool = True, min_severity: str = "high") -> Config:
    config = Config()
    config.threat_intel.enabled = True
    config.threat_intel.min_severity = min_severity
    config.threat_intel.abuseipdb.enabled = abuseipdb
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    config.threat_intel.virustotal.enabled = virustotal
    config.threat_intel.virustotal.api_key = "vt-key"
    return config


def _response(status_code: int = 200, payload: Optional[Dict[str, Any]] = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload if payload is not None else {}
    return response


def _fake_get(abuseipdb: Any = None, virustotal: Any = None):
    """Builds a requests.get replacement routing by URL. Each argument is
    either a response to return or an exception instance to raise; the
    defaults return the canned payloads above."""
    abuseipdb = abuseipdb if abuseipdb is not None else _response(payload=ABUSEIPDB_PAYLOAD)
    virustotal = virustotal if virustotal is not None else _response(payload=VIRUSTOTAL_PAYLOAD)

    def fake_get(url: str, **_kwargs: Any) -> MagicMock:
        outcome = abuseipdb if url == ABUSEIPDB_URL else virustotal
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return fake_get


def _called_urls(mock_get: MagicMock) -> List[str]:
    return [call.args[0] for call in mock_get.call_args_list]


# --- config -------------------------------------------------------------------


def test_config_defaults_are_disabled_and_yaml_overrides_merge(tmp_path: Any) -> None:
    defaults = Config().threat_intel
    assert defaults.enabled is False
    assert defaults.abuseipdb.enabled is False
    assert defaults.abuseipdb.api_key == ""
    assert defaults.abuseipdb.max_age_days == 90
    assert defaults.virustotal.enabled is False
    assert defaults.virustotal.api_key == ""
    assert defaults.cache_ttl_hours == 24

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "threat_intel:\n"
        "  enabled: true\n"
        "  cache_ttl_hours: 6\n"
        "  virustotal:\n"
        "    enabled: true\n"
        "    api_key: vt-key\n",
        encoding="utf-8",
    )
    loaded = load_config(config_file).threat_intel
    assert loaded.enabled is True
    assert loaded.cache_ttl_hours == 6
    assert loaded.virustotal.api_key == "vt-key"
    assert loaded.abuseipdb.enabled is False
    assert loaded.abuseipdb.max_age_days == 90


# --- which IPs/events get looked up ------------------------------------------


def test_private_and_local_ips_never_trigger_a_lookup(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)

    for private_ip in ("192.168.1.50", "10.0.0.5", "172.16.0.9", "127.0.0.1", "169.254.1.1", "::1", "fe80::1"):
        event = _make_event(source_ip=private_ip)
        with patch("src.threat_intel.requests.get") as mock_get:
            assert lookup.enrich(event, now=NOW) is None
        mock_get.assert_not_called()
        assert event.details == "something sketchy happened"


def test_whitelisted_ip_never_triggers_a_lookup(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db, whitelist=[PUBLIC_IP])

    with patch("src.threat_intel.requests.get") as mock_get:
        assert lookup.enrich(_make_event(), now=NOW) is None

    mock_get.assert_not_called()


def test_whitelisted_cidr_range_never_triggers_a_lookup(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db, whitelist=["45.33.12.0/24"])

    with patch("src.threat_intel.requests.get") as mock_get:
        assert lookup.enrich(_make_event(), now=NOW) is None

    mock_get.assert_not_called()


def test_disabled_by_default_never_looks_anything_up(in_memory_db: Database) -> None:
    config = Config()
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    lookup = ThreatIntelLookup(config, in_memory_db)

    with patch("src.threat_intel.requests.get") as mock_get:
        assert lookup.enrich(_make_event(), now=NOW) is None

    mock_get.assert_not_called()


def test_events_below_min_severity_are_not_looked_up(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(min_severity="high"), in_memory_db)

    with patch("src.threat_intel.requests.get") as mock_get:
        # PORT_SCAN ranks "low", below the configured "high"
        assert lookup.enrich(_make_event(event_type="PORT_SCAN"), now=NOW) is None

    mock_get.assert_not_called()


def test_enabled_service_without_api_key_is_skipped(in_memory_db: Database) -> None:
    config = _config()
    config.threat_intel.virustotal.api_key = ""
    lookup = ThreatIntelLookup(config, in_memory_db)

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()) as mock_get:
        lookup.enrich(_make_event(), now=NOW)

    assert _called_urls(mock_get) == [ABUSEIPDB_URL]


# --- enrichment ---------------------------------------------------------------


def test_event_details_are_enriched_with_parsed_results(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = in_memory_db.log_event(_make_event())

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()) as mock_get:
        result = lookup.enrich(event, now=NOW)

    assert result is not None
    assert result.abuseipdb_score == 87
    assert result.abuseipdb_reports == 42
    assert result.virustotal_malicious_count == 12
    assert result.virustotal_total_engines == 94
    assert event.details == (
        "something sketchy happened "
        "[AbuseIPDB: 87% confidence, 42 reports | VirusTotal: 12/94 engines flagged malicious]"
    )
    # the already-written db row is updated too, so the dashboard sees it
    assert in_memory_db.get_events()[0].details == event.details

    abuse_call = next(c for c in mock_get.call_args_list if c.args[0] == ABUSEIPDB_URL)
    assert abuse_call.kwargs["headers"]["Key"] == "abuse-key"
    assert abuse_call.kwargs["params"] == {"ipAddress": PUBLIC_IP, "maxAgeInDays": 90}
    assert abuse_call.kwargs["timeout"] <= 5
    vt_call = next(c for c in mock_get.call_args_list if c.args[0] != ABUSEIPDB_URL)
    assert vt_call.args[0].endswith(f"/ip_addresses/{PUBLIC_IP}")
    assert vt_call.kwargs["headers"]["x-apikey"] == "vt-key"


def test_only_one_service_configured_is_used_on_its_own(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(abuseipdb=False, virustotal=True), in_memory_db)
    event = _make_event()

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()) as mock_get:
        lookup.enrich(event, now=NOW)

    assert len(mock_get.call_args_list) == 1
    assert "AbuseIPDB" not in event.details
    assert "VirusTotal: 12/94 engines flagged malicious" in event.details


# --- caching ------------------------------------------------------------------


def test_cached_result_is_used_instead_of_requerying_within_ttl(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()) as mock_get:
        lookup.enrich(_make_event(), now=NOW)
        assert mock_get.call_count == 2

        second = _make_event()
        lookup.enrich(second, now=NOW + 2 * HOUR)

    assert mock_get.call_count == 2
    assert "AbuseIPDB: 87% confidence, 42 reports" in second.details


def test_sqlite_cache_is_used_across_instances(in_memory_db: Database) -> None:
    with patch("src.threat_intel.requests.get", side_effect=_fake_get()):
        ThreatIntelLookup(_config(), in_memory_db).enrich(_make_event(), now=NOW)

    fresh_lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = _make_event()
    with patch("src.threat_intel.requests.get") as mock_get:
        fresh_lookup.enrich(event, now=NOW + HOUR)

    mock_get.assert_not_called()
    assert "VirusTotal: 12/94" in event.details


def test_expired_cache_is_requeried(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()) as mock_get:
        lookup.enrich(_make_event(), now=NOW)
        lookup.enrich(_make_event(), now=NOW + 25 * HOUR)

    assert mock_get.call_count == 4


def test_clean_results_are_cached_too(in_memory_db: Database) -> None:
    clean_abuse = _response(payload={"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    clean_vt = _response(
        payload={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70, "undetected": 24}}}}
    )
    lookup = ThreatIntelLookup(_config(), in_memory_db)

    with patch("src.threat_intel.requests.get", side_effect=_fake_get(clean_abuse, clean_vt)) as mock_get:
        lookup.enrich(_make_event(), now=NOW)
        lookup.enrich(_make_event(), now=NOW + HOUR)

    assert mock_get.call_count == 2
    cached = in_memory_db.get_threat_intel(PUBLIC_IP)
    assert cached is not None
    assert cached.abuseipdb_score == 0
    assert cached.virustotal_malicious_count == 0
    assert cached.virustotal_total_engines == 94


# --- failure isolation --------------------------------------------------------


@pytest.mark.parametrize(
    "abuse_outcome",
    [
        _response(status_code=500),
        _response(status_code=401),
        _response(status_code=429),
        requests.Timeout("slow"),
        requests.ConnectionError("no route"),
    ],
    ids=["http-500", "bad-key-401", "rate-limit-429", "timeout", "network-error"],
)
def test_abuseipdb_failure_does_not_stop_virustotal(in_memory_db: Database, abuse_outcome: Any) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = _make_event()

    with patch("src.threat_intel.requests.get", side_effect=_fake_get(abuseipdb=abuse_outcome)) as mock_get:
        result = lookup.enrich(event, now=NOW)

    assert mock_get.call_count == 2
    assert result is not None
    assert result.abuseipdb_score is None
    assert result.virustotal_malicious_count == 12
    assert "AbuseIPDB" not in event.details
    assert "VirusTotal: 12/94 engines flagged malicious" in event.details


def test_virustotal_failure_does_not_stop_abuseipdb(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = _make_event()

    with patch(
        "src.threat_intel.requests.get", side_effect=_fake_get(virustotal=_response(status_code=429))
    ) as mock_get:
        lookup.enrich(event, now=NOW)

    assert mock_get.call_count == 2
    assert "AbuseIPDB: 87% confidence, 42 reports" in event.details
    assert "VirusTotal" not in event.details


def test_malformed_response_is_handled_gracefully(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = _make_event()

    with patch(
        "src.threat_intel.requests.get",
        side_effect=_fake_get(abuseipdb=_response(payload={"errors": ["nope"]})),
    ):
        lookup.enrich(event, now=NOW)

    assert "VirusTotal: 12/94" in event.details


def test_both_services_failing_leaves_event_untouched(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    event = _make_event()

    with patch(
        "src.threat_intel.requests.get",
        side_effect=_fake_get(requests.ConnectionError("down"), requests.ConnectionError("down")),
    ):
        assert lookup.enrich(event, now=NOW) is None

    assert event.details == "something sketchy happened"
    assert in_memory_db.get_threat_intel(PUBLIC_IP) is None


def test_failing_ip_is_not_requeried_within_cooldown(in_memory_db: Database) -> None:
    config = _config()
    config.notifications.cooldown = 300
    lookup = ThreatIntelLookup(config, in_memory_db)
    failing = _fake_get(requests.ConnectionError("down"), requests.ConnectionError("down"))

    with patch("src.threat_intel.requests.get", side_effect=failing) as mock_get:
        lookup.enrich(_make_event(), now=NOW)
        lookup.enrich(_make_event(), now=NOW + 10)
        assert mock_get.call_count == 2
        lookup.enrich(_make_event(), now=NOW + 301)

    assert mock_get.call_count == 4


def test_repeated_identical_failures_warn_only_once(
    in_memory_db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(virustotal=False)
    config.notifications.cooldown = 0
    lookup = ThreatIntelLookup(config, in_memory_db)
    caplog.set_level(logging.WARNING, logger="netsentry.threat_intel")

    with patch("src.threat_intel.requests.get", side_effect=_fake_get(abuseipdb=_response(status_code=401))):
        for offset in range(5):
            lookup.enrich(_make_event(), now=NOW + offset)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "abuseipdb" in r.getMessage()]
    assert len(warnings) == 1
    assert "401" in warnings[0].getMessage()


# --- engine integration -------------------------------------------------------


class _AlwaysFires:
    name = "always_fires"

    def process_packet(self, packet: Any) -> List[Event]:
        return [Event(event_type="SYN_FLOOD", source_ip=packet.src_ip, details="flood")]


def test_engine_enriches_event_before_notifying(in_memory_db: Database) -> None:
    notifier = MagicMock()
    lookup = ThreatIntelLookup(_config(), in_memory_db)
    engine = DetectionEngine(in_memory_db, [_AlwaysFires()], notifier=notifier, threat_intel=lookup)

    with patch("src.threat_intel.requests.get", side_effect=_fake_get()):
        engine.handle_packet(make_packet(timestamp=NOW, src_ip=PUBLIC_IP))

    notified_event = notifier.notify.call_args.args[0]
    assert "AbuseIPDB: 87% confidence" in notified_event.details
    assert "AbuseIPDB: 87% confidence" in in_memory_db.get_events()[0].details


def test_engine_survives_threat_intel_crash(in_memory_db: Database) -> None:
    lookup = MagicMock()
    lookup.enrich.side_effect = RuntimeError("boom")
    notifier = MagicMock()
    engine = DetectionEngine(in_memory_db, [_AlwaysFires()], notifier=notifier, threat_intel=lookup)

    engine.handle_packet(make_packet(timestamp=NOW, src_ip=PUBLIC_IP))

    assert engine.event_count == 1
    notifier.notify.assert_called_once()
