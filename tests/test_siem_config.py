"""Tests for the siem section of :mod:`src.config`."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.config import Config, load_config, parse_siem_destinations


def _udp(**overrides: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"name": "syslog", "format": "rfc5424", "transport": "udp", "host": "10.0.0.5"}
    entry.update(overrides)
    return entry


def test_defaults() -> None:
    siem = Config().siem
    assert siem.enabled is False
    assert siem.destinations == []
    assert siem.hostname == ""
    assert siem.app_name == "netsentry"
    assert siem.facility == "local0"
    assert siem.queue_size == 10000
    assert siem.include_details is True
    assert siem.ecs_fields is False


def test_shipped_config_yaml_keeps_siem_off() -> None:
    config = load_config(Path(__file__).resolve().parent.parent / "config.yaml")
    assert config.siem.enabled is False
    assert parse_siem_destinations(config.siem.destinations) == ([], [])


def test_overrides_from_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
siem:
  enabled: true
  hostname: sensor-1
  facility: local3
  queue_size: 50
  ecs_fields: true
  destinations:
    - name: elastic
      format: json
      transport: tls
      host: logs.example.com
      port: 5514
      ca_file: certs/ca.pem
    - name: wazuh
      format: json
      transport: file
      path: siem/events.ndjson
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.siem.enabled is True
    assert config.siem.hostname == "sensor-1"
    assert config.siem.facility == "local3"
    assert config.siem.queue_size == 50
    assert config.siem.ecs_fields is True
    destinations, errors = parse_siem_destinations(config.siem.destinations)
    assert errors == []
    assert [d.name for d in destinations] == ["elastic", "wazuh"]
    elastic, wazuh = destinations
    assert (elastic.transport, elastic.port, elastic.ca_file, elastic.verify) == ("tls", 5514, "certs/ca.pem", True)
    assert (wazuh.path, wazuh.max_size_mb, wazuh.backup_count) == ("siem/events.ndjson", 50, 5)


@pytest.mark.parametrize(
    ("transport", "port"), [("udp", 514), ("tcp", 514), ("tls", 6514)]
)
def test_default_port_per_transport(transport: str, port: int) -> None:
    destinations, errors = parse_siem_destinations([_udp(transport=transport)])
    assert errors == []
    assert destinations[0].port == port


def test_values_are_normalized_to_lower_case() -> None:
    destinations, _ = parse_siem_destinations([_udp(format="CEF", transport="TCP", min_severity="HIGH")])
    assert (destinations[0].format, destinations[0].transport, destinations[0].min_severity) == (
        "cef",
        "tcp",
        "high",
    )


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        (_udp(format="leef"), "format must be one of"),
        (_udp(transport="http"), "transport must be one of"),
        (_udp(port=70000), "port must be between 1 and 65535"),
        (_udp(port=-1), "port must be between 1 and 65535"),
        (_udp(port="514"), "port must be a whole number"),
        (_udp(port=True), "port must be a whole number"),
        (_udp(host=""), "needs a host"),
        (_udp(host="   "), "needs a host"),
        (_udp(min_severity="severe"), "min_severity must be one of"),
        (_udp(framing="null"), "framing must be one of"),
        (_udp(verfy=False), "unknown setting(s) ['verfy']"),
        (_udp(ca_file="ca.pem"), "only apply to the tls transport"),
        (_udp(transport="tls", client_key="key.pem"), "client_key needs a client_cert"),
        (_udp(transport="tls", verify="no"), "verify must be true or false"),
        ({"name": "x", "format": "json"}, "missing required setting(s) ['transport']"),
        ({"format": "json", "transport": "udp", "host": "h"}, "missing required setting(s) ['name']"),
        ({"name": "f", "format": "json", "transport": "file"}, "needs a path"),
        ({"name": "f", "format": "json", "transport": "file", "path": "p", "max_size_mb": 0}, "max_size_mb"),
        ({"name": "f", "format": "json", "transport": "file", "path": "p", "backup_count": -1}, "backup_count"),
        ("udp://10.0.0.5", "must be a mapping"),
    ],
)
def test_invalid_destination_is_skipped_with_a_reason(entry: Any, reason: str) -> None:
    destinations, errors = parse_siem_destinations([entry])
    assert destinations == []
    assert len(errors) == 1
    assert "invalid and skipped" in errors[0]
    assert reason in errors[0]


def test_only_the_invalid_destination_is_skipped() -> None:
    destinations, errors = parse_siem_destinations(
        [_udp(name="good"), _udp(name="bad", port=0.5), _udp(name="also-good", transport="tcp")]
    )
    assert [d.name for d in destinations] == ["good", "also-good"]
    assert len(errors) == 1
    assert "'bad'" in errors[0]


def test_duplicate_names_keep_the_first() -> None:
    destinations, errors = parse_siem_destinations([_udp(), _udp(transport="tcp")])
    assert [d.transport for d in destinations] == ["udp"]
    assert "already used" in errors[0]


def test_destinations_must_be_a_list() -> None:
    assert parse_siem_destinations({"name": "x"}) == ([], ["siem.destinations must be a list of destinations"])
    assert parse_siem_destinations(None) == ([], [])
