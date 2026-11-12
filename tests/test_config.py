"""Unit tests for :mod:`src.config`."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import Config, load_config


def test_defaults_when_no_path_given() -> None:
    config = load_config(None)
    assert isinstance(config, Config)
    assert config.port_scan.port_threshold == 15
    assert config.dos.syn_threshold == 100
    assert config.web.port == 5000


def test_defaults_when_file_missing(tmp_path: Path) -> None:
    config = load_config(tmp_path / "does-not-exist.yaml")
    assert config.port_scan.port_threshold == 15


def test_overrides_from_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
port_scan:
  port_threshold: 42
  time_window: 20
dos:
  syn_threshold: 500
web:
  port: 9000
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.port_scan.port_threshold == 42
    assert config.port_scan.time_window == 20
    assert config.dos.syn_threshold == 500
    assert config.web.port == 9000
    # Untouched sections keep their defaults.
    assert config.arp_spoof.cooldown == 60.0


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("totally_unknown_section:\n  foo: bar\n", encoding="utf-8")
    config = load_config(config_file)
    assert config.port_scan.port_threshold == 15


def test_non_mapping_yaml_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(config_file)


def test_shipped_config_yaml_loads() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    config = load_config(repo_root / "config.yaml")
    assert config.port_scan.enabled is True
    assert config.traffic_anomaly.multiplier == 3.0


def test_interfaces_default_is_empty_list() -> None:
    config = load_config(None)
    assert config.interfaces == []


def test_single_interface_string_is_normalized_to_list(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("interfaces: eth0\n", encoding="utf-8")
    config = load_config(config_file)
    assert config.interfaces == ["eth0"]


def test_interface_list_is_passed_through(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "interfaces:\n  - eth0\n  - wlan0\n",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.interfaces == ["eth0", "wlan0"]


def test_env_vars_override_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "web:\n  host: 127.0.0.1\ndatabase:\n  path: netsentry.db\nlogging:\n  file: netsentry.log\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETSENTRY_WEB_HOST", "0.0.0.0")
    monkeypatch.setenv("NETSENTRY_DATABASE_PATH", "data/netsentry.db")
    monkeypatch.setenv("NETSENTRY_LOG_FILE", "logs/netsentry.log")
    config = load_config(config_file)
    assert config.web.host == "0.0.0.0"
    assert config.database.path == "data/netsentry.db"
    assert config.logging.file == "logs/netsentry.log"


def test_empty_env_vars_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETSENTRY_WEB_HOST", "")
    config = load_config(None)
    assert config.web.host == "127.0.0.1"


def test_reports_defaults() -> None:
    reports = load_config(None).reports
    assert reports.enabled is False
    assert reports.output_dir == "reports/"
    assert (reports.daily, reports.daily_time) == (True, "08:00")
    assert (reports.weekly, reports.weekly_day, reports.weekly_time) == (True, "monday", "08:00")
    assert reports.max_notable_events == 20
    assert reports.top_n_sources == 10
    assert reports.keep_reports == 30


def test_reports_overrides_from_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
reports:
  enabled: true
  output_dir: /srv/netsentry/reports
  daily: false
  weekly_day: friday
  weekly_time: "17:30"
  keep_reports: 5
""",
        encoding="utf-8",
    )
    reports = load_config(config_file).reports
    assert reports.enabled is True
    assert reports.output_dir == "/srv/netsentry/reports"
    assert reports.daily is False
    assert reports.daily_time == "08:00"  # untouched keys keep their defaults
    assert (reports.weekly_day, reports.weekly_time) == ("friday", "17:30")
    assert reports.keep_reports == 5
    assert reports.max_notable_events == 20


def test_shipped_config_reports_section_matches_defaults() -> None:
    shipped = load_config(Path(__file__).resolve().parent.parent / "config.yaml").reports
    assert shipped == load_config(None).reports
