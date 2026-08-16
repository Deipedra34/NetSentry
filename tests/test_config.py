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
