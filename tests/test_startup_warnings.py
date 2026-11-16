"""Tests for main.py's startup warnings about how the dashboard is exposed."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

import main
from src.config import Config


def _config(host: str, auth: bool = False, https: bool = False, basic_auth: bool = False) -> Config:
    config = Config()
    config.web.host = host
    config.web.https = https
    config.auth.enabled = auth
    if basic_auth:
        config.web.username, config.web.password = "admin", "pw"
    return config


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.2", "[::1]"])
@pytest.mark.parametrize("auth", [False, True])
def test_no_warnings_on_loopback(host: str, auth: bool) -> None:
    assert main.dashboard_security_warnings(_config(host, auth=auth)) == []


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "netsentry.lan", ""])
def test_exposed_without_auth(host: str) -> None:
    warnings = main.dashboard_security_warnings(_config(host))
    assert len(warnings) == 1
    assert "NO authentication" in warnings[0]
    assert "auth.enabled" in warnings[0]


def test_exposed_with_only_basic_auth() -> None:
    warnings = main.dashboard_security_warnings(_config("0.0.0.0", basic_auth=True))
    assert len(warnings) == 1
    assert "legacy shared Basic Auth" in warnings[0]


def test_auth_without_tls_beyond_localhost() -> None:
    warnings = main.dashboard_security_warnings(_config("0.0.0.0", auth=True, https=False))
    assert len(warnings) == 1
    assert "unencrypted" in warnings[0]


def test_auth_with_tls_beyond_localhost_is_fine() -> None:
    assert main.dashboard_security_warnings(_config("0.0.0.0", auth=True, https=True)) == []


def test_warnings_are_logged_when_the_dashboard_starts(
    in_memory_db: object, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config("0.0.0.0")
    with patch("src.web.create_app") as create_app, caplog.at_level(logging.WARNING, logger="netsentry.main"):
        main.run_web_dashboard(in_memory_db, config, blocking=True)  # type: ignore[arg-type]
    create_app.return_value.run.assert_called_once()
    assert "NO authentication" in caplog.text
