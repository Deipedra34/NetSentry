"""Tests for the dashboard's SIEM status: /api/siem/status and its panel."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

import main
from src.config import Config
from src.database import Database
from src.siem.dispatcher import SiemForwarder
from src.web import create_app
from tests.auth_helpers import FakeClock, add_user, auth_config, login

STATUS: Dict[str, Any] = {
    "enabled": True,
    "running": True,
    "destinations": [
        {
            "name": "splunk",
            "format": "cef",
            "transport": "tcp",
            "target": "10.0.0.9:514",
            "min_severity": "low",
            "state": "retrying",
            "sent": 12,
            "dropped": 3,
            "failed": 0,
            "queued": 7,
            "last_error": "connection refused",
            "last_error_at": "2026-11-26T09:00:00+00:00",
        }
    ],
}


def _app(db: Database, **kwargs: Any) -> Flask:
    app = create_app(db, **kwargs)
    app.config["TESTING"] = True
    return app


def test_status_without_auth(in_memory_db: Database) -> None:
    client = _app(in_memory_db, siem_status=lambda: STATUS).test_client()
    response = client.get("/api/siem/status")
    assert response.status_code == 200
    assert response.get_json() == STATUS


def test_not_running_when_no_forwarder_is_attached(in_memory_db: Database) -> None:
    response = _app(in_memory_db).test_client().get("/api/siem/status")
    assert response.get_json() == {"enabled": False, "running": False, "destinations": []}


def test_a_broken_status_source_returns_500(in_memory_db: Database) -> None:
    def broken() -> Dict[str, Any]:
        raise RuntimeError("boom")

    response = _app(in_memory_db, siem_status=broken).test_client().get("/api/siem/status")
    assert response.status_code == 500
    assert "boom" not in response.get_data(as_text=True)


def test_needs_a_login_when_auth_is_enabled(in_memory_db: Database, tmp_path: Path) -> None:
    add_user(in_memory_db, "viewer", role="viewer")
    app = _app(in_memory_db, auth_config=auth_config(tmp_path), clock=FakeClock(), siem_status=lambda: STATUS)
    client = app.test_client()
    assert client.get("/api/siem/status").status_code == 401
    login(client, "viewer")
    response = client.get("/api/siem/status")
    assert response.status_code == 200  # read-only: any role may look
    assert response.get_json()["destinations"][0]["name"] == "splunk"


def test_is_read_only(in_memory_db: Database) -> None:
    client = _app(in_memory_db, siem_status=lambda: STATUS).test_client()
    assert client.post("/api/siem/status").status_code == 405
    assert client.delete("/api/siem/status").status_code == 405


def test_legacy_basic_auth_applies(in_memory_db: Database) -> None:
    client = _app(in_memory_db, username="admin", password="pw", siem_status=lambda: STATUS).test_client()
    assert client.get("/api/siem/status").status_code == 401
    token = base64.b64encode(b"admin:pw").decode("ascii")
    assert client.get("/api/siem/status", headers={"Authorization": f"Basic {token}"}).status_code == 200


def test_real_forwarder_status_reveals_no_secrets(in_memory_db: Database, tmp_path: Path) -> None:
    config = Config()
    config.siem.enabled = True
    config.siem.destinations = [
        {"name": "tcp", "format": "rfc5424", "transport": "tcp", "host": "svc:hunter2@collector.test"},
        {"name": "mtls", "format": "json", "transport": "tls", "host": "elastic.test",
         "ca_file": str(tmp_path / "private" / "ca.pem"), "client_cert": str(tmp_path / "private" / "client.pem")},
        {"name": "file", "format": "json", "transport": "file", "path": str(tmp_path / "private" / "events.ndjson")},
    ]
    forwarder = SiemForwarder(config, start=False)
    client = _app(in_memory_db, siem_status=forwarder.status).test_client()
    body = client.get("/api/siem/status").get_data(as_text=True)
    assert "hunter2" not in body
    assert "private" not in body and "ca.pem" not in body and "client.pem" not in body
    destinations = {d["name"]: d for d in json.loads(body)["destinations"]}
    assert destinations["tcp"]["target"] == "collector.test:514"
    assert destinations["file"]["target"] == "events.ndjson"
    assert destinations["mtls"]["state"] == "disabled"


def test_dashboard_has_the_siem_panel(in_memory_db: Database) -> None:
    html = _app(in_memory_db).test_client().get("/").get_data(as_text=True)
    assert "SIEM Forwarding" in html
    assert 'fetch("/api/siem/status")' in html


def test_web_dashboard_is_given_the_forwarders_status() -> None:
    config = Config()
    forwarder = MagicMock()
    with patch("src.web.create_app") as create_app_mock, patch("main.threading.Thread"):
        main.run_web_dashboard(MagicMock(), config, blocking=False, siem=forwarder)
    assert create_app_mock.call_args.kwargs["siem_status"] is forwarder.status


@pytest.mark.parametrize("enabled", [False, True])
def test_web_only_reports_forwarding_as_not_running(enabled: bool) -> None:
    config = Config()
    config.siem.enabled = enabled
    with patch("src.web.create_app") as create_app_mock, patch("main.threading.Thread"):
        main.run_web_dashboard(MagicMock(), config, blocking=False)
    status = create_app_mock.call_args.kwargs["siem_status"]()
    assert status == {"enabled": enabled, "running": False, "destinations": []}
