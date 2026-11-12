"""Tests for the dashboard's /api/report endpoint and its download button."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.config import ReportsConfig
from src.database import Database, Event
from src.web import create_app


@pytest.mark.parametrize("range_key", ["1h", "24h", "7d", "30d"])
def test_report_endpoint_returns_a_pdf_download(in_memory_db: Database, range_key: str) -> None:
    in_memory_db.log_event(
        Event("PORT_SCAN", "45.33.1.1", "scan", timestamp=datetime.now(timezone.utc) - timedelta(minutes=5))
    )
    response = create_app(in_memory_db).test_client().get(f"/api/report?range={range_key}")
    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    disposition = response.headers["Content-Disposition"]
    assert disposition.startswith(f'attachment; filename="report_{range_key}_')
    assert disposition.endswith('.pdf"')


def test_report_endpoint_defaults_to_24h(in_memory_db: Database) -> None:
    response = create_app(in_memory_db).test_client().get("/api/report")
    assert response.status_code == 200
    assert 'filename="report_24h_' in response.headers["Content-Disposition"]


def test_report_endpoint_works_on_an_empty_database(in_memory_db: Database) -> None:
    response = create_app(in_memory_db).test_client().get("/api/report?range=7d")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF-")


def test_report_endpoint_rejects_an_invalid_range(in_memory_db: Database) -> None:
    response = create_app(in_memory_db).test_client().get("/api/report?range=2y")
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid range, expected one of: 1h, 24h, 7d, 30d"}


def test_report_endpoint_uses_the_reports_settings(in_memory_db: Database) -> None:
    settings = ReportsConfig(max_notable_events=3, top_n_sources=2)
    with patch("src.reports.report_bytes", return_value=b"%PDF-fake") as report_bytes:
        response = create_app(in_memory_db, reports_config=settings).test_client().get("/api/report?range=7d")
    assert response.data == b"%PDF-fake"
    database, period, passed_settings = report_bytes.call_args.args
    assert database is in_memory_db
    assert period.kind == "7d"
    assert passed_settings is settings


def test_report_endpoint_failure_is_a_json_error(in_memory_db: Database) -> None:
    with patch("src.reports.report_bytes", side_effect=RuntimeError("boom")):
        response = create_app(in_memory_db).test_client().get("/api/report")
    assert response.status_code == 500
    assert "report generation failed" in response.get_json()["error"]


def test_report_endpoint_is_behind_basic_auth(in_memory_db: Database) -> None:
    client = create_app(in_memory_db, username="admin", password="secret").test_client()
    assert client.get("/api/report").status_code == 401
    token = base64.b64encode(b"admin:secret").decode()
    assert client.get("/api/report", headers={"Authorization": f"Basic {token}"}).status_code == 200


def test_dashboard_has_a_download_report_button(in_memory_db: Database) -> None:
    page = create_app(in_memory_db).test_client().get("/").get_data(as_text=True)
    assert 'id="report-button"' in page
    assert 'href="/api/report?range=24h"' in page
    assert "Download report" in page
