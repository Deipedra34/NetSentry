"""Tests for which dashboard routes need a login (src/web.py), the
first-run setup page, and the dashboard behaving exactly as before when
auth.enabled is off."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import List

import pytest
from flask import Flask

from src.config import AuthConfig
from src.database import Database, Event
from src.web import SECURITY_HEADERS, create_app
from tests.auth_helpers import add_user, login, make_app

API_ENDPOINTS = [
    "/api/events",
    "/api/stats",
    "/api/stats/timeline",
    "/api/stats/distribution",
    "/api/report",
    "/api/blocked_ips",
]
PUBLIC_ENDPOINTS = {"login", "healthz", "static"}


@pytest.fixture()
def app(in_memory_db: Database, tmp_path: Path) -> Flask:
    add_user(in_memory_db, "alice", "admin")
    add_user(in_memory_db, "victor", "viewer")
    return make_app(in_memory_db, tmp_path)


@pytest.mark.parametrize("endpoint", API_ENDPOINTS)
def test_api_without_session_is_401_json(app: Flask, endpoint: str) -> None:
    response = app.test_client().get(endpoint)
    assert response.status_code == 401
    assert response.get_json() == {"error": "authentication required"}


def test_dashboard_page_without_session_redirects_to_login(app: Flask) -> None:
    response = app.test_client().get("/")
    assert response.status_code == 302
    assert response.headers["Location"] == "/login?next=%2F"


def test_redirect_keeps_the_query_string(app: Flask) -> None:
    response = app.test_client().get("/admin/users?x=1")
    assert response.headers["Location"] == "/login?next=%2Fadmin%2Fusers%3Fx%3D1"


def _non_public_rules(app: Flask) -> List[str]:
    return [
        rule.rule
        for rule in app.url_map.iter_rules()
        if rule.endpoint not in PUBLIC_ENDPOINTS and "GET" in rule.methods and not rule.arguments
    ]


def test_every_route_except_login_and_healthz_needs_a_session(app: Flask) -> None:
    """Guards against a future route forgetting @login_required."""
    client = app.test_client()
    rules = _non_public_rules(app)
    assert "/" in rules and "/api/events" in rules
    for rule in rules:
        assert client.get(rule).status_code in (302, 401), rule


@pytest.mark.parametrize("username", ["alice", "victor"])
def test_both_roles_can_read_everything(app: Flask, in_memory_db: Database, username: str) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="scan"))
    client = app.test_client()
    login(client, username)
    assert client.get("/").status_code == 200
    for endpoint in API_ENDPOINTS:
        response = client.get(endpoint)
        assert response.status_code == 200, endpoint
    assert client.get("/api/events").get_json()[0]["event_type"] == "PORT_SCAN"
    report = client.get("/api/report?range=1h")
    assert report.mimetype == "application/pdf"


def test_healthz_and_login_stay_public(app: Flask) -> None:
    client = app.test_client()
    assert client.get("/healthz").get_json() == {"status": "ok"}
    assert client.get("/login").status_code == 200


def test_security_headers(app: Flask) -> None:
    client = app.test_client()
    for path in ("/login", "/api/stats", "/healthz"):
        response = client.get(path)
        for header, value in SECURITY_HEADERS.items():
            assert response.headers[header] == value


def test_basic_auth_is_ignored_when_auth_enabled(in_memory_db: Database, tmp_path: Path) -> None:
    add_user(in_memory_db, "alice")
    app = create_app(
        in_memory_db, username="admin", password="pw",
        auth_config=AuthConfig(enabled=True, secret_key_path=str(tmp_path / "key")),
    )
    token = base64.b64encode(b"admin:pw").decode()
    response = app.test_client().get("/api/stats", headers={"Authorization": f"Basic {token}"})
    assert response.status_code == 401
    assert "WWW-Authenticate" not in response.headers


# --- first run: auth enabled, no users ------------------------------------


def test_no_users_shows_setup_page_everywhere(in_memory_db: Database, tmp_path: Path) -> None:
    client = make_app(in_memory_db, tmp_path).test_client()
    for path in ["/", "/login", *API_ENDPOINTS]:
        response = client.get(path)
        assert response.status_code == 503, path
        assert b"--create-user" in response.data
    assert client.post("/login", data={"username": "a", "password": "b"}).status_code == 503
    assert client.get("/healthz").status_code == 200


def test_no_users_is_logged(in_memory_db: Database, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="netsentry.web"):
        make_app(in_memory_db, tmp_path)
    assert "no user accounts exist" in caplog.text
    assert "--create-user" in caplog.text


def test_setup_page_goes_away_once_an_admin_exists(in_memory_db: Database, tmp_path: Path) -> None:
    client = make_app(in_memory_db, tmp_path).test_client()
    assert client.get("/login").status_code == 503
    add_user(in_memory_db, "alice")  # e.g. created from the CLI while running
    assert client.get("/login").status_code == 200


# --- auth disabled: exactly as before -------------------------------------


@pytest.mark.parametrize("auth_config", [None, AuthConfig(enabled=False)])
def test_auth_disabled_leaves_endpoints_open(
    in_memory_db: Database, auth_config: AuthConfig | None
) -> None:
    in_memory_db.log_event(Event(event_type="PORT_SCAN", source_ip="10.0.0.1", details="scan"))
    app = create_app(in_memory_db, auth_config=auth_config)
    client = app.test_client()
    assert client.get("/").status_code == 200
    for endpoint in API_ENDPOINTS:
        assert client.get(endpoint).status_code == 200, endpoint
    assert client.get("/api/events").get_json()[0]["source_ip"] == "10.0.0.1"
    assert client.get("/login").status_code == 404
    assert client.post("/logout").status_code == 404
    assert client.get_cookie("netsentry_session") is None


def test_auth_disabled_creates_no_secret_key(in_memory_db: Database, tmp_path: Path) -> None:
    key_path = tmp_path / "secret_key"
    create_app(in_memory_db, auth_config=AuthConfig(enabled=False, secret_key_path=str(key_path)))
    assert not key_path.exists()


def test_auth_disabled_keeps_legacy_basic_auth(in_memory_db: Database) -> None:
    app = create_app(in_memory_db, username="admin", password="pw", auth_config=AuthConfig())
    client = app.test_client()
    response = client.get("/api/stats")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="NetSentry"'
    token = base64.b64encode(b"admin:pw").decode()
    assert client.get("/api/stats", headers={"Authorization": f"Basic {token}"}).status_code == 200


def test_header_shows_user_role_and_sign_out(app: Flask) -> None:
    client = app.test_client()
    login(client, "alice")
    page = client.get("/").get_data(as_text=True)
    assert "alice" in page and "admin" in page
    assert 'action="/logout"' in page and 'name="csrf_token"' in page
    assert 'href="/admin/users"' in page

    viewer = app.test_client()
    login(viewer, "victor")
    page = viewer.get("/").get_data(as_text=True)
    assert "victor" in page and 'action="/logout"' in page
    assert 'href="/admin/users"' not in page


def test_header_has_no_user_menu_when_auth_disabled(in_memory_db: Database) -> None:
    page = create_app(in_memory_db).test_client().get("/").get_data(as_text=True)
    assert 'action="/logout"' not in page
