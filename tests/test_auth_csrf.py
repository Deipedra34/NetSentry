"""Tests for the CSRF token helper in :mod:`src.auth` and the check the
dashboard runs on every state-changing request when auth is enabled."""

from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

from src import auth
from src.database import Database
from tests.auth_helpers import add_user, csrf_from_session, make_app


@pytest.fixture()
def app(in_memory_db: Database, tmp_path: Path) -> Flask:
    add_user(in_memory_db, "alice")  # otherwise the dashboard is locked until setup
    app = make_app(in_memory_db, tmp_path)

    @app.route("/_test/token")
    def _token() -> str:
        return auth.csrf_token()

    @app.route("/_test/change", methods=["POST", "DELETE"])
    def _change() -> str:
        return "changed"

    @app.route("/api/_test/change", methods=["POST"])
    def _api_change() -> str:
        return "changed"

    return app


def test_token_is_stable_within_a_session(app: Flask) -> None:
    client = app.test_client()
    first = client.get("/_test/token").get_data(as_text=True)
    assert len(first) >= 32
    assert client.get("/_test/token").get_data(as_text=True) == first
    assert csrf_from_session(client) == first


def test_sessions_get_different_tokens(app: Flask) -> None:
    one = app.test_client().get("/_test/token").get_data(as_text=True)
    two = app.test_client().get("/_test/token").get_data(as_text=True)
    assert one != two


def test_post_with_form_token_is_accepted(app: Flask) -> None:
    client = app.test_client()
    token = client.get("/_test/token").get_data(as_text=True)
    response = client.post("/_test/change", data={"csrf_token": token})
    assert response.status_code == 200


def test_header_token_is_accepted(app: Flask) -> None:
    client = app.test_client()
    token = client.get("/_test/token").get_data(as_text=True)
    response = client.delete("/_test/change", headers={"X-CSRF-Token": token})
    assert response.status_code == 200


def test_missing_token_is_rejected(app: Flask) -> None:
    client = app.test_client()
    client.get("/_test/token")
    response = client.post("/_test/change", data={})
    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_wrong_token_is_rejected(app: Flask) -> None:
    client = app.test_client()
    client.get("/_test/token")
    response = client.post("/_test/change", data={"csrf_token": "forged"})
    assert response.status_code == 400


def test_token_without_a_session_is_rejected(app: Flask) -> None:
    """A forged cross-site POST from a browser with no session at all."""
    token = app.test_client().get("/_test/token").get_data(as_text=True)
    response = app.test_client().post("/_test/change", data={"csrf_token": token})
    assert response.status_code == 400


def test_api_rejection_uses_api_error_style(app: Flask) -> None:
    client = app.test_client()
    client.get("/_test/token")
    response = client.post("/api/_test/change")
    assert response.status_code == 400
    assert "CSRF" in response.get_json()["error"]


def test_get_requests_need_no_token(app: Flask) -> None:
    assert app.test_client().get("/_test/token").status_code == 200
