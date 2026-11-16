"""Tests for the admin-only user management page (/admin/users) and role
enforcement in :mod:`src.web`."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import pytest
from flask.testing import FlaskClient

from src import auth
from src.database import Database
from tests.auth_helpers import PASSWORD, add_user, csrf_from_session, login, make_app

NEW_PASSWORD = "a-brand-new-password"


@pytest.fixture()
def db(in_memory_db: Database) -> Database:
    add_user(in_memory_db, "alice", "admin")
    add_user(in_memory_db, "victor", "viewer")
    return in_memory_db


@pytest.fixture()
def admin(db: Database, tmp_path: Path) -> FlaskClient:
    client = make_app(db, tmp_path).test_client()
    login(client, "alice")
    return client


@pytest.fixture()
def viewer(db: Database, tmp_path: Path) -> FlaskClient:
    client = make_app(db, tmp_path).test_client()
    login(client, "victor")
    return client


def _post(client: FlaskClient, path: str, data: Dict[str, str] | None = None, follow: bool = True):  # type: ignore[no-untyped-def]
    payload = {"csrf_token": csrf_from_session(client), **(data or {})}
    return client.post(path, data=payload, follow_redirects=follow)


def _id(db: Database, username: str) -> int:
    return db.get_user_by_username(username).id  # type: ignore[union-attr,return-value]


def test_admin_sees_user_list(admin: FlaskClient) -> None:
    response = admin.get("/admin/users")
    assert response.status_code == 200
    assert b"alice" in response.data and b"victor" in response.data
    assert b"scrypt" not in response.data  # no hashes on the page


def test_viewer_gets_403_on_every_admin_route(viewer: FlaskClient, db: Database) -> None:
    alice = _id(db, "alice")
    assert viewer.get("/admin/users").status_code == 403
    for path in [
        "/admin/users",
        f"/admin/users/{alice}/password",
        f"/admin/users/{alice}/role",
        f"/admin/users/{alice}/disable",
        f"/admin/users/{alice}/enable",
        f"/admin/users/{alice}/delete",
    ]:
        assert _post(viewer, path, {"role": "viewer", "password": NEW_PASSWORD,
                                    "confirm": NEW_PASSWORD, "username": "mallory"},
                     follow=False).status_code == 403, path
    alice_now = db.get_user(alice)
    assert (alice_now.role, alice_now.disabled) == ("admin", False)
    assert db.get_user_by_username("mallory") is None


def test_logged_out_admin_routes_redirect_or_401(db: Database, tmp_path: Path) -> None:
    client = make_app(db, tmp_path).test_client()
    response = client.get("/admin/users")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login?next=")


def test_admin_required_on_api_paths_returns_json_403(db: Database, tmp_path: Path) -> None:
    app = make_app(db, tmp_path)

    @app.route("/api/_test/admin-only", methods=["POST"])
    @auth.admin_required
    def _admin_only() -> str:
        return "ok"

    client = app.test_client()
    login(client, "victor")
    response = _post(client, "/api/_test/admin-only", follow=False)
    assert response.status_code == 403
    assert response.get_json() == {"error": "admin role required"}
    client = app.test_client()
    login(client, "alice")
    assert _post(client, "/api/_test/admin-only", follow=False).status_code == 200


def test_create_user(admin: FlaskClient, db: Database) -> None:
    response = _post(admin, "/admin/users", {
        "username": "carol", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "role": "viewer",
    })
    assert response.status_code == 200
    assert b"Created viewer" in response.data
    carol = db.get_user_by_username("carol")
    assert carol.role == "viewer"
    assert auth.verify_password(carol.password_hash, NEW_PASSWORD)


@pytest.mark.parametrize(
    ("form", "message"),
    [
        ({"username": "x", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD}, b"3 to 32"),
        ({"username": "carol", "password": "short", "confirm": "short"}, b"at least 12"),
        ({"username": "carol", "password": NEW_PASSWORD, "confirm": "something-else-x"}, b"match"),
        ({"username": "VICTOR", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD}, b"already exists"),
        ({"username": "carol", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "role": "root"},
         b"Unknown role"),
    ],
)
def test_create_user_validation(admin: FlaskClient, db: Database, form: Dict[str, str], message: bytes) -> None:
    response = _post(admin, "/admin/users", form)
    assert message in response.data
    assert db.count_users() == 2


def test_reset_password(admin: FlaskClient, db: Database, tmp_path: Path) -> None:
    response = _post(admin, f"/admin/users/{_id(db, 'victor')}/password",
                     {"password": NEW_PASSWORD, "confirm": NEW_PASSWORD})
    assert b"updated" in response.data
    client = make_app(db, tmp_path).test_client()
    assert login(client, "victor", PASSWORD).status_code == 401
    assert login(client, "victor", NEW_PASSWORD).status_code == 302


def test_change_role(admin: FlaskClient, db: Database) -> None:
    _post(admin, f"/admin/users/{_id(db, 'victor')}/role", {"role": "admin"})
    assert db.get_user_by_username("victor").role == "admin"


def test_disable_and_enable(admin: FlaskClient, db: Database) -> None:
    victor = _id(db, "victor")
    _post(admin, f"/admin/users/{victor}/disable")
    assert db.get_user(victor).disabled is True
    _post(admin, f"/admin/users/{victor}/enable")
    assert db.get_user(victor).disabled is False


def test_delete_user(admin: FlaskClient, db: Database) -> None:
    response = _post(admin, f"/admin/users/{_id(db, 'victor')}/delete")
    assert b"Deleted" in response.data
    assert db.get_user_by_username("victor") is None


def test_last_admin_rules_apply(admin: FlaskClient, db: Database) -> None:
    alice = _id(db, "alice")
    response = _post(admin, f"/admin/users/{alice}/role", {"role": "viewer"})
    assert b"last enabled admin" in response.data
    assert db.get_user(alice).role == "admin"


def test_admin_cannot_delete_or_disable_self(admin: FlaskClient, db: Database) -> None:
    add_user(db, "root2", "admin")  # so the last-admin rule isn't what stops it
    alice = _id(db, "alice")
    assert b"your own account" in _post(admin, f"/admin/users/{alice}/delete").data
    assert b"your own account" in _post(admin, f"/admin/users/{alice}/disable").data
    assert db.get_user(alice) is not None and db.get_user(alice).disabled is False


def test_missing_user(admin: FlaskClient) -> None:
    assert b"no longer exists" in _post(admin, "/admin/users/999/delete").data


@pytest.mark.parametrize("path_suffix", ["", "/1/password", "/1/role", "/1/disable", "/1/enable", "/1/delete"])
def test_admin_actions_need_csrf(admin: FlaskClient, db: Database, path_suffix: str) -> None:
    response = admin.post(f"/admin/users{path_suffix}", data={
        "username": "carol", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "role": "viewer",
    })
    assert response.status_code == 400
    response = admin.post(f"/admin/users{path_suffix}", data={"csrf_token": "forged", "role": "viewer"})
    assert response.status_code == 400
    assert db.count_users() == 2
    assert db.get_user_by_username("alice").role == "admin"


def test_demoted_admin_loses_admin_access_immediately(db: Database, tmp_path: Path) -> None:
    add_user(db, "root2", "admin")
    client = make_app(db, tmp_path).test_client()
    login(client, "root2")
    assert client.get("/admin/users").status_code == 200
    auth.set_account_role(db, "root2", "viewer")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/api/stats").status_code == 200
