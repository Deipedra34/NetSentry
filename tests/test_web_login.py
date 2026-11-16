"""Tests for the dashboard's session login (src/web.py + src/auth.py):
login/logout, generic failures, lockout, session fixation, timeouts,
disabled users, cookie flags and the ?next= redirect."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from flask.testing import FlaskClient

from src import auth
from src.database import Database
from src.web import GENERIC_LOGIN_ERROR, LOCKED_OUT_ERROR
from tests.auth_helpers import FakeClock, add_user, csrf_from_session, login, make_app


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def client(in_memory_db: Database, tmp_path: Path, clock: FakeClock) -> FlaskClient:
    add_user(in_memory_db, "alice", "admin")
    add_user(in_memory_db, "victor", "viewer")
    return make_app(
        in_memory_db, tmp_path, clock=clock,
        idle_timeout_minutes=60, session_lifetime_minutes=480,
        max_failed_logins=3, lockout_minutes=15,
    ).test_client()


def _session_cookie(client: FlaskClient) -> str:
    cookie = client.get_cookie("netsentry_session")
    return cookie.value if cookie else ""


def test_login_page_renders(client: FlaskClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Sign in" in response.data
    assert b'name="csrf_token"' in response.data


def test_successful_login_redirects_and_grants_access(client: FlaskClient, in_memory_db: Database) -> None:
    response = login(client, "alice")
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert client.get("/").status_code == 200
    assert client.get("/api/stats").status_code == 200
    assert in_memory_db.get_user_by_username("alice").last_login_at is not None


def test_username_is_case_insensitive_at_login(client: FlaskClient) -> None:
    assert login(client, "ALICE").status_code == 302


def test_session_stores_only_user_id_and_times(client: FlaskClient, in_memory_db: Database) -> None:
    login(client, "alice")
    with client.session_transaction() as sess:
        assert set(sess) - {"_permanent"} == {  # _permanent is Flask's cookie-expiry flag
            auth.SESSION_USER_ID, auth.SESSION_STARTED, auth.SESSION_LAST_SEEN, auth.CSRF_SESSION_KEY,
        }
        assert sess[auth.SESSION_USER_ID] == in_memory_db.get_user_by_username("alice").id


def test_wrong_password_and_unknown_user_get_the_same_answer(client: FlaskClient) -> None:
    wrong_password = login(client, "alice", "not-the-right-password")
    unknown_user = login(client, "mallory", "not-the-right-password")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert GENERIC_LOGIN_ERROR.encode() in wrong_password.data
    assert GENERIC_LOGIN_ERROR.encode() in unknown_user.data
    assert client.get("/api/stats").status_code == 401


def test_unknown_user_is_still_checked_against_a_hash(client: FlaskClient) -> None:
    """Comparable work (one hash check) whether or not the user exists, so
    timing doesn't reveal valid usernames."""
    with patch.object(auth, "check_password_hash", wraps=auth.check_password_hash) as check:
        login(client, "mallory", "not-the-right-password")
        assert check.call_count == 1
        login(client, "alice", "not-the-right-password")
        assert check.call_count == 2


def test_disabled_user_cannot_log_in(client: FlaskClient, in_memory_db: Database) -> None:
    in_memory_db.set_user_disabled(in_memory_db.get_user_by_username("victor").id, True)
    response = login(client, "victor")
    assert response.status_code == 401
    assert GENERIC_LOGIN_ERROR.encode() in response.data


def test_lockout_after_max_failures_and_expiry(client: FlaskClient, clock: FakeClock) -> None:
    for _ in range(3):
        assert login(client, "alice", "not-the-right-password").status_code == 401
    # locked now -- even the right password is refused
    locked = login(client, "alice")
    assert locked.status_code == 429
    assert LOCKED_OUT_ERROR.encode() in locked.data
    clock.advance(15 * 60)
    assert login(client, "alice").status_code == 302


def test_lockout_by_client_ip_across_usernames(client: FlaskClient) -> None:
    for name in ("mallory", "trudy", "eve"):
        login(client, name, "not-the-right-password")
    assert login(client, "alice").status_code == 429


def test_login_requires_csrf_token(client: FlaskClient) -> None:
    client.get("/login")
    response = client.post("/login", data={"username": "alice", "password": "a-long-enough-password"})
    assert response.status_code == 400
    response = client.post(
        "/login",
        data={"username": "alice", "password": "a-long-enough-password", "csrf_token": "forged"},
    )
    assert response.status_code == 400
    assert client.get("/api/stats").status_code == 401


def test_session_is_regenerated_on_login(client: FlaskClient, tmp_path: Path) -> None:
    """Session fixation: the pre-login cookie (and CSRF token) is replaced,
    and a copy of the pre-login cookie grants nothing afterwards."""
    client.get("/login")
    before_cookie = _session_cookie(client)
    before_token = csrf_from_session(client)
    data = {"username": "alice", "password": "a-long-enough-password", "csrf_token": before_token}
    assert client.post("/login", data=data).status_code == 302

    assert _session_cookie(client) != before_cookie
    assert csrf_from_session(client) != before_token

    attacker = client.application.test_client()
    attacker.set_cookie("netsentry_session", before_cookie)
    assert attacker.get("/api/stats").status_code == 401


def test_logout_ends_the_session(client: FlaskClient) -> None:
    login(client, "alice")
    response = client.post("/logout", data={"csrf_token": csrf_from_session(client)})
    assert response.status_code == 302
    assert response.headers["Location"] == "/login"
    assert client.get("/api/stats").status_code == 401


def test_logout_requires_post_and_csrf(client: FlaskClient) -> None:
    login(client, "alice")
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    assert client.post("/logout", data={"csrf_token": "forged"}).status_code == 400
    assert client.get("/api/stats").status_code == 200


def test_idle_timeout(client: FlaskClient, clock: FakeClock) -> None:
    login(client, "alice")
    clock.advance(59 * 60)
    assert client.get("/api/stats").status_code == 200  # activity resets the idle timer
    clock.advance(59 * 60)
    assert client.get("/api/stats").status_code == 200
    clock.advance(60 * 60)
    assert client.get("/api/stats").status_code == 401


def test_absolute_lifetime_even_when_active(client: FlaskClient, clock: FakeClock) -> None:
    login(client, "alice")
    for _ in range(8):  # 8 x 59.9 minutes, active all along
        clock.advance(59.9 * 60)
        assert client.get("/api/stats").status_code == 200
    clock.advance(10 * 60)  # past the 480-minute lifetime
    assert client.get("/api/stats").status_code == 401


def test_disabled_user_loses_access_immediately(client: FlaskClient, in_memory_db: Database) -> None:
    login(client, "victor")
    assert client.get("/api/stats").status_code == 200
    in_memory_db.set_user_disabled(in_memory_db.get_user_by_username("victor").id, True)
    assert client.get("/api/stats").status_code == 401
    # and re-enabling doesn't revive the ended session
    in_memory_db.set_user_disabled(in_memory_db.get_user_by_username("victor").id, False)
    assert client.get("/api/stats").status_code == 401


def test_deleted_user_loses_access_immediately(client: FlaskClient, in_memory_db: Database) -> None:
    login(client, "victor")
    in_memory_db.delete_user(in_memory_db.get_user_by_username("victor").id)
    assert client.get("/").status_code == 302


@pytest.mark.parametrize(
    ("next_url", "expected"),
    [
        ("/api/report?range=7d", "/api/report?range=7d"),
        ("/", "/"),
        ("https://evil.example/", "/"),
        ("//evil.example/", "/"),
        ("/\\evil.example/", "/"),
        ("evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("/\r\nSet-Cookie: x=y", "/"),
    ],
)
def test_next_only_allows_local_paths(client: FlaskClient, next_url: str, expected: str) -> None:
    response = login(client, "alice", next_url=next_url)
    assert response.status_code == 302
    assert response.headers["Location"] == expected


def test_logged_in_user_visiting_login_is_redirected(client: FlaskClient) -> None:
    login(client, "alice")
    response = client.get("/login?next=/api/stats")
    assert response.status_code == 302
    assert response.headers["Location"] == "/api/stats"


def test_cookie_flags_without_tls(client: FlaskClient) -> None:
    response = login(client, "alice")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Secure" not in cookie


@pytest.mark.parametrize(
    ("tls", "setting", "secure"),
    [(True, "auto", True), (False, "auto", False), (False, "true", True),
     (True, "false", False), (False, True, True)],
)
def test_cookie_secure_setting(
    in_memory_db: Database, tmp_path: Path, tls: bool, setting: object, secure: bool
) -> None:
    add_user(in_memory_db, "alice")
    app = make_app(in_memory_db, tmp_path, tls=tls, cookie_secure=setting)
    client = app.test_client()
    if secure:  # the test client only sends Secure cookies back over https
        client.environ_base["wsgi.url_scheme"] = "https"
    cookie = login(client, "alice").headers["Set-Cookie"]
    assert ("Secure" in cookie) is secure
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_sessions_survive_an_app_restart(in_memory_db: Database, tmp_path: Path) -> None:
    """Same secret key file -> a new app instance accepts the old cookie."""
    add_user(in_memory_db, "alice")
    clock = FakeClock()
    first = make_app(in_memory_db, tmp_path, clock=clock).test_client()
    login(first, "alice")
    second = make_app(in_memory_db, tmp_path, clock=clock).test_client()
    second.set_cookie("netsentry_session", _session_cookie(first))
    assert second.get("/api/stats").status_code == 200


def test_passwords_never_logged(client: FlaskClient, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("DEBUG"):
        login(client, "alice", "wrong-secret-password-1")
        login(client, "alice")
    assert "wrong-secret-password-1" not in caplog.text
    assert "a-long-enough-password" not in caplog.text
