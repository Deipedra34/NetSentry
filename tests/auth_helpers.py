"""Shared helpers for the dashboard authentication tests: a fake clock, an
auth-enabled app factory and a login helper. No real sleeping, no network."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask
from flask.testing import FlaskClient

from src import auth
from src.config import AuthConfig
from src.database import Database
from src.web import create_app

PASSWORD = "a-long-enough-password"


class FakeClock:
    """A settable stand-in for time.time()."""

    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def auth_config(tmp_path: Path, **overrides: Any) -> AuthConfig:
    """An enabled AuthConfig with its secret key inside tmp_path."""
    config = AuthConfig(enabled=True, secret_key_path=str(tmp_path / "secret_key"))
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def make_app(
    db: Database, tmp_path: Path, clock: FakeClock | None = None, tls: bool = False, **overrides: Any
) -> Flask:
    """An auth-enabled dashboard app for tests."""
    app = create_app(
        db,
        auth_config=auth_config(tmp_path, **overrides),
        tls=tls,
        clock=clock or FakeClock(),
    )
    app.config["TESTING"] = True
    return app


def add_user(db: Database, username: str, role: str = "admin", password: str = PASSWORD) -> None:
    auth.create_account(db, username, password, role, min_password_length=12)


def csrf_from_session(client: FlaskClient) -> str:
    """The CSRF token stored in the client's current session."""
    with client.session_transaction() as sess:
        return sess.get(auth.CSRF_SESSION_KEY, "")


def login(client: FlaskClient, username: str, password: str = PASSWORD, next_url: str = "") -> Any:
    """GETs /login for a CSRF token, then POSTs the credentials."""
    client.get("/login")
    data = {"username": username, "password": password, "csrf_token": csrf_from_session(client)}
    if next_url:
        data["next"] = next_url
    return client.post("/login", data=data)
