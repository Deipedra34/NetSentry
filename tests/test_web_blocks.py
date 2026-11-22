"""Tests for the Blocked IPs management endpoints in :mod:`src.web`: role
enforcement, CSRF, the auth-off localhost rule, and the block, unblock and
duration actions. No real firewall commands: everything runs in dry run
unless a test mocks subprocess."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

from src.block_management import BlockManager, ProtectedAddresses
from src.config import Config
from src.database import BlockedIP, Database
from src.web import create_app
from tests.auth_helpers import FakeClock, add_user, auth_config, csrf_from_session, login


def manager_for(db: Database, dry_run: bool = True, **settings: Any) -> BlockManager:
    config = Config()
    config.auto_block.dry_run = dry_run
    for key, value in settings.items():
        setattr(config.block_management, key, value)
    return BlockManager(config, db, protected_addresses=lambda: ProtectedAddresses(), clock=FakeClock())


def auth_app(db: Database, tmp_path: Path, manager: Optional[BlockManager] = None, bind_host: str = "0.0.0.0") -> Flask:
    app = create_app(
        db,
        auth_config=auth_config(tmp_path),
        clock=FakeClock(),
        block_manager=manager or manager_for(db),
        bind_host=bind_host,
    )
    app.config["TESTING"] = True
    return app


def no_auth_app(db: Database, bind_host: str, manager: Optional[BlockManager] = None) -> Flask:
    app = create_app(db, block_manager=manager or manager_for(db), bind_host=bind_host)
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def db(in_memory_db: Database) -> Database:
    add_user(in_memory_db, "alice", "admin")
    add_user(in_memory_db, "victor", "viewer")
    return in_memory_db


def signed_in(app: Flask, username: str) -> FlaskClient:
    client = app.test_client()
    login(client, username)
    return client


def post(client: FlaskClient, path: str, body: Dict[str, Any], token: Optional[str] = "session", **kwargs: Any) -> Any:
    headers = kwargs.pop("headers", {})
    if token == "session":
        token = csrf_from_session(client)
    if token:
        headers["X-CSRF-Token"] = token
    return client.post(path, json=body, headers=headers, **kwargs)


# --- roles and CSRF (auth enabled) ---------------------------------------------------------


def test_both_roles_can_read(db: Database, tmp_path: Path) -> None:
    app = auth_app(db, tmp_path)
    for username in ("alice", "victor"):
        client = signed_in(app, username)
        for path in ("/api/blocked_ips", "/api/blocks/history", "/api/blocks/audit"):
            assert client.get(path).status_code == 200, (username, path)


def test_logged_out_requests_get_401(db: Database, tmp_path: Path) -> None:
    client = auth_app(db, tmp_path).test_client()
    assert client.get("/api/blocks/audit").status_code == 401
    client.get("/login")  # a session (and CSRF token) without signing in
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}).status_code == 401
    assert db.get_blocked_ips() == []


def test_viewer_gets_403_and_the_attempt_is_audited(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "victor")
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}).status_code == 403
    assert post(client, "/api/blocks/1/unblock", {}).status_code == 403
    assert post(client, "/api/blocks/1/duration", {"duration_minutes": 5}).status_code == 403
    assert db.get_blocked_ips() == []
    entries = db.get_audit_entries()
    assert {(e.actor, e.result) for e in entries} == {("victor", "refused")}
    assert all("admin_required" in e.details for e in entries)


def test_admin_can_block_with_a_csrf_token(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    response = post(client, "/api/blocks", {"target": "45.33.12.7", "duration_minutes": 15, "reason": "scanner"})
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["applied"] is False  # dry run
    assert payload["block"]["source_ip"] == "45.33.12.7"
    (block,) = db.get_blocked_ips()
    assert (block.created_by, block.reason, block.source) == ("alice", "scanner", "manual")


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_writes_without_a_valid_csrf_token_are_rejected(db: Database, tmp_path: Path, token: Optional[str]) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    response = post(client, "/api/blocks", {"target": "45.33.12.7"}, token=token)
    assert response.status_code == 400
    assert "CSRF" in response.get_json()["error"]
    assert db.get_blocked_ips() == []


def test_requesters_own_address_is_refused(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    response = post(
        client, "/api/blocks", {"target": "45.33.100.0/24"}, environ_base={"REMOTE_ADDR": "45.33.100.5"}
    )
    assert response.status_code == 400
    assert response.get_json()["rule"] == "requester"


def test_refusals_name_the_rule(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    for body, rule in [
        ({"target": "10.0.0.1"}, "private"),
        ({"target": "not an ip"}, "invalid"),
        ({"target": "45.0.0.0/8"}, "range_too_large"),
        ({"target": "45.33.12.7", "duration_minutes": "60"}, "invalid_duration"),
        ({"target": "45.33.12.7", "reason": "x" * 201}, "reason_too_long"),
    ]:
        response = post(client, "/api/blocks", body)
        assert (response.status_code, response.get_json()["rule"]) == (400, rule), body


# --- auth disabled: localhost only ------------------------------------------------------------


def test_auth_off_on_the_network_is_read_only(in_memory_db: Database) -> None:
    app = no_auth_app(in_memory_db, bind_host="0.0.0.0")
    client = app.test_client()
    assert client.get("/api/blocks/audit").status_code == 200
    token = app.config["NETSENTRY_LOCAL_CSRF_TOKEN"]
    response = post(client, "/api/blocks", {"target": "45.33.12.7"}, token=token)
    assert response.status_code == 403
    assert "auth.enabled" in response.get_json()["error"]
    assert in_memory_db.get_blocked_ips() == []
    (entry,) = in_memory_db.get_audit_entries()
    assert (entry.actor, entry.result) == ("anonymous", "refused")
    assert "network_write_without_auth" in entry.details


def test_auth_off_on_localhost_allows_writes_as_local(in_memory_db: Database) -> None:
    app = no_auth_app(in_memory_db, bind_host="127.0.0.1")
    client = app.test_client()
    token = app.config["NETSENTRY_LOCAL_CSRF_TOKEN"]
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}, token=token).status_code == 201
    assert in_memory_db.get_blocked_ips()[0].created_by == "local"


def test_auth_off_on_localhost_still_needs_the_local_csrf_token(in_memory_db: Database) -> None:
    client = no_auth_app(in_memory_db, bind_host="127.0.0.1").test_client()
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}, token=None).status_code == 400
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}, token="guess").status_code == 400
    assert in_memory_db.get_blocked_ips() == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"headers": {"Host": "evil.example:5000"}},  # DNS rebinding
        {"environ_base": {"REMOTE_ADDR": "192.168.1.50"}},  # not actually local
    ],
)
def test_auth_off_localhost_rule_checks_the_actual_request(in_memory_db: Database, kwargs: Dict[str, Any]) -> None:
    app = no_auth_app(in_memory_db, bind_host="127.0.0.1")
    token = app.config["NETSENTRY_LOCAL_CSRF_TOKEN"]
    response = post(app.test_client(), "/api/blocks", {"target": "45.33.12.7"}, token=token, **kwargs)
    assert response.status_code == 403
    assert in_memory_db.get_blocked_ips() == []


# --- actions ------------------------------------------------------------------------------------


def test_unblock_and_bulk_unblock(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    ids = [post(client, "/api/blocks", {"target": f"45.33.12.{n}"}).get_json()["block"]["id"] for n in (1, 2, 3)]
    assert post(client, f"/api/blocks/{ids[0]}/unblock", {}).status_code == 200
    assert post(client, f"/api/blocks/{ids[0]}/unblock", {}).status_code == 404
    response = post(client, "/api/blocks/unblock", {"ids": [ids[1], ids[2], 999]})
    assert [(r["id"], r["ok"]) for r in response.get_json()["results"]] == [(ids[1], True), (ids[2], True), (999, False)]
    assert db.get_blocked_ips() == []
    assert db.count_block_history() == 3


@pytest.mark.parametrize("ids", [None, [], "1,2", [1, "2"], [True], list(range(501))])
def test_bulk_unblock_validates_the_id_list(db: Database, tmp_path: Path, ids: Any) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    assert post(client, "/api/blocks/unblock", {"ids": ids}).status_code == 400


def test_failed_firewall_unblock_keeps_the_record_and_reports_the_error(db: Database, tmp_path: Path) -> None:
    db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "NetSentry_Block_45.33.12.7"))
    block_id = db.get_blocked_ips()[0].id
    client = signed_in(auth_app(db, tmp_path, manager_for(db, dry_run=False)), "alice")
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", side_effect=PermissionError("you must be root")):
        response = post(client, f"/api/blocks/{block_id}/unblock", {})
    assert response.status_code == 502
    assert "you must be root" in response.get_json()["error"]
    assert len(db.get_blocked_ips()) == 1


def test_live_block_through_the_endpoint_calls_the_firewall_with_a_list(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path, manager_for(db, dry_run=False)), "alice")
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run", return_value=MagicMock(returncode=0)) as run:
        response = post(client, "/api/blocks", {"target": "45.33.12.7", "reason": "$(reboot)"})
    assert response.status_code == 201
    assert run.call_args.args[0] == ["iptables", "-A", "INPUT", "-s", "45.33.12.7", "-j", "DROP"]


def test_change_duration_endpoint(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    block = post(client, "/api/blocks", {"target": "45.33.12.7", "duration_minutes": 15}).get_json()["block"]
    response = post(client, f"/api/blocks/{block['id']}/duration", {"duration_minutes": 0})
    assert response.status_code == 200
    assert response.get_json()["block"]["expires_at"] is None
    assert post(client, f"/api/blocks/{block['id']}/duration", {"duration_minutes": 999999}).status_code == 400
    assert post(client, "/api/blocks/999/duration", {"duration_minutes": 5}).status_code == 404


def test_history_and_audit_pagination_and_filters(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    for n in range(1, 6):
        block_id = post(client, "/api/blocks", {"target": f"45.33.12.{n}"}).get_json()["block"]["id"]
        post(client, f"/api/blocks/{block_id}/unblock", {})
    history = client.get("/api/blocks/history?per_page=2&page=3").get_json()
    assert (history["total"], history["pages"], history["page"], len(history["entries"])) == (5, 3, 3, 1)
    assert history["entries"][0]["source_ip"] == "45.33.12.1"
    audit = client.get("/api/blocks/audit?action=unblock&user=alice&per_page=100").get_json()
    assert audit["total"] == 5
    assert {e["action"] for e in audit["entries"]} == {"unblock"}
    assert audit["users"] == ["alice"]
    assert client.get("/api/blocks/audit?per_page=100000").get_json()["per_page"] == 100


def test_disabled_block_management_has_no_endpoints(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path, manager_for(db, enabled=False)), "alice")
    assert client.get("/api/blocks/audit").status_code == 404
    assert post(client, "/api/blocks", {"target": "45.33.12.7"}).status_code in (404, 405)
    assert client.get("/api/blocked_ips").status_code == 200  # the plain list always stays


def test_expires_at_is_reported_for_the_page(db: Database, tmp_path: Path) -> None:
    client = signed_in(auth_app(db, tmp_path), "alice")
    block = post(client, "/api/blocks", {"target": "45.33.12.7", "duration_minutes": 60}).get_json()["block"]
    (listed,) = client.get("/api/blocked_ips").get_json()
    assert listed["expires_at"] == block["expires_at"]
    stored = db.get_blocked_ips()[0]
    assert stored.expires_at - stored.blocked_at == timedelta(minutes=60)  # type: ignore[operator]
