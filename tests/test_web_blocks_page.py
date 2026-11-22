"""Tests for the Blocked IPs management page (/blocks) in :mod:`src.web`."""

from __future__ import annotations

from pathlib import Path

from src.config import Config
from src.database import AuditEntry, BlockedIP, Database
from src.web import create_app
from tests.auth_helpers import add_user, csrf_from_session, login
from tests.test_web_blocks import auth_app, manager_for, no_auth_app

MARKUP = '<img src=x onerror="alert(1)">'


def _page(client) -> str:  # type: ignore[no-untyped-def]
    response = client.get("/blocks")
    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_admin_sees_the_block_form_and_actions(in_memory_db: Database, tmp_path: Path) -> None:
    add_user(in_memory_db, "alice", "admin")
    client = auth_app(in_memory_db, tmp_path).test_client()
    login(client, "alice")
    page = _page(client)
    assert 'id="block-form"' in page
    assert 'id="bulk-unblock"' in page
    assert "canWrite: true" in page
    # the page's requests carry this session's CSRF token
    assert f'csrfToken: "{csrf_from_session(client)}"' in page


def test_viewer_sees_a_read_only_page(in_memory_db: Database, tmp_path: Path) -> None:
    add_user(in_memory_db, "victor", "viewer")
    client = auth_app(in_memory_db, tmp_path).test_client()
    login(client, "victor")
    page = _page(client)
    assert 'id="block-form"' not in page
    assert 'id="bulk-unblock"' not in page
    assert "canWrite: false" in page
    assert "needs the admin role" in page


def test_logged_out_visitors_are_sent_to_the_login_page(in_memory_db: Database, tmp_path: Path) -> None:
    add_user(in_memory_db, "alice", "admin")
    response = auth_app(in_memory_db, tmp_path).test_client().get("/blocks")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login")


def test_auth_off_network_page_is_read_only_and_says_why(in_memory_db: Database) -> None:
    page = _page(no_auth_app(in_memory_db, bind_host="0.0.0.0").test_client())
    assert 'id="block-form"' not in page
    assert "auth.enabled: true" in page
    assert "canWrite: false" in page


def test_auth_off_localhost_page_uses_the_local_csrf_token(in_memory_db: Database) -> None:
    app = no_auth_app(in_memory_db, bind_host="127.0.0.1")
    page = _page(app.test_client())
    assert 'id="block-form"' in page
    assert f'csrfToken: "{app.config["NETSENTRY_LOCAL_CSRF_TOKEN"]}"' in page


def test_dry_run_and_live_banners(in_memory_db: Database) -> None:
    dry = _page(no_auth_app(in_memory_db, "127.0.0.1", manager_for(in_memory_db, dry_run=True)).test_client())
    assert "mode-banner dry" in dry and "Live mode" not in dry
    live = _page(no_auth_app(in_memory_db, "127.0.0.1", manager_for(in_memory_db, dry_run=False)).test_client())
    assert "Live mode: changes affect the host firewall" in live


def test_duration_choices_follow_the_settings(in_memory_db: Database) -> None:
    manager = manager_for(in_memory_db, allow_permanent=False, max_duration_minutes=1440, default_duration_minutes=60)
    page = _page(no_auth_app(in_memory_db, "127.0.0.1", manager).test_client())
    assert '<option value="0"' not in page  # no "Permanent"
    assert '<option value="10080"' not in page  # longer than the maximum
    assert '<option value="60" selected>' in page


def test_stored_values_are_never_rendered_as_html(in_memory_db: Database) -> None:
    in_memory_db.add_blocked_ip(BlockedIP("45.33.12.7", "SYN_FLOOD", "rule", reason=MARKUP, created_by=MARKUP))
    in_memory_db.add_audit_entry(AuditEntry(MARKUP, "block", MARKUP, "refused", details=MARKUP))
    client = no_auth_app(in_memory_db, "127.0.0.1").test_client()
    page = _page(client)
    # the page itself never contains stored values -- they arrive as JSON
    # and are only ever put on the page with textContent
    assert MARKUP not in page
    assert "innerHTML" not in page
    assert "textContent" in page
    for path in ("/api/blocked_ips", "/api/blocks/audit"):
        response = client.get(path)
        assert response.mimetype == "application/json"
        assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_dashboard_links_to_the_management_page(in_memory_db: Database) -> None:
    page = create_app(in_memory_db).test_client().get("/").get_data(as_text=True)
    assert 'href="/blocks"' in page


def test_page_is_gone_when_block_management_is_disabled(in_memory_db: Database) -> None:
    config = Config()
    config.block_management.enabled = False
    from src.block_management import BlockManager

    client = create_app(in_memory_db, block_manager=BlockManager(config, in_memory_db)).test_client()
    assert client.get("/blocks").status_code == 404
    # ...and the dashboard doesn't link to it
    assert 'href="/blocks"' not in client.get("/").get_data(as_text=True)
