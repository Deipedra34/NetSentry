"""Unit tests for :mod:`src.notifications`."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.config import Config
from src.database import Event
from src.notifications import NotificationDispatcher


def _make_event(event_type: str = "SYN_FLOOD", source_ip: str = "10.0.0.1") -> Event:
    return Event(
        event_type=event_type,
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _all_channels_config() -> Config:
    config = Config()
    config.notifications.discord.enabled = True
    config.notifications.discord.webhook_url = "https://discord.com/api/webhooks/x/y"
    config.notifications.telegram.enabled = True
    config.notifications.telegram.bot_token = "token"
    config.notifications.telegram.chat_id = "12345"
    config.notifications.email.enabled = True
    config.notifications.email.smtp_host = "smtp.example.com"
    config.notifications.email.from_addr = "alerts@example.com"
    config.notifications.email.to_addr = "you@example.com"
    return config


def test_non_critical_event_type_does_not_dispatch() -> None:
    config = _all_channels_config()
    dispatcher = NotificationDispatcher(config)
    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen, \
         patch("src.notifications.smtplib.SMTP") as mock_smtp:
        dispatcher.notify(_make_event(event_type="NOT_A_REAL_EVENT"))
    mock_urlopen.assert_not_called()
    mock_smtp.assert_not_called()


def test_critical_event_dispatches_to_all_enabled_channels() -> None:
    config = _all_channels_config()
    dispatcher = NotificationDispatcher(config)
    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen, \
         patch("src.notifications.smtplib.SMTP") as mock_smtp:
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        dispatcher.notify(_make_event())

    # Discord + Telegram both go through urlopen, so two calls.
    assert mock_urlopen.call_count == 2
    mock_smtp.assert_called_once()


def test_disabled_channels_are_skipped() -> None:
    config = Config()  # everything disabled by default
    dispatcher = NotificationDispatcher(config)
    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen, \
         patch("src.notifications.smtplib.SMTP") as mock_smtp:
        dispatcher.notify(_make_event())
    mock_urlopen.assert_not_called()
    mock_smtp.assert_not_called()


def test_cooldown_suppresses_repeat_notification_within_window() -> None:
    config = _all_channels_config()
    config.notifications.email.enabled = False
    config.notifications.telegram.enabled = False
    config.notifications.cooldown = 300.0
    dispatcher = NotificationDispatcher(config)

    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen, \
         patch("src.notifications.time.time", side_effect=[1000.0, 1000.0, 1010.0, 1010.0]):
        dispatcher.notify(_make_event())
        dispatcher.notify(_make_event())  # same ip/type, within cooldown

    assert mock_urlopen.call_count == 1


def test_cooldown_resets_after_window_elapses() -> None:
    config = _all_channels_config()
    config.notifications.email.enabled = False
    config.notifications.telegram.enabled = False
    config.notifications.cooldown = 5.0
    dispatcher = NotificationDispatcher(config)

    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen, \
         patch("src.notifications.time.time", side_effect=[1000.0, 1010.0]):
        dispatcher.notify(_make_event())
        dispatcher.notify(_make_event())  # cooldown has elapsed

    assert mock_urlopen.call_count == 2


def test_different_source_ips_are_not_throttled_against_each_other() -> None:
    config = _all_channels_config()
    config.notifications.email.enabled = False
    config.notifications.telegram.enabled = False
    dispatcher = NotificationDispatcher(config)

    with patch("src.notifications.urllib.request.urlopen") as mock_urlopen:
        dispatcher.notify(_make_event(source_ip="10.0.0.1"))
        dispatcher.notify(_make_event(source_ip="10.0.0.2"))

    assert mock_urlopen.call_count == 2


def test_discord_failure_does_not_block_other_channels() -> None:
    config = _all_channels_config()
    dispatcher = NotificationDispatcher(config)

    def urlopen_side_effect(request, timeout=None):  # noqa: ANN001 - matches urlopen signature loosely
        if "discord.com" in request.full_url:
            raise OSError("connection refused")
        return MagicMock()

    with patch("src.notifications.urllib.request.urlopen", side_effect=urlopen_side_effect), \
         patch("src.notifications.smtplib.SMTP") as mock_smtp:
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        dispatcher.notify(_make_event())  # must not raise

    mock_smtp.assert_called_once()


def test_email_failure_is_logged_and_swallowed(caplog) -> None:
    config = _all_channels_config()
    config.notifications.discord.enabled = False
    config.notifications.telegram.enabled = False
    dispatcher = NotificationDispatcher(config)

    with patch("src.notifications.smtplib.SMTP", side_effect=OSError("no route to host")):
        with caplog.at_level("WARNING"):
            dispatcher.notify(_make_event())  # must not raise

    assert "Email notification failed" in caplog.text
