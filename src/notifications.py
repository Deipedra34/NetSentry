"""Multi-channel notifications for critical NetSentry events.

NotificationDispatcher fires Discord/Telegram/email alerts for events the
engine decides are worth waking someone up for. Each channel is best-effort
-- a bad webhook URL, wrong bot token, or no internet shouldn't take down
packet capture, so every send is wrapped and just logs a warning on failure.
"""

from __future__ import annotations

import json
import logging
import smtplib
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Dict, Tuple

from src.config import Config
from src.database import Event

logger = logging.getLogger("netsentry.notifications")

# Event types severe enough to page someone. SYN floods and ARP spoofing are
# inherently critical, traffic anomalies flag volumetric spikes, and port
# scans are included too since Event doesn't carry a severity/priority field
# to distinguish "probing" from "worse".
CRITICAL_EVENT_TYPES = {"SYN_FLOOD", "ARP_SPOOF", "TRAFFIC_ANOMALY", "PORT_SCAN"}


class NotificationDispatcher:
    """Fans a critical Event out to whichever channels are enabled.

    Each channel keeps its own per-(event_type, source_ip) cooldown so a
    sustained attack doesn't spam Discord/Telegram/email once per packet --
    mirrors the per-IP cooldown pattern the detectors already use.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        # (channel, event_type, source_ip) -> last sent timestamp
        self._last_sent: Dict[Tuple[str, str, str], float] = {}

    def notify(self, event: Event) -> None:
        """Sends `event` to every enabled channel, provided it's critical
        and not currently on cooldown for that channel. Never raises --
        each channel's send is wrapped so one bad channel can't block the
        others or crash the caller."""
        if event.event_type not in CRITICAL_EVENT_TYPES:
            return

        notifications = self.config.notifications
        if notifications.discord.enabled and self._should_send("discord", event):
            self._send_discord(event)
        if notifications.telegram.enabled and self._should_send("telegram", event):
            self._send_telegram(event)
        if notifications.email.enabled and self._should_send("email", event):
            self._send_email(event)

    def _should_send(self, channel: str, event: Event) -> bool:
        """True if `channel` hasn't alerted for this event_type/source_ip
        combo within the configured cooldown window. Records the send
        attempt immediately (not just on success) so a channel that's
        currently erroring out doesn't get hammered every single event."""
        key = (channel, event.event_type, event.source_ip)
        now = time.time()
        last = self._last_sent.get(key, float("-inf"))
        if now - last < self.config.notifications.cooldown:
            return False
        self._last_sent[key] = now
        return True

    @staticmethod
    def _format_body(event: Event) -> str:
        """Plain-text event summary shared by the Telegram and email sends."""
        return (
            f"Event: {event.event_type}\n"
            f"Source IP: {event.source_ip}\n"
            f"Time: {event.timestamp.isoformat()}\n"
            f"Details: {event.details}"
        )

    def _send_discord(self, event: Event) -> None:
        webhook_url = self.config.notifications.discord.webhook_url
        payload = {
            "embeds": [
                {
                    "title": f"NetSentry Alert: {event.event_type}",
                    "color": 15158332,  # red
                    "fields": [
                        {"name": "Source IP", "value": event.source_ip, "inline": True},
                        {"name": "Timestamp", "value": event.timestamp.isoformat(), "inline": True},
                        {"name": "Details", "value": event.details, "inline": False},
                    ],
                }
            ]
        }
        try:
            request = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=10)
        except Exception as exc:  # noqa: BLE001 - a bad webhook must not take down the engine
            logger.warning("Discord notification failed: %s", exc)

    def _send_telegram(self, event: Event) -> None:
        telegram = self.config.notifications.telegram
        url = f"https://api.telegram.org/bot{telegram.bot_token}/sendMessage"
        payload = {"chat_id": telegram.chat_id, "text": f"NetSentry Alert\n\n{self._format_body(event)}"}
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=10)
        except Exception as exc:  # noqa: BLE001 - a bad token/chat id must not take down the engine
            logger.warning("Telegram notification failed: %s", exc)

    def _send_email(self, event: Event) -> None:
        email_config = self.config.notifications.email
        message = EmailMessage()
        message["Subject"] = f"NetSentry Alert: {event.event_type} from {event.source_ip}"
        message["From"] = email_config.from_addr
        message["To"] = email_config.to_addr
        message.set_content(self._format_body(event))
        try:
            with smtplib.SMTP(email_config.smtp_host, email_config.smtp_port, timeout=10) as smtp:
                if email_config.use_tls:
                    smtp.starttls()
                if email_config.username:
                    smtp.login(email_config.username, email_config.password)
                smtp.send_message(message)
        except Exception as exc:  # noqa: BLE001 - bad creds/unreachable smtp must not take down the engine
            logger.warning("Email notification failed: %s", exc)
