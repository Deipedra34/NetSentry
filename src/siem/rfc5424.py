"""RFC 5424 syslog messages, the format every syslog collector understands.

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [netsentry@32473 ...] MSG

PRI comes from the configured facility and the event's severity, MSGID is
the event type, and one structured data element carries the normalized
fields (all but details, which is the message text). 32473 is the
private enterprise number RFC 5424 reserves for examples and
documentation, which is what NetSentry, without one of its own, uses.
"""

from __future__ import annotations

from typing import Any, Dict

from src.siem.formatting import DEFAULT_MAX_BYTES, FormatSettings, fit_to_size
from src.siem.sanitize import clean_text, sd_name, sd_param_value, syslog_header_token
from src.siem.severity import syslog_priority

SD_ID = "netsentry@32473"
_BOM = "﻿"


def summary(record: Dict[str, Any]) -> str:
    """The short human-readable line, e.g. "Port scan from 45.33.12.9: 20
    ports in 10s". Shared with CEF's msg and ECS's message."""
    name = record.get("event_name") or record.get("event_type") or "Event"
    origin = record.get("source_ip") or record.get("source_mac")
    text = f"{name} from {origin}" if origin else str(name)
    details = record.get("details")
    return f"{text}: {details}" if details else text


def _param_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return sd_param_value(value)


def _render(record: Dict[str, Any], settings: FormatSettings) -> bytes:
    pri = syslog_priority(settings.facility, str(record.get("severity", "")))
    header = " ".join(
        (
            f"<{pri}>1",
            syslog_header_token(record.get("timestamp", ""), 64),
            syslog_header_token(settings.hostname, 255),
            syslog_header_token(settings.app_name, 48),
            syslog_header_token(settings.procid, 128),
            syslog_header_token(record.get("event_type", ""), 32),
        )
    )
    params = " ".join(
        f'{sd_name(key)}="{_param_value(value)}"'
        for key, value in record.items()
        if key != "details"
    )
    structured_data = f"[{SD_ID} {params}]" if params else f"[{SD_ID}]"
    message = clean_text(summary(record), 1 << 20)
    # RFC 5424 6.4: a UTF-8 MSG starts with a BOM; plain ASCII needs none
    if not message.isascii():
        message = _BOM + message
    return f"{header} {structured_data} {message}".encode("utf-8")


def format_rfc5424(
    record: Dict[str, Any], settings: FormatSettings, max_bytes: int = DEFAULT_MAX_BYTES
) -> bytes:
    """One RFC 5424 message for a normalized record (no trailing newline --
    framing is the transport's job), at most max_bytes long."""
    return fit_to_size(record, lambda fields: _render(fields, settings), max_bytes)
