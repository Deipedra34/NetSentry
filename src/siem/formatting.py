"""What every SIEM format shares: its settings and the message size limit."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict

from src import __version__
from src.siem.sanitize import TRUNCATION_MARK, truncate, truncate_utf8

# the largest message sent over UDP, TCP or TLS; the details field is cut
# first so the rest of the event survives
DEFAULT_MAX_BYTES = 8192
# what's left of every text field if cutting details alone isn't enough
_LAST_RESORT_FIELD_LENGTH = 64


@dataclass
class FormatSettings:
    """The parts of a message that come from config.yaml's siem section
    rather than from the event. facility is the numeric RFC 5424 code."""

    hostname: str = "-"
    app_name: str = "netsentry"
    facility: int = 16
    version: str = __version__
    procid: str = field(default_factory=lambda: str(os.getpid()))
    ecs_fields: bool = False


Render = Callable[[Dict[str, Any]], bytes]


def fit_to_size(record: Dict[str, Any], render: Render, max_bytes: int) -> bytes:
    """render(record), made to fit in max_bytes. A message that's too big
    gets "truncated": true and a shorter details field; if that's not
    enough, every text field is shortened, and only then is the rendered
    message itself cut (at a UTF-8 character boundary)."""
    data = render(record)
    if len(data) <= max_bytes:
        return data

    trimmed = dict(record)
    trimmed["truncated"] = True
    details = trimmed.get("details")
    if isinstance(details, str):
        while True:
            data = render(trimmed)
            overflow = len(data) - max_bytes
            if overflow <= 0:
                return data
            # overflow is in bytes; a character can take several
            current = trimmed["details"]
            bytes_per_char = len(current.encode("utf-8")) / max(len(current), 1)
            keep = len(current) - int(overflow / max(bytes_per_char, 1.0)) - 1
            if keep <= len(TRUNCATION_MARK):
                del trimmed["details"]
                break
            trimmed["details"] = truncate(details, keep)

    for key, value in trimmed.items():
        if isinstance(value, str):
            trimmed[key] = truncate(value, _LAST_RESORT_FIELD_LENGTH)
    return truncate_utf8(render(trimmed), max_bytes)
