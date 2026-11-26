"""Sanitizing and escaping for every value NetSentry forwards to a SIEM.

Events carry attacker-influenced text -- DNS query names, TLS certificate
subjects, hostnames, detector details quoting any of those. A value that
reaches a collector unchanged could forge an extra syslog line (a newline),
break out of an RFC 5424 structured data element (a `"` or `]`), or add
CEF extension keys (a `=`). So every value is first cleaned the same way
(clean_text: control characters escaped, length capped, invalid UTF-8
replaced) and then escaped for the format it ends up in.
"""

from __future__ import annotations

import re
from typing import Any

# default cap for one field, in characters; details get a larger one
MAX_FIELD_LENGTH = 256
MAX_DETAILS_LENGTH = 4096
# appended to a value that was cut short
TRUNCATION_MARK = "...[truncated]"

# C0 and C1 control characters, DEL, and the Unicode line/paragraph
# separators some log viewers also break lines on
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}

# RFC 5424 header fields and SD-NAMEs are printable US-ASCII only
_NOT_PRINTUSASCII = re.compile(r"[^\x21-\x7e]")
_NOT_SD_NAME = re.compile(r'[^\x21-\x7e]|[= \]"]')


def _escape_control(match: "re.Match[str]") -> str:
    char = match.group(0)
    named = _NAMED_ESCAPES.get(char)
    if named:
        return named
    code = ord(char)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def to_text(value: Any) -> str:
    """value as a str that's always valid UTF-8: bytes are decoded with
    invalid sequences replaced, and lone surrogates (what invalid bytes
    turn into under the surrogateescape error handler) become visible
    escapes instead of making the encode fail later."""
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", errors="replace")
    else:
        text = str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", errors="backslashreplace").decode("utf-8")
    return text


def truncate(text: str, max_length: int) -> str:
    """text cut to at most max_length characters, ending in
    TRUNCATION_MARK if anything was cut."""
    if len(text) <= max_length:
        return text
    keep = max(max_length - len(TRUNCATION_MARK), 0)
    return text[:keep] + TRUNCATION_MARK


def clean_text(value: Any, max_length: int = MAX_FIELD_LENGTH) -> str:
    """value as safe single-line text: valid UTF-8, every control character
    (CR, LF, TAB, NUL, ESC, ...) replaced by a visible escape like `\\n` or
    `\\x1b`, and capped at max_length characters."""
    text = _CONTROL_CHARS.sub(_escape_control, to_text(value))
    return truncate(text, max_length)


def truncate_utf8(data: bytes, max_bytes: int) -> bytes:
    """data cut to at most max_bytes without splitting a UTF-8 character."""
    if len(data) <= max_bytes:
        return data
    return data[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8")


def syslog_header_token(value: Any, max_length: int) -> str:
    """An RFC 5424 header field (HOSTNAME, APP-NAME, PROCID, MSGID): printable
    US-ASCII without spaces, at most max_length characters, "-" (the NILVALUE)
    if nothing is left."""
    token = _NOT_PRINTUSASCII.sub("_", to_text(value))[:max_length]
    return token or "-"


def sd_name(value: Any) -> str:
    """An RFC 5424 SD-NAME (an SD-ID or PARAM-NAME): printable US-ASCII
    without `=`, space, `]` or `"`, at most 32 characters."""
    return _NOT_SD_NAME.sub("_", to_text(value))[:32] or "_"


def sd_param_value(value: Any, max_length: int = MAX_FIELD_LENGTH) -> str:
    """An RFC 5424 PARAM-VALUE: cleaned, then `\\`, `"` and `]` escaped with
    a backslash, as section 6.3.3 requires."""
    text = clean_text(value, max_length)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def cef_header_value(value: Any, max_length: int = MAX_FIELD_LENGTH) -> str:
    """A CEF header field: cleaned, then `\\` and `|` escaped."""
    text = clean_text(value, max_length)
    return text.replace("\\", "\\\\").replace("|", "\\|")


def cef_extension_value(value: Any, max_length: int = MAX_FIELD_LENGTH) -> str:
    """A CEF extension value: `\\` and `=` escaped and line breaks written
    as `\\n` / `\\r`, so a value can never start another key=value pair or
    another line. Other control characters become visible escapes with
    the backslash itself escaped (a TAB is sent as `\\\\t`), and the value
    is capped at max_length characters."""
    text = to_text(value).replace("\\", "\\\\").replace("=", "\\=")
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    text = _CONTROL_CHARS.sub(lambda match: "\\" + _escape_control(match), text)
    return truncate(text, max_length)
