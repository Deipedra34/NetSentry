"""Manual blocking: blocking and unblocking IPs and CIDR ranges by hand from
the dashboard or the CLI, with an audit log of every action.

Everything a person types goes through the strict validation here before
it can get anywhere near a firewall command: targets are parsed with the
ipaddress module and only ever used in their normalized form, and the
never-block safety rules (private ranges, this machine, the gateway,
whitelisted IPs, the requester's own address, ...) are hard-coded, not
configurable. The firewall commands themselves are shared with automatic
blocking (src/auto_block.py), so both paths behave the same, dry_run
included.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# the widest ranges a manual block may cover
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48
MAX_REASON_LENGTH = 200
# nothing valid is longer ("ffff:...:ffff/128" is 43 characters)
MAX_TARGET_LENGTH = 64
# all an IP address or CIDR range can contain -- checked before parsing,
# so anything else (spaces, quotes, ;, |, $, newlines...) never even
# reaches the parser, let alone a command line
_TARGET_CHARACTERS = re.compile(r"[0-9A-Fa-f.:]+(/[0-9]{1,3})?")


class BlockRefused(ValueError):
    """A manual block action that was refused. rule names the validation or
    safety rule that applied (e.g. "private", "whitelist"); the message is
    safe to show to the person who asked."""

    def __init__(self, rule: str, message: str) -> None:
        super().__init__(message)
        self.rule = rule


def printable(value: object, limit: int) -> str:
    """value as text with control characters removed and runs of whitespace
    collapsed, cut to `limit` characters -- for anything user-supplied that
    ends up in a log line or the audit log, even when it was refused."""
    text = "".join(
        " " if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") else char
        for char in str(value)
    )
    text = " ".join(text.split())
    return text[:limit]


def parse_target(value: str) -> IPNetwork:
    """The IP address or CIDR range in `value` as an ipaddress network (a
    single address is a /32 or /128). Raises BlockRefused for anything
    that isn't exactly one valid address or range, a range with host bits
    set (45.33.1.5/24 -- did you mean 45.33.1.0/24?), or a range wider than
    /16 (IPv4) or /48 (IPv6)."""
    text = (value or "").strip()
    if not text:
        raise BlockRefused("invalid", "Enter an IP address or a CIDR range.")
    shown = printable(text, MAX_TARGET_LENGTH)
    if len(text) > MAX_TARGET_LENGTH or not _TARGET_CHARACTERS.fullmatch(text):
        raise BlockRefused("invalid", f"{shown!r} is not a valid IP address or CIDR range.")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        try:
            loose = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise BlockRefused("invalid", f"{shown!r} is not a valid IP address or CIDR range.") from None
        raise BlockRefused(
            "invalid", f"{shown!r} has host bits set; did you mean {loose}?"
        ) from None
    widest = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
    if network.prefixlen < widest:
        raise BlockRefused(
            "range_too_large",
            f"{network} is too large a range to block: IPv{network.version} ranges may be "
            f"at most /{widest}.",
        )
    return network


def target_text(network: IPNetwork) -> str:
    """The normalized form a block is stored and applied as: just the
    address for a single IP ("45.33.1.5"), the CIDR range otherwise
    ("45.33.1.0/24"). Always produced by ipaddress, never the raw input."""
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def clean_reason(value: str) -> str:
    """The optional reason as short plain text: control characters removed,
    whitespace collapsed. Raises BlockRefused if it's longer than
    MAX_REASON_LENGTH characters."""
    reason = printable(value or "", MAX_REASON_LENGTH + 1)
    if len(reason) > MAX_REASON_LENGTH:
        raise BlockRefused(
            "reason_too_long", f"The reason may be at most {MAX_REASON_LENGTH} characters."
        )
    return reason
