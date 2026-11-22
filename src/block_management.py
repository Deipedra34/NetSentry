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
import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, FrozenSet, Iterable, List, Optional, Sequence, Tuple, Union

from src.auto_block import build_block_command, rule_identifier_for, run_firewall_command
from src.config import Config
from src.database import AuditEntry, BlockedIP, Database

logger = logging.getLogger("netsentry.block_management")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
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


# address classes that are never blocked, whatever the config says: (rule,
# what it is, ranges). A target is refused if it overlaps any of them, so
# a range can't sneak one in either.
NEVER_BLOCK_RANGES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    ("unspecified", "the unspecified address", ("0.0.0.0/8", "::/128")),
    ("loopback", "a loopback address", ("127.0.0.0/8", "::1/128")),
    ("link-local", "a link-local address", ("169.254.0.0/16", "fe80::/10")),
    ("multicast", "a multicast address", ("224.0.0.0/4", "ff00::/8")),
    ("broadcast", "the broadcast address", ("255.255.255.255/32",)),
    (
        "private",
        "a private network address (RFC 1918, unique local or shared address space)",
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"),
    ),
    ("ipv4_mapped", "an IPv4-mapped IPv6 address (block the IPv4 address itself)", ("::ffff:0:0/96",)),
)
_NEVER_BLOCK_NETWORKS: Tuple[Tuple[str, str, Tuple[IPNetwork, ...]], ...] = tuple(
    (rule, description, tuple(ipaddress.ip_network(r) for r in ranges))
    for rule, description, ranges in NEVER_BLOCK_RANGES
)


def _parse_addresses(values: Iterable[str]) -> FrozenSet[IPAddress]:
    """The valid IP addresses among values (zone IDs dropped)."""
    parsed = set()
    for value in values:
        try:
            parsed.add(ipaddress.ip_address(str(value).split("%")[0]))
        except ValueError:
            continue
    return frozenset(parsed)


@dataclass(frozen=True)
class ProtectedAddresses:
    """This machine's own addresses and its default gateway(s) -- never
    blockable. Built with from_strings() from src/sniffer.py's
    local_network_addresses(), or by hand in tests."""

    own: FrozenSet[IPAddress] = field(default_factory=frozenset)
    gateways: FrozenSet[IPAddress] = field(default_factory=frozenset)

    @classmethod
    def from_strings(cls, own: Iterable[str], gateways: Iterable[str]) -> "ProtectedAddresses":
        return cls(_parse_addresses(own), _parse_addresses(gateways))


def _unmapped(address: IPAddress) -> IPAddress:
    """An IPv4-mapped IPv6 address (::ffff:45.33.1.1, how a dual-stack
    server sees IPv4 clients) as the IPv4 address it is."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _contains(network: IPNetwork, address: IPAddress) -> bool:
    address = _unmapped(address)
    return address.version == network.version and address in network


def check_blockable(
    network: IPNetwork,
    whitelist: Sequence[IPNetwork] = (),
    protected: ProtectedAddresses = ProtectedAddresses(),
    requester_ip: Optional[str] = None,
) -> None:
    """Raises BlockRefused (naming the rule) unless `network` may be
    blocked. These rules are hard-coded, not configurable:

      - never a special address class (NEVER_BLOCK_RANGES), nor anything
        else that isn't a public address (reserved, documentation ranges...)
      - never anything overlapping a whitelist entry
      - never this machine's own addresses or its default gateway
      - never the address of whoever is asking (an admin must not lock
        themselves out of the dashboard)

    A range is refused if it overlaps or contains any of those."""
    target = target_text(network)
    for rule, description, ranges in _NEVER_BLOCK_NETWORKS:
        if any(r.version == network.version and network.overlaps(r) for r in ranges):
            raise BlockRefused(rule, f"{target} is or contains {description}, which is never blocked.")
    if not (network.network_address.is_global and network.broadcast_address.is_global):
        raise BlockRefused(
            "non_public",
            f"{target} is or contains a reserved or otherwise non-public address, which is never blocked.",
        )
    for entry in whitelist:
        if entry.version == network.version and network.overlaps(entry):
            raise BlockRefused("whitelist", f"{target} overlaps the whitelist entry {entry}.")
    for address in protected.own:
        if _contains(network, address):
            raise BlockRefused("own_address", f"{target} contains {address}, an address of this machine.")
    for address in protected.gateways:
        if _contains(network, address):
            raise BlockRefused("gateway", f"{target} contains {address}, this machine's default gateway.")
    if requester_ip:
        requester = _parse_addresses([requester_ip])
        if any(_contains(network, address) for address in requester):
            raise BlockRefused(
                "requester",
                f"{target} contains your own address ({requester_ip}); blocking it would lock you out.",
            )


def parse_whitelist(entries: Iterable[str]) -> List[IPNetwork]:
    """The global whitelist as networks; malformed entries are skipped
    (config loading doesn't validate them, and a typo there must not stop
    the safety check from running)."""
    networks: List[IPNetwork] = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue
    return networks


# the actor recorded for actions without a dashboard account behind them
ACTOR_LOCAL = "local"  # the desktop app, or the auth-less localhost dashboard
ACTOR_CLI = "cli"
# event_type stored for a manual block (an automatic one stores the event
# that triggered it)
MANUAL_EVENT_TYPE = "MANUAL"
# seconds this machine's looked-up addresses are reused before asking again
PROTECTED_CACHE_SECONDS = 300.0


class BlockFailed(RuntimeError):
    """A manual block action that passed every check but failed at the
    firewall (or can't be done on this OS). The message is safe to show;
    the block's record is left as it was."""


@dataclass
class BlockResult:
    """What a successful manual action did. applied is False when nothing
    touched the firewall (dry run, or a block that was only recorded)."""

    block: BlockedIP
    message: str
    applied: bool


def describe_duration(minutes: int) -> str:
    """'permanently', 'for 15 minutes', 'for 2 hours', 'for 7 days'."""
    if minutes == 0:
        return "permanently"
    for unit, size in (("day", 1440), ("hour", 60)):
        if minutes % size == 0:
            count = minutes // size
            return f"for {count} {unit}{'s' if count != 1 else ''}"
    return f"for {minutes} minute{'s' if minutes != 1 else ''}"


def _local_protected_addresses() -> ProtectedAddresses:
    from src.sniffer import local_network_addresses  # the only module that imports scapy

    own, gateways = local_network_addresses()
    return ProtectedAddresses.from_strings(own, gateways)


class BlockManager:
    """Manual block, unblock and duration changes, shared by the dashboard
    and the CLI. Every attempt -- successful, refused or failed -- is
    written to the audit log.

    Uses the same firewall commands and the same auto_block.dry_run switch
    as AutoBlocker: in dry run, blocks are recorded (marked dry_run, shown
    as "dry run (not applied)") and the log shows the exact command that
    would have run, but nothing touches the firewall.

    protected_addresses and clock are injectable for tests; by default this
    machine's addresses and gateway come from src/sniffer.py.
    """

    def __init__(
        self,
        config: Config,
        database: Database,
        protected_addresses: Optional[Callable[[], ProtectedAddresses]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.database = database
        self.settings = config.block_management
        self._whitelist = parse_whitelist(config.whitelist)
        self._lookup_protected = protected_addresses or _local_protected_addresses
        self._protected: Optional[ProtectedAddresses] = None
        self._protected_at = float("-inf")
        self._clock = clock

    @property
    def dry_run(self) -> bool:
        """Whether actions only get recorded, never applied at the firewall
        (auto_block.dry_run, shared with automatic blocking)."""
        return bool(self.config.auto_block.dry_run)

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self._clock(), timezone.utc)

    def protected(self) -> ProtectedAddresses:
        """This machine's own addresses and gateway, looked up at most every
        PROTECTED_CACHE_SECONDS."""
        if self._protected is None or self._clock() - self._protected_at >= PROTECTED_CACHE_SECONDS:
            self._protected = self._lookup_protected()
            self._protected_at = self._clock()
        return self._protected

    def _audit(self, actor: str, action: str, target: str, result: str, details: str = "") -> None:
        entry = AuditEntry(
            actor=printable(actor, 64) or "unknown",
            action=action,
            target=printable(target, MAX_TARGET_LENGTH) or "-",
            result=result,
            details=printable(details, 500),
            timestamp=self._now(),
        )
        self.database.add_audit_entry(entry)
        level = logging.WARNING if result in ("refused", "failed") else logging.INFO
        logger.log(level, "Block management: %s %s %s -> %s (%s)", entry.actor, action, entry.target, result, entry.details)

    def _refuse(self, actor: str, action: str, target: str, exc: BlockRefused) -> BlockRefused:
        self._audit(actor, action, target, "refused", f"refused by rule '{exc.rule}': {exc}")
        return exc

    def _fail(self, actor: str, action: str, target: str, message: str) -> BlockFailed:
        self._audit(actor, action, target, "failed", message)
        return BlockFailed(message)

    def duration_minutes(self, requested: Optional[int]) -> int:
        """The duration to use, in minutes (0 = permanent): `requested`, or
        default_duration_minutes when it's None. Raises BlockRefused if it
        isn't a whole number of minutes, is permanent while allow_permanent
        is off, or is longer than max_duration_minutes."""
        minutes = self.settings.default_duration_minutes if requested is None else requested
        if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 0:
            raise BlockRefused("invalid_duration", "The duration must be a whole number of minutes (0 = permanent).")
        if minutes == 0:
            if not self.settings.allow_permanent:
                raise BlockRefused("permanent_not_allowed", "Permanent blocks are disabled (block_management.allow_permanent).")
            return 0
        if minutes > self.settings.max_duration_minutes:
            raise BlockRefused(
                "duration_too_long",
                f"Blocks may last at most {self.settings.max_duration_minutes} minutes "
                f"({describe_duration(self.settings.max_duration_minutes).removeprefix('for ')}), or be permanent.",
            )
        return minutes

    def _expires_at(self, minutes: int) -> Optional[datetime]:
        return None if minutes == 0 else self._now() + timedelta(minutes=minutes)

    def block(
        self,
        target: str,
        duration_minutes: Optional[int] = None,
        reason: str = "",
        actor: str = ACTOR_LOCAL,
        requester_ip: Optional[str] = None,
    ) -> BlockResult:
        """Blocks an IP or CIDR range by hand for duration_minutes (None =
        the default, 0 = permanent). Re-blocking a target that's already
        blocked updates that entry instead of adding a second rule. Raises
        BlockRefused (validation or a safety rule said no) or BlockFailed
        (the firewall command failed -- nothing is recorded then, since the
        rule wasn't applied)."""
        try:
            network = parse_target(target)
            text = target_text(network)
            clean = clean_reason(reason)
            minutes = self.duration_minutes(duration_minutes)
            check_blockable(network, self._whitelist, self.protected(), requester_ip)
            existing = self.database.get_active_block(text)
            if existing is None and self.database.count_active_manual_blocks() >= self.settings.max_manual_blocks:
                raise BlockRefused(
                    "max_manual_blocks",
                    f"There are already {self.settings.max_manual_blocks} active manual blocks "
                    "(block_management.max_manual_blocks); unblock some first.",
                )
        except BlockRefused as exc:
            raise self._refuse(actor, "block", target, exc)

        expires_at = self._expires_at(minutes)
        how_long = describe_duration(minutes)
        if existing is not None:
            return self._reblock(existing, expires_at, how_long, clean, actor)

        command = build_block_command(text)
        if command is None:
            raise self._fail(actor, "block", text, "Firewall blocking isn't supported on this operating system.")
        logger.info("Firewall block command for %s [manual, %s]: %s", text, actor, " ".join(command))
        if self.dry_run:
            logger.info(
                "auto_block.dry_run is enabled -- NOT applying firewall block for %s (would have run: %s)",
                text, " ".join(command),
            )
        else:
            error = run_firewall_command(command)
            if error:
                raise self._fail(actor, "block", text, f"The firewall command failed: {error}")

        blocked = self.database.add_blocked_ip(
            BlockedIP(
                source_ip=text,
                event_type=MANUAL_EVENT_TYPE,
                rule_identifier=rule_identifier_for(text),
                blocked_at=self._now(),
                expires_at=expires_at,
                source="manual",
                created_by=printable(actor, 64),
                reason=clean,
                dry_run=self.dry_run,
            )
        )
        details = f"blocked {how_long}" + (f"; reason: {clean}" if clean else "")
        if self.dry_run:
            self._audit(actor, "block", text, "dry_run", details + "; not applied (dry run)")
            message = f"Dry run: {text} recorded as blocked {how_long}, but not applied at the firewall."
        else:
            self._audit(actor, "block", text, "success", details)
            message = f"Blocked {text} {how_long}."
        return BlockResult(blocked, message, applied=not self.dry_run)

    def _reblock(
        self, existing: BlockedIP, expires_at: Optional[datetime], how_long: str, reason: str, actor: str
    ) -> BlockResult:
        """Updates an active block instead of adding a duplicate rule. A
        dry-run entry gets its rule applied now if live mode is on."""
        text = existing.source_ip
        apply_now = existing.dry_run and not self.dry_run
        if apply_now:
            command = build_block_command(text)
            if command is None:
                raise self._fail(actor, "block", text, "Firewall blocking isn't supported on this operating system.")
            logger.info("Firewall block command for %s [manual, %s]: %s", text, actor, " ".join(command))
            error = run_firewall_command(command)
            if error:
                raise self._fail(actor, "block", text, f"The firewall command failed: {error}")
        existing.expires_at = expires_at
        existing.reason = reason or existing.reason
        existing.source = "manual"
        existing.created_by = printable(actor, 64)
        existing.dry_run = existing.dry_run and not apply_now
        self.database.update_blocked_ip(existing)
        details = f"already blocked; updated the existing entry to last {how_long.removeprefix('for ')}"
        if apply_now:
            details += "; applied the dry-run entry at the firewall"
        if reason:
            details += f"; reason: {reason}"
        self._audit(actor, "block", text, "dry_run" if existing.dry_run else "success", details)
        return BlockResult(existing, f"{text} was already blocked; its entry now lasts {how_long.removeprefix('for ')}.", applied=apply_now)
