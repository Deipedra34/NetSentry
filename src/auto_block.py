"""Automatic firewall blocking for source IPs behind critical events.

AutoBlocker applies an OS-level firewall rule (netsh on Windows, iptables on
Linux) the moment a critical event fires, and tracks the block in the
`blocked_ips` table so it survives a restart and can be lifted again once it
expires. Mirrors the disabled-by-default, best-effort pattern already used
by NotificationDispatcher and PcapExporter -- a missing binary, insufficient
privileges, or an unsupported OS must never take down packet capture, it
just logs a warning and moves on.

dry_run defaults to true (see src/config.py AutoBlockConfig) so nobody
accidentally locks themselves out of their own network the first time they
flip auto_block.enabled -- in dry_run mode this module never calls
subprocess at all, it only logs what it would have run.

Two hard safety rules apply regardless of config, checked before anything
else: a whitelisted IP is never blocked, and neither is a private/local one
(loopback, RFC1918, link-local) even if an event somehow names one as its
source.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Union

from src.config import Config
from src.database import BlockedIP, Database, Event
from src.notifications import EVENT_SEVERITY, SEVERITY_LEVELS

logger = logging.getLogger("netsentry.auto_block")

# how often (seconds) maybe_check_expired actually hits the db, even though
# it's called on every packet -- no need to check for expired blocks more
# than once a minute
_EXPIRY_CHECK_INTERVAL = 60.0

_RULE_PREFIX = "NetSentry_Block_"


def _parse_whitelist(entries: List[str]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """Same idea as engine._parse_whitelist -- exact IPs or CIDR ranges,
    strict=False so a bare host IP doesn't blow up for not being a network
    address."""
    return [ipaddress.ip_network(entry, strict=False) for entry in entries]


def _is_private_or_local(ip_str: str) -> bool:
    """True for loopback/RFC1918/link-local addresses -- these never get
    blocked, even if an event somehow names one as its source (unparseable
    input is treated as private too, so we fail closed rather than acting on
    garbage)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_private or addr.is_link_local


class AutoBlocker:
    """Applies/removes OS firewall rules for source IPs behind critical
    events, and tracks them in the `blocked_ips` table.

    maybe_block() should be called once per event the engine raises (right
    alongside NotificationDispatcher.notify() / PcapExporter.export()).
    maybe_check_expired() should be called once per packet, like
    PcapExporter.add_packet() -- it's cheap (a no-op most calls) since it
    only actually hits the database once every _EXPIRY_CHECK_INTERVAL
    seconds.
    """

    def __init__(self, config: Config, database: Database, whitelist: Optional[List[str]] = None) -> None:
        self.config = config
        self.database = database
        self._whitelist_networks = _parse_whitelist(whitelist or [])
        self._last_expiry_check = 0.0

    def _is_whitelisted(self, source_ip: str) -> bool:
        """True if source_ip matches an exact IP or falls inside a CIDR
        range from the whitelist. Checked independently of whatever
        filtering the engine already did on the *packet's* source IP,
        since an event's source_ip isn't always the same address (e.g.
        TrafficAnomalyDetector reports whichever IP was busiest in the
        window, not necessarily the packet that closed it) -- so this is a
        hard rule, not just relying on the engine having filtered upstream."""
        if not self._whitelist_networks:
            return False
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(addr in network for network in self._whitelist_networks)

    def maybe_block(self, event: Event) -> None:
        """Applies a firewall block for event.source_ip if auto_block is
        enabled, the event is critical enough (min_severity), the IP isn't
        whitelisted or private/local, and it isn't already blocked. Never
        raises -- subprocess/db failures are logged as warnings."""
        if not self.config.auto_block.enabled:
            return
        if not self._meets_min_severity(event.event_type):
            return
        if self._is_whitelisted(event.source_ip):
            logger.debug("Not auto-blocking whitelisted source IP %s", event.source_ip)
            return
        if _is_private_or_local(event.source_ip):
            logger.debug("Not auto-blocking private/local source IP %s", event.source_ip)
            return
        if self.database.get_active_block(event.source_ip) is not None:
            logger.debug("Source IP %s is already blocked, skipping", event.source_ip)
            return

        self._apply_block(event)

    def maybe_check_expired(self, now: Optional[float] = None) -> None:
        """Called on every packet; actually checks for and lifts expired
        blocks at most once per _EXPIRY_CHECK_INTERVAL seconds so we're not
        hitting the database on every single packet."""
        current = now if now is not None else time.time()
        if current - self._last_expiry_check < _EXPIRY_CHECK_INTERVAL:
            return
        self._last_expiry_check = current
        self._unblock_expired()

    def _meets_min_severity(self, event_type: str) -> bool:
        if event_type not in EVENT_SEVERITY:
            return False
        min_severity = self.config.auto_block.min_severity
        if min_severity not in SEVERITY_LEVELS:
            logger.warning(
                "auto_block.min_severity=%r is not a recognized level %s; skipping block",
                min_severity, SEVERITY_LEVELS,
            )
            return False
        return SEVERITY_LEVELS.index(EVENT_SEVERITY[event_type]) >= SEVERITY_LEVELS.index(min_severity)

    def _apply_block(self, event: Event) -> None:
        ip = event.source_ip
        command = self._build_block_command(ip)
        if command is None:
            logger.warning(
                "Unsupported OS %s; skipping auto-block for %s", platform.system(), ip
            )
            return

        logger.info("Firewall block command for %s [%s]: %s", ip, event.event_type, " ".join(command))

        if self.config.auto_block.dry_run:
            logger.info(
                "auto_block.dry_run is enabled -- NOT applying firewall block for %s "
                "(would have run: %s)", ip, " ".join(command),
            )
            return

        if not self._run_command(command):
            return

        duration = self.config.auto_block.block_duration_minutes
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=duration) if duration else None
        )
        blocked = BlockedIP(
            source_ip=ip,
            event_type=event.event_type,
            rule_identifier=_RULE_PREFIX + ip,
            expires_at=expires_at,
        )
        self.database.add_blocked_ip(blocked)
        logger.warning(
            "Blocked source IP %s at the firewall (event=%s, expires=%s)",
            ip, event.event_type, expires_at.isoformat() if expires_at else "never",
        )

    def _unblock_expired(self) -> None:
        for blocked in self.database.get_expired_blocks():
            self._remove_block(blocked)

    def _remove_block(self, blocked: BlockedIP) -> None:
        command = self._build_unblock_command(blocked.source_ip)
        if command is None:
            logger.warning(
                "Unsupported OS %s; cannot remove firewall rule for %s, leaving it tracked",
                platform.system(), blocked.source_ip,
            )
            return

        logger.info("Firewall unblock command for %s: %s", blocked.source_ip, " ".join(command))

        if self.config.auto_block.dry_run:
            logger.info(
                "auto_block.dry_run is enabled -- NOT removing firewall block for %s "
                "(would have run: %s)", blocked.source_ip, " ".join(command),
            )
            self.database.remove_blocked_ip(blocked.id)
            return

        if not self._run_command(command):
            return

        self.database.remove_blocked_ip(blocked.id)
        logger.info("Unblocked expired source IP %s", blocked.source_ip)

    @staticmethod
    def _run_command(command: List[str]) -> bool:
        """Runs a firewall command, returns True on success. Never raises --
        a missing binary, insufficient privileges, or any other subprocess
        failure is logged as a warning and swallowed so it can never take
        down the detection engine."""
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
        except Exception as exc:  # noqa: BLE001 - a bad/missing firewall tool must not take down the engine
            logger.warning("Firewall command failed (%s): %s", " ".join(command), exc)
            return False
        return True

    @staticmethod
    def _build_block_command(ip: str) -> Optional[List[str]]:
        system = platform.system()
        if system == "Windows":
            return [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={_RULE_PREFIX}{ip}", "dir=in", "action=block", f"remoteip={ip}",
            ]
        if system == "Linux":
            return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        return None

    @staticmethod
    def _build_unblock_command(ip: str) -> Optional[List[str]]:
        system = platform.system()
        if system == "Windows":
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={_RULE_PREFIX}{ip}"]
        if system == "Linux":
            return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return None
