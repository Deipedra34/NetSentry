"""SiemForwarder: what the engine, the CLI and the dashboard talk to.

Built once at startup from config.yaml's siem section. Each valid
destination gets its transport, its format and its own DestinationSender
(queue + daemon thread); an invalid one is logged and skipped, and one
whose TLS files can't be loaded is shown as disabled. forward() is the
engine's hook: it normalizes the event once and queues it for every
destination whose min_severity it meets, without ever waiting on the
network.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, Dict, List, Optional

from src.config import Config, SiemDestinationConfig, parse_siem_destinations
from src.database import Event, ThreatIntelResult
from src.packet_info import PacketInfo
from src.siem.cef import format_cef
from src.siem.file_output import FileTransport
from src.siem.formatting import FormatSettings
from src.siem.json_format import format_json
from src.siem.normalize import make_test_event, normalize_event
from src.siem.rfc5424 import format_rfc5424
from src.siem.sender import DEFAULT_FLUSH_TIMEOUT, STATE_DISABLED, DestinationSender
from src.siem.severity import SYSLOG_FACILITIES, event_severity, facility_code, meets_min_severity
from src.siem.transports import TcpTransport, TlsTransport, Transport, UdpTransport, describe_error, tls_context

logger = logging.getLogger("netsentry.siem")

FORMATTERS: Dict[str, Callable[..., bytes]] = {
    "rfc5424": format_rfc5424,
    "cef": format_cef,
    "json": format_json,
}
DEFAULT_FACILITY = "local0"
DEFAULT_QUEUE_SIZE = 10000


def framing_for(destination: SiemDestinationConfig) -> str:
    """A tcp/tls destination's framing: "auto" means octet counting for
    syslog and CEF, one object per line for JSON."""
    if destination.framing != "auto":
        return destination.framing
    return "newline" if destination.format == "json" else "octet_counting"


def make_transport(destination: SiemDestinationConfig) -> Transport:
    """The transport for a (validated) destination. Raises OSError or
    ssl.SSLError if a TLS file can't be loaded."""
    if destination.transport == "udp":
        return UdpTransport(destination.host, destination.port)
    if destination.transport == "tcp":
        return TcpTransport(destination.host, destination.port, framing=framing_for(destination))
    if destination.transport == "tls":
        context = tls_context(
            verify=destination.verify,
            ca_file=destination.ca_file,
            client_cert=destination.client_cert,
            client_key=destination.client_key,
        )
        return TlsTransport(destination.host, destination.port, context, framing=framing_for(destination))
    return FileTransport(destination.path, destination.max_size_mb, destination.backup_count)


def _safe_target(destination: SiemDestinationConfig, transport: Optional[Transport]) -> str:
    """Where a destination sends to, safe to show on the dashboard: host and
    port without any user:password@ prefix, or just the file name."""
    if transport is not None:
        return transport.target
    if destination.transport == "file":
        return destination.path.replace("\\", "/").rsplit("/", 1)[-1]
    return Transport(destination.host, destination.port).target


@dataclass
class _Destination:
    config: SiemDestinationConfig
    transport: Optional[Transport]
    sender: Optional[DestinationSender]
    # why the destination is disabled, if it is
    error: Optional[str] = None


TransportFactory = Callable[[SiemDestinationConfig], Transport]


class SiemForwarder:
    """Forwards events to every configured SIEM destination.

    geoip (a GeoIPLookup) adds country and network fields when it's
    enabled. transport_factory and clock are injectable for tests; start
    False leaves the sender threads unstarted (tests drive them with
    step(), and --siem-test needs no threads at all).
    """

    def __init__(
        self,
        config: Config,
        geoip: Optional[Any] = None,
        transport_factory: TransportFactory = make_transport,
        start: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        siem = config.siem
        self.config = config
        self.enabled = bool(siem.enabled)
        self.transport_factory = transport_factory
        self.hostname = str(siem.hostname or "").strip() or socket.gethostname()
        self.include_details = bool(siem.include_details)
        self._geo = geoip.locate if geoip is not None and getattr(geoip, "enabled", False) else None

        try:
            facility = facility_code(siem.facility)
        except ValueError as exc:
            logger.error("siem.facility: %s; using %s", exc, DEFAULT_FACILITY)
            facility = SYSLOG_FACILITIES[DEFAULT_FACILITY]
        queue_size = siem.queue_size
        if isinstance(queue_size, bool) or not isinstance(queue_size, int) or queue_size < 1:
            logger.error("siem.queue_size must be a whole number above 0; using %d", DEFAULT_QUEUE_SIZE)
            queue_size = DEFAULT_QUEUE_SIZE
        self.queue_size = queue_size
        self.settings = FormatSettings(
            hostname=self.hostname,
            app_name=str(siem.app_name or "netsentry"),
            facility=facility,
            ecs_fields=bool(siem.ecs_fields),
        )

        self.destinations: List[_Destination] = []
        if not self.enabled:
            return

        parsed, errors = parse_siem_destinations(siem.destinations)
        for error in errors:
            logger.error(error)
        for destination in parsed:
            self.destinations.append(self._build(destination, clock))

        senders = [d.sender for d in self.destinations if d.sender is not None]
        if start:
            for sender in senders:
                sender.start()
        if senders:
            logger.info(
                "SIEM forwarding enabled for %d destination(s): %s",
                len(senders),
                ", ".join(
                    f"{d.config.name} ({d.config.format} over {d.config.transport})"
                    for d in self.destinations
                    if d.sender is not None
                ),
            )
        else:
            logger.warning("siem.enabled is true but no SIEM destination is usable; nothing is forwarded")

    def _build(self, destination: SiemDestinationConfig, clock: Callable[[], float]) -> _Destination:
        try:
            transport = self.transport_factory(destination)
        except (OSError, ValueError) as exc:
            reason = describe_error(exc)
            if destination.transport == "tls":
                reason = f"TLS files could not be loaded: {reason}"
            # the log names the file; the dashboard (status()) doesn't
            filename = getattr(exc, "filename", None)
            logger.error(
                "SIEM destination %r is disabled: %s%s",
                destination.name,
                reason,
                f" ({filename})" if filename else "",
            )
            return _Destination(destination, None, None, error=reason)
        if destination.transport == "tls" and not destination.verify:
            logger.warning(
                "SIEM destination %r: TLS certificate verification is OFF (verify: false). The "
                "connection is encrypted, but anyone in the path can impersonate the collector. "
                "Only use this for testing.",
                destination.name,
            )
        render = partial(FORMATTERS[destination.format], settings=self.settings, max_bytes=transport.max_bytes)
        sender = DestinationSender(destination.name, transport, render, queue_size=self.queue_size, clock=clock)
        return _Destination(destination, transport, sender)

    @property
    def active(self) -> bool:
        """True if at least one destination is forwarding."""
        return any(d.sender is not None for d in self.destinations)

    def forward(
        self,
        event: Event,
        packet: Optional[PacketInfo] = None,
        threat: Optional[ThreatIntelResult] = None,
    ) -> None:
        """Queues event for every destination whose min_severity it meets.
        Returns at once; delivery happens on the senders' threads."""
        severity = event_severity(event.event_type)
        targets = [
            d.sender
            for d in self.destinations
            if d.sender is not None and meets_min_severity(severity, d.config.min_severity)
        ]
        if not targets:
            return
        record = normalize_event(
            event,
            packet=packet,
            geo=self._geo,
            threat=threat,
            sensor=self.hostname,
            include_details=self.include_details,
        )
        for sender in targets:
            sender.submit(record)

    def close(self, flush_timeout: float = DEFAULT_FLUSH_TIMEOUT) -> None:
        """Flushes every destination at the same time for about
        flush_timeout seconds, then stops them. Never hangs."""
        senders = [d.sender for d in self.destinations if d.sender is not None]
        for sender in senders:
            sender.request_stop(flush_timeout)
        deadline = time.monotonic() + flush_timeout + 1.0
        for sender in senders:
            sender.join(deadline - time.monotonic())

    def status(self) -> Dict[str, Any]:
        """What the dashboard shows: per destination its state and
        counters, and where it sends to -- never credentials or file paths."""
        destinations = []
        for destination in self.destinations:
            entry: Dict[str, Any] = {
                "name": destination.config.name,
                "format": destination.config.format,
                "transport": destination.config.transport,
                "target": _safe_target(destination.config, destination.transport),
                "min_severity": destination.config.min_severity,
            }
            if destination.sender is not None:
                entry.update(destination.sender.status())
            else:
                entry.update(
                    state=STATE_DISABLED, sent=0, dropped=0, failed=0, queued=0,
                    last_error=destination.error, last_error_at=None,
                )
            destinations.append(entry)
        return {"enabled": self.enabled, "running": True, "destinations": destinations}

    def send_test(self) -> List["TestResult"]:
        """Sends the synthetic siem_test event to every configured
        destination -- whether or not siem.enabled is on -- straight away
        (no queue, no thread), in that destination's format. Returns one
        TestResult per destination, invalid ones included."""
        parsed, errors = parse_siem_destinations(self.config.siem.destinations)
        results = [TestResult("(invalid)", "", "", "", False, error) for error in errors]
        record = normalize_event(make_test_event(), sensor=self.hostname)
        for destination in parsed:
            transport: Optional[Transport] = None
            try:
                transport = self.transport_factory(destination)
                payload = FORMATTERS[destination.format](record, self.settings, transport.max_bytes)
                transport.connect()
                transport.send(payload)
            except Exception as exc:  # noqa: BLE001 - every failure is reported, not raised
                outcome, delivered = describe_error(exc), False
            else:
                outcome, delivered = "sent", True
                if destination.transport == "udp":
                    outcome = "sent (UDP: delivery is not confirmed)"
                if destination.transport == "tls" and not destination.verify:
                    outcome += " (WARNING: certificate not verified)"
            finally:
                if transport is not None:
                    transport.close()
            results.append(
                TestResult(
                    destination.name,
                    destination.format,
                    destination.transport,
                    _safe_target(destination, transport),
                    delivered,
                    outcome,
                )
            )
        return results


@dataclass
class TestResult:
    """What --siem-test reports for one destination."""

    __test__ = False  # not a pytest test class

    name: str
    format: str
    transport: str
    target: str
    delivered: bool
    outcome: str
