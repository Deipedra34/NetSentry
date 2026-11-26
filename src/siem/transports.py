"""Network transports that deliver formatted SIEM messages: UDP, TCP and TLS.

A transport only moves bytes and reports failures by raising OSError (or
ssl.SSLError, a subclass); retrying with backoff is the sender's job (see
sender.py). Every step that can wait on the network has a timeout --
hostname resolution included, which the standard library can't time out
on its own -- so a slow or unreachable collector can never block the
sender thread for long.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Any, Callable, List, Optional, Tuple

from src.siem.formatting import DEFAULT_MAX_BYTES

CONNECT_TIMEOUT = 5.0
SEND_TIMEOUT = 5.0
RESOLVE_TIMEOUT = 5.0

AddressInfo = Tuple[Any, ...]
Resolver = Callable[..., List[AddressInfo]]


def resolve(
    host: str,
    port: int,
    socktype: int,
    timeout: float = RESOLVE_TIMEOUT,
    resolver: Resolver = socket.getaddrinfo,
) -> List[AddressInfo]:
    """getaddrinfo() for host, giving up after timeout seconds. An IP
    address is returned straight away; a hostname is looked up on a
    short-lived daemon thread, since getaddrinfo itself can't be timed
    out and a stuck DNS server would otherwise hang the caller."""
    try:
        return resolver(host, port, 0, socktype, 0, socket.AI_NUMERICHOST)
    except socket.gaierror:
        pass  # not an IP address literal

    outcome: dict = {}

    def _lookup() -> None:
        try:
            outcome["result"] = resolver(host, port, 0, socktype)
        except Exception as exc:  # noqa: BLE001 - handed back to the caller below
            outcome["error"] = exc

    thread = threading.Thread(target=_lookup, name="netsentry-siem-resolve", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise socket.timeout(f"resolving {host} timed out")
    if "error" in outcome:
        raise outcome["error"]
    if not outcome.get("result"):
        raise socket.gaierror(f"no address found for {host}")
    return outcome["result"]


def describe_error(exc: BaseException) -> str:
    """A short, stable reason for a delivery failure -- for the log, the
    dashboard and --siem-test. Never includes the message being sent."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"TLS certificate verification failed: {exc.verify_message or exc.reason}"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc.reason or exc.__class__.__name__}"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(exc, socket.gaierror):
        return "hostname could not be resolved"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "connection lost"
    if isinstance(exc, OSError):
        return exc.strerror or str(exc) or exc.__class__.__name__
    return exc.__class__.__name__


class Transport:
    """Base class: connect(), send() and close(), raising OSError on failure.
    max_bytes is the largest message the transport accepts."""

    kind = "base"
    max_bytes = DEFAULT_MAX_BYTES

    def __init__(self, host: str, port: int, timeout: float = SEND_TIMEOUT, resolver: Resolver = socket.getaddrinfo) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.resolver = resolver
        self._sock: Optional[Any] = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    @property
    def target(self) -> str:
        """host:port, for status displays."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    def connect(self) -> None:
        raise NotImplementedError

    def send(self, payload: bytes) -> None:
        raise NotImplementedError

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class UdpTransport(Transport):
    """Plain syslog over UDP (RFC 5426): one datagram per message, no
    framing, no delivery confirmation. connect() only picks the address;
    an ICMP "port unreachable" can still surface as ConnectionRefusedError
    on a later send."""

    kind = "udp"

    def connect(self) -> None:
        self.close()
        family, socktype, proto, _, address = resolve(
            self.host, self.port, socket.SOCK_DGRAM, resolver=self.resolver
        )[0]
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(self.timeout)
            sock.connect(address)
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def send(self, payload: bytes) -> None:
        if self._sock is None:
            self.connect()
        assert self._sock is not None
        try:
            self._sock.send(payload[: self.max_bytes])
        except OSError:
            self.close()
            raise
