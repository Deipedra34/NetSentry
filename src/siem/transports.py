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


def frame(payload: bytes, framing: str) -> bytes:
    """payload framed for a stream transport: RFC 6587 octet counting
    ("<length> <message>") or one message per line ("newline")."""
    if framing == "newline":
        return payload + b"\n"
    return str(len(payload)).encode("ascii") + b" " + payload


class TcpTransport(Transport):
    """Syslog over TCP (RFC 6587). framing is "octet_counting", the safe
    choice for syslog since a message can never be split or merged, or
    "newline" for inputs that read one JSON object per line. A dropped
    connection is noticed before the next send and reopened."""

    kind = "tcp"

    def __init__(
        self,
        host: str,
        port: int,
        framing: str = "octet_counting",
        timeout: float = SEND_TIMEOUT,
        connect_timeout: float = CONNECT_TIMEOUT,
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        super().__init__(host, port, timeout=timeout, resolver=resolver)
        self.framing = framing
        self.connect_timeout = connect_timeout

    def _wrap(self, sock: socket.socket) -> Any:
        """Hook for TLS; plain TCP uses the socket as it is."""
        return sock

    def connect(self) -> None:
        self.close()
        last_error: Optional[BaseException] = None
        for family, socktype, proto, _, address in resolve(
            self.host, self.port, socket.SOCK_STREAM, resolver=self.resolver
        ):
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.connect_timeout)
                sock.connect(address)
                wrapped = self._wrap(sock)
                wrapped.settimeout(self.timeout)
            except OSError as exc:
                sock.close()
                last_error = exc
                continue
            self._sock = wrapped
            return
        raise last_error or OSError(f"no address to connect to for {self.host}")

    def _peer_closed(self) -> bool:
        """True if the collector has closed the connection (or reset it)
        since the last send. A plain send() would often still succeed once
        after that, silently losing the message."""
        sock = self._sock
        if sock is None:
            return True
        try:
            sock.setblocking(False)
            data = self._peek(sock)
        except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return False  # nothing to read: still open
        except OSError:
            return True
        finally:
            try:
                sock.settimeout(self.timeout)
            except OSError:
                pass
        return data == b""

    def _peek(self, sock: Any) -> bytes:
        return sock.recv(1, socket.MSG_PEEK)

    def send(self, payload: bytes) -> None:
        if self._sock is None or self._peer_closed():
            self.connect()
        assert self._sock is not None
        try:
            self._sock.sendall(frame(payload[: self.max_bytes], self.framing))
        except OSError:
            self.close()
            raise


def tls_context(
    verify: bool = True, ca_file: str = "", client_cert: str = "", client_key: str = ""
) -> ssl.SSLContext:
    """The client context for a TLS destination: TLS 1.2 or newer, the
    collector's certificate and hostname verified against ca_file (or the
    system's trusted CAs), and an optional client certificate for mutual
    TLS. Raises OSError / ssl.SSLError if a file can't be loaded."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
        else:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key or None)
    return context


class TlsTransport(TcpTransport):
    """Syslog over TLS (RFC 5425), with the same framing as TCP. The
    handshake runs under the connect timeout; verification is on unless
    the destination sets verify: false."""

    kind = "tls"

    def __init__(
        self,
        host: str,
        port: int,
        context: ssl.SSLContext,
        framing: str = "octet_counting",
        timeout: float = SEND_TIMEOUT,
        connect_timeout: float = CONNECT_TIMEOUT,
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        super().__init__(
            host, port, framing=framing, timeout=timeout, connect_timeout=connect_timeout, resolver=resolver
        )
        self.context = context

    def _wrap(self, sock: socket.socket) -> Any:
        return self.context.wrap_socket(sock, server_hostname=self.host)

    def _peek(self, sock: Any) -> bytes:
        # SSL sockets can't peek; a collector never sends application data,
        # so anything read here is safe to discard
        return sock.recv(1)
