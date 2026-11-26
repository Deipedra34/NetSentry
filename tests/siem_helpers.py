"""Shared helpers for the SIEM forwarding tests: local collectors that
listen on 127.0.0.1 (UDP, TCP and TLS), throwaway test certificates, and a
fake clock. No external network traffic, and waiting is event-driven
(a Condition with a generous timeout), never a fixed sleep."""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional


class FakeClock:
    """A settable stand-in for time.monotonic()."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def split_octet_counted(data: bytes) -> List[bytes]:
    """The messages in an RFC 6587 octet-counted stream."""
    messages = []
    while data:
        length, _, rest = data.partition(b" ")
        size = int(length)
        messages.append(rest[:size])
        data = rest[size:]
    return messages


class Collector:
    """A local TCP (or, with a server context, TLS) collector that accepts
    any number of connections and keeps everything it receives."""

    def __init__(self, context: Optional[ssl.SSLContext] = None, port: int = 0) -> None:
        self.context = context
        self.data = b""
        self.peer_certs: List[Optional[dict]] = []
        self.connections = 0
        self.errors: List[BaseException] = []
        self._changed = threading.Condition()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", port))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._open: List[socket.socket] = []
        self._stopped = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
                with self._changed:
                    self.peer_certs.append(conn.getpeercert())
            with self._changed:
                self.connections += 1
                self._open.append(conn)
                self._changed.notify_all()
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                with self._changed:
                    self.data += chunk
                    self._changed.notify_all()
        except (OSError, ssl.SSLError) as exc:
            with self._changed:
                self.errors.append(exc)
                self._changed.notify_all()
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def wait_for(self, predicate: Callable[["Collector"], bool], timeout: float = 5.0) -> bool:
        with self._changed:
            return self._changed.wait_for(lambda: predicate(self), timeout)

    def messages(self) -> List[bytes]:
        with self._changed:
            return split_octet_counted(self.data)

    def drop_connections(self) -> None:
        """Closes every open connection but keeps listening."""
        with self._changed:
            conns, self._open = self._open, []
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def stop(self) -> None:
        self._listener.close()
        self.drop_connections()


class UdpCollector:
    """A local UDP collector keeping every datagram."""

    def __init__(self) -> None:
        self.datagrams: List[bytes] = []
        self._changed = threading.Condition()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                data, _ = self._sock.recvfrom(65536)
            except OSError:
                return
            with self._changed:
                self.datagrams.append(data)
                self._changed.notify_all()

    def wait_for(self, count: int, timeout: float = 5.0) -> bool:
        with self._changed:
            return self._changed.wait_for(lambda: len(self.datagrams) >= count, timeout)

    def stop(self) -> None:
        self._sock.close()


@dataclass
class SiemPki:
    """A throwaway CA plus a server certificate for "localhost" (no IP
    SAN, so connecting as 127.0.0.1 is a hostname mismatch) and a client
    certificate, all written into a temporary directory."""

    ca_file: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path

    def server_context(self, require_client_cert: bool = False) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.server_cert), str(self.server_key))
        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=str(self.ca_file))
        return context


def make_pki(directory: Path) -> SiemPki:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def _name(common_name: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    def _write_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("NetSentry Test CA"))
        .issuer_name(_name("NetSentry Test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def _leaf(common_name: str, usage: x509.ObjectIdentifier, san: Optional[List[x509.GeneralName]]):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(common_name))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
            )
        )
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return key, builder.sign(ca_key, hashes.SHA256())

    server_key, server_cert = _leaf("localhost", ExtendedKeyUsageOID.SERVER_AUTH, [x509.DNSName("localhost")])
    client_key, client_cert = _leaf("netsentry-sensor", ExtendedKeyUsageOID.CLIENT_AUTH, None)

    pki = SiemPki(
        ca_file=directory / "ca.pem",
        server_cert=directory / "server.pem",
        server_key=directory / "server-key.pem",
        client_cert=directory / "client.pem",
        client_key=directory / "client-key.pem",
    )
    pki.ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    pki.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(server_key, pki.server_key)
    pki.client_cert.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(client_key, pki.client_key)
    return pki


def ipv4_only_resolver(host, port, family=0, socktype=0, proto=0, flags=0):
    """getaddrinfo, restricted to IPv4 -- the collectors only listen on
    127.0.0.1, and "localhost" may resolve to ::1 first."""
    return socket.getaddrinfo(host, port, socket.AF_INET, socktype, proto, flags)


__all__ = [
    "Collector",
    "FakeClock",
    "SiemPki",
    "UdpCollector",
    "ipv4_only_resolver",
    "make_pki",
    "split_octet_counted",
]
