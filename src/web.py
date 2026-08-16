"""Flask app for the live events dashboard, plus its self-signed TLS setup.

Kept the dashboard deliberately simple -- the page just polls a tiny JSON
api every few seconds and re-renders the table with plain JS. No build
step, no frontend framework, no npm nonsense.
"""

from __future__ import annotations

import datetime
import ipaddress
import secrets
from pathlib import Path
from typing import Any, Dict, Tuple

from flask import Flask, Response, jsonify, render_template, request

from src.database import Database


def create_app(
    database: Database,
    refresh_interval: int = 5,
    username: str = "",
    password: str = "",
) -> Flask:
    """Builds the Flask app. refresh_interval just gets passed through to the
    template so the JS knows how often to poll. username/password enable
    basic auth, but only if you set both -- leave either blank and auth is
    just off (fine for localhost-only use, wouldn't recommend exposing this
    to the internet without at least setting these though).
    """
    app = Flask(__name__)
    app.config["NETSENTRY_DB"] = database
    app.config["NETSENTRY_REFRESH_INTERVAL"] = refresh_interval

    auth_required = bool(username and password)

    @app.before_request
    def _require_auth():
        if not auth_required:
            return None
        auth = request.authorization
        valid = (
            auth is not None
            and secrets.compare_digest(auth.username or "", username)
            and secrets.compare_digest(auth.password or "", password)
        )
        if not valid:
            return Response(
                "Authentication required.",
                401,
                {"WWW-Authenticate": 'Basic realm="NetSentry"'},
            )
        return None

    @app.route("/")
    def dashboard() -> str:
        """just renders the dashboard template"""
        return render_template(
            "dashboard.html",
            refresh_interval=refresh_interval,
        )

    @app.route("/api/events")
    def api_events() -> Any:
        """JSON list of recent events, newest first. Takes optional query
        params: limit (default 100, capped at 1000 so nobody accidentally
        nukes the browser with a huge response), event_type, source_ip."""
        limit = min(request.args.get("limit", default=100, type=int) or 100, 1000)
        event_type = request.args.get("event_type") or None
        source_ip = request.args.get("source_ip") or None

        events = database.get_events(limit=limit, event_type=event_type, source_ip=source_ip)
        return jsonify([event.to_dict() for event in events])

    @app.route("/api/stats")
    def api_stats() -> Any:
        """total events + a breakdown by type, for the summary cards up top"""
        stats: Dict[str, Any] = {
            "total_events": database.count_events(),
            "by_type": database.event_type_counts(),
        }
        return jsonify(stats)

    @app.route("/healthz")
    def healthz() -> Any:
        """just so uptime monitors have something to ping"""
        return jsonify({"status": "ok"})

    return app


def ensure_self_signed_cert(cert_path: str | Path, key_path: str | Path) -> Tuple[Path, Path]:
    """Generates a self-signed cert for the dashboard, if you want https.

    This is only meant for hitting https://127.0.0.1 locally, not something
    a real CA would ever sign -- your browser will complain about it and
    that's expected, just click through. If both files already exist we
    just hand back the paths as-is; otherwise generates a fresh 2048-bit RSA
    cert (valid ~10 years, whatever) and writes both files before returning.
    """
    cert_path = Path(cert_path)
    key_path = Path(key_path)

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netsentry.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("netsentry"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path
