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
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, render_template, request

from src.database import Database

# every event_type a detector can raise (the `name` of each class in
# src/detectors.py). The distribution endpoint always reports all of these,
# zero-filled, so the chart's categories don't jump around as events arrive.
EVENT_TYPES: Tuple[str, ...] = (
    "PORT_SCAN",
    "ARP_SPOOF",
    "SYN_FLOOD",
    "TRAFFIC_ANOMALY",
    "DNS_TUNNEL",
    "TLS_ANOMALY",
    "ML_ANOMALY",
)

# ?range= value -> (window length, bucket size), both in seconds. Buckets are
# sized so each range comes out at a readable number of points (60/24/28).
STATS_RANGES: Dict[str, Tuple[int, int]] = {
    "1h": (3600, 60),
    "24h": (86400, 3600),
    "7d": (7 * 86400, 6 * 3600),
}
DEFAULT_STATS_RANGE = "24h"


def _stats_window(
    range_key: str, now: Optional[datetime.datetime] = None
) -> Tuple[List[datetime.datetime], int]:
    """Bucket start times (UTC, oldest first) covering range_key, plus the
    bucket size in seconds. Buckets are aligned to whole multiples of the
    bucket size, so the last one is the bucket that contains now."""
    span, bucket_seconds = STATS_RANGES[range_key]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    last_start = int(now.timestamp()) // bucket_seconds * bucket_seconds
    count = span // bucket_seconds
    starts = [
        datetime.datetime.fromtimestamp(
            last_start - (count - 1 - i) * bucket_seconds, tz=datetime.timezone.utc
        )
        for i in range(count)
    ]
    return starts, bucket_seconds


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
        nukes the browser with a huge response), event_type, source_ip.
        Each event also carries `threat_intel`: the latest cached
        AbuseIPDB/VirusTotal lookup for its source IP, or null."""
        limit = min(request.args.get("limit", default=100, type=int) or 100, 1000)
        event_type = request.args.get("event_type") or None
        source_ip = request.args.get("source_ip") or None

        events = database.get_events(limit=limit, event_type=event_type, source_ip=source_ip)
        intel = database.get_threat_intel_for_ips([event.source_ip for event in events])
        payload = []
        for event in events:
            item = event.to_dict()
            cached = intel.get(event.source_ip)
            item["threat_intel"] = cached.to_dict() if cached else None
            payload.append(item)
        return jsonify(payload)

    @app.route("/api/stats")
    def api_stats() -> Any:
        """total events + a breakdown by type, for the summary cards up top"""
        stats: Dict[str, Any] = {
            "total_events": database.count_events(),
            "by_type": database.event_type_counts(),
        }
        return jsonify(stats)

    def _requested_range() -> Optional[str]:
        """?range= value, DEFAULT_STATS_RANGE if omitted, None if invalid."""
        range_key = request.args.get("range") or DEFAULT_STATS_RANGE
        return range_key if range_key in STATS_RANGES else None

    def _bad_range() -> Tuple[Any, int]:
        valid = ", ".join(STATS_RANGES)
        return jsonify({"error": f"invalid range, expected one of: {valid}"}), 400

    @app.route("/api/stats/timeline")
    def api_stats_timeline() -> Any:
        """Event counts per time bucket, one series per event type, for the
        dashboard's timeline chart. ?range= is 1h (1-minute buckets), 24h
        (hourly, the default) or 7d (6-hourly). `buckets` holds each
        bucket's start time; every list in `series` lines up with it. Only
        types with at least one event in the window get a series."""
        range_key = _requested_range()
        if range_key is None:
            return _bad_range()

        starts, bucket_seconds = _stats_window(range_key)
        first = int(starts[0].timestamp())
        series: Dict[str, List[int]] = {}
        for timestamp, event_type in database.get_event_times_since(starts[0]):
            index = (int(timestamp.timestamp()) - first) // bucket_seconds
            if 0 <= index < len(starts):
                series.setdefault(event_type, [0] * len(starts))[index] += 1

        return jsonify(
            {
                "range": range_key,
                "bucket_seconds": bucket_seconds,
                "buckets": [start.isoformat() for start in starts],
                "series": series,
            }
        )

    @app.route("/api/stats/distribution")
    def api_stats_distribution() -> Any:
        """Total events per type within ?range= (same values as the timeline
        endpoint), for the dashboard's distribution chart. Every known type
        is included, zero-filled."""
        range_key = _requested_range()
        if range_key is None:
            return _bad_range()

        starts, _ = _stats_window(range_key)
        counts = database.event_type_counts(since=starts[0])
        by_type = {event_type: counts.pop(event_type, 0) for event_type in EVENT_TYPES}
        by_type.update(counts)  # anything not in EVENT_TYPES, just in case
        return jsonify(
            {
                "range": range_key,
                "total_events": sum(by_type.values()),
                "by_type": by_type,
            }
        )

    @app.route("/api/blocked_ips")
    def api_blocked_ips() -> Any:
        """JSON list of currently-blocked IPs (see AutoBlocker in
        src/auto_block.py), newest first. Read-only -- blocks/unblocks
        happen from the detection engine, not the dashboard."""
        blocked = database.get_blocked_ips()
        return jsonify([b.to_dict() for b in blocked])

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
