"""ArcSight Common Event Format (CEF), which most SIEMs parse out of the box.

    CEF:0|NetSentry|NetSentry|<version>|<event type>|<name>|<severity 0-10>|<extension>

The extension uses CEF's standard keys where one exists (rt, src, dst, spt,
dpt, smac, proto, dvchost, externalId, msg, ...) and labeled custom fields
(cs1..cs6, cn1..cn3) for the rest -- the field reference is in README.md
"SIEM and Syslog Forwarding".
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.siem.formatting import DEFAULT_MAX_BYTES, FormatSettings, fit_to_size
from src.siem.normalize import event_name
from src.siem.sanitize import MAX_DETAILS_LENGTH, cef_extension_value, cef_header_value
from src.siem.severity import cef_severity

VENDOR = "NetSentry"
PRODUCT = "NetSentry"

# (custom field, its label, the record key it carries)
_CUSTOM_FIELDS: Tuple[Tuple[str, str, str], ...] = (
    ("cs1", "severity", "severity"),
    ("cs2", "sourceCountry", "source_country"),
    ("cs3", "destinationCountry", "destination_country"),
    ("cs4", "sourceNetwork", "source_network"),
    ("cs5", "destinationNetwork", "destination_network"),
    ("cs6", "netsentryFlags", "flags"),
    ("cn1", "sourceAbuseScore", "source_abuse_score"),
    ("cn2", "sourceVirusTotalMalicious", "source_vt_malicious"),
    ("cn3", "destinationAbuseScore", "destination_abuse_score"),
    ("flexNumber1", "schemaVersion", "schema_version"),
)


def _epoch_millis(timestamp: Any) -> Optional[int]:
    try:
        moment = datetime.strptime(str(timestamp), "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
    return int(moment.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _is_ipv6(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).version == 6
    except ValueError:
        return False


def _network(record: Dict[str, Any], role: str) -> Optional[str]:
    """"AS24940 Hetzner Online GmbH" from the record's asn/as_org fields."""
    asn = record.get(f"{role}_asn")
    organization = record.get(f"{role}_as_org")
    parts = [f"AS{asn}" if asn else "", str(organization) if organization else ""]
    return " ".join(part for part in parts if part) or None


def _extension(record: Dict[str, Any]) -> List[Tuple[str, Any]]:
    pairs: List[Tuple[str, Any]] = [
        ("rt", _epoch_millis(record.get("timestamp"))),
        ("dvchost", record.get("sensor")),
        ("externalId", record.get("event_id")),
    ]
    for role, address_key, ipv6_key, ipv6_label, port_key in (
        ("source", "src", "c6a2", "Source IPv6 Address", "spt"),
        ("destination", "dst", "c6a3", "Destination IPv6 Address", "dpt"),
    ):
        ip = record.get(f"{role}_ip")
        if ip and _is_ipv6(ip):
            pairs += [(f"{ipv6_key}Label", ipv6_label), (ipv6_key, ip)]
        else:
            pairs.append((address_key, ip))
        pairs.append((port_key, record.get(f"{role}_port")))
    pairs += [
        ("smac", record.get("source_mac")),
        ("proto", record.get("protocol")),
        ("deviceInboundInterface", record.get("interface")),
    ]

    extra = dict(record)
    extra["source_network"] = _network(record, "source")
    extra["destination_network"] = _network(record, "destination")
    flags = [flag for flag in ("test", "truncated") if record.get(flag)]
    extra["flags"] = ",".join(flags) or None
    for key, label, record_key in _CUSTOM_FIELDS:
        value = extra.get(record_key)
        if value is not None:
            pairs += [(f"{key}Label", label), (key, value)]

    # free text last, by convention
    pairs.append(("msg", record.get("details")))
    return [(key, value) for key, value in pairs if value is not None and value != ""]


def _render(record: Dict[str, Any], settings: FormatSettings) -> bytes:
    event_type = str(record.get("event_type") or "UNKNOWN")
    header = "|".join(
        (
            "CEF:0",
            cef_header_value(VENDOR),
            cef_header_value(PRODUCT),
            cef_header_value(settings.version),
            cef_header_value(event_type),
            cef_header_value(record.get("event_name") or event_name(event_type)),
            str(cef_severity(str(record.get("severity", "")))),
        )
    )
    extension = " ".join(
        f"{key}={cef_extension_value(value, MAX_DETAILS_LENGTH if key == 'msg' else 256)}"
        for key, value in _extension(record)
    )
    return f"{header}|{extension}".encode("utf-8")


def format_cef(
    record: Dict[str, Any], settings: FormatSettings, max_bytes: int = DEFAULT_MAX_BYTES
) -> bytes:
    """One CEF message for a normalized record (no trailing newline), at
    most max_bytes long."""
    return fit_to_size(record, lambda fields: _render(fields, settings), max_bytes)
