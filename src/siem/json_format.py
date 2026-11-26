"""JSON events, one object per line (NDJSON), for Elastic, Splunk, Graylog
and anything else that parses JSON.

By default the object is the normalized record itself (see normalize.py)
plus netsentry_version: a flat, stable schema whose schema_version says
which revision it is. With siem.ecs_fields on, the same data uses Elastic
Common Schema names instead (@timestamp, event.*, source.*, destination.*,
observer.*, message), with NetSentry's own extras under netsentry.*.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from src.siem.formatting import DEFAULT_MAX_BYTES, FormatSettings, fit_to_size
from src.siem.rfc5424 import summary

ECS_VERSION = "8.11.0"


def _compact(value: Any) -> Any:
    """value with None and empty dicts/lists removed, recursively."""
    if isinstance(value, dict):
        cleaned = {key: _compact(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, {}, [])}
    return value


def _ecs_mac(value: Optional[str]) -> Optional[str]:
    """ECS writes MAC addresses upper case with dashes: AA-BB-CC-DD-EE-FF."""
    return value.replace(":", "-").upper() if value else None


def _ecs_endpoint(record: Dict[str, Any], role: str) -> Dict[str, Any]:
    return {
        "ip": record.get(f"{role}_ip"),
        "port": record.get(f"{role}_port"),
        "mac": _ecs_mac(record.get(f"{role}_mac")),
        "geo": {
            "country_name": record.get(f"{role}_country"),
            "country_iso_code": record.get(f"{role}_country_code"),
            "city_name": record.get(f"{role}_city"),
        },
        "as": {
            "number": record.get(f"{role}_asn"),
            "organization": {"name": record.get(f"{role}_as_org")},
        },
    }


def _threat_intel(record: Dict[str, Any], role: str) -> Dict[str, Any]:
    return {
        "abuseipdb_score": record.get(f"{role}_abuse_score"),
        "abuseipdb_reports": record.get(f"{role}_abuse_reports"),
        "virustotal_malicious": record.get(f"{role}_vt_malicious"),
        "virustotal_engines": record.get(f"{role}_vt_engines"),
    }


def to_ecs(record: Dict[str, Any], settings: FormatSettings) -> Dict[str, Any]:
    """The normalized record as an Elastic Common Schema document."""
    protocol = record.get("protocol")
    event_id = record.get("event_id")
    document = {
        "@timestamp": record.get("timestamp"),
        "message": summary(record),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "type": ["info"],
            "code": record.get("event_type"),
            "id": str(event_id) if event_id is not None else None,
            "severity": record.get("severity_score"),
            "module": "netsentry",
            "dataset": "netsentry.alert",
        },
        "log": {"level": record.get("severity")},
        "rule": {"name": record.get("event_name")},
        "source": _ecs_endpoint(record, "source"),
        "destination": _ecs_endpoint(record, "destination"),
        "network": {"transport": protocol.lower() if isinstance(protocol, str) else None},
        "observer": {
            "name": record.get("sensor"),
            "hostname": record.get("sensor"),
            "product": "NetSentry",
            "vendor": "NetSentry",
            "version": settings.version,
            "type": "ids",
            "ingress": {"interface": {"name": record.get("interface")}},
        },
        "netsentry": {
            "schema_version": record.get("schema_version"),
            "severity": record.get("severity"),
            "threat_intel": {
                "source": _threat_intel(record, "source"),
                "destination": _threat_intel(record, "destination"),
            },
            "truncated": record.get("truncated"),
            "test": record.get("test"),
        },
        "tags": ["netsentry", "test"] if record.get("test") else ["netsentry"],
    }
    return _compact(document)


def _render(record: Dict[str, Any], settings: FormatSettings) -> bytes:
    if settings.ecs_fields:
        document = to_ecs(record, settings)
    else:
        document = dict(record)
        document["netsentry_version"] = settings.version
    # ensure_ascii=False keeps names readable; json still escapes every
    # control character, so one event is always exactly one line
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def format_json(
    record: Dict[str, Any], settings: FormatSettings, max_bytes: int = DEFAULT_MAX_BYTES
) -> bytes:
    """One JSON object for a normalized record (no trailing newline), at
    most max_bytes long."""
    return fit_to_size(record, lambda fields: _render(fields, settings), max_bytes)
