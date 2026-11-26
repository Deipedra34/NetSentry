"""NetSentry severity levels mapped onto what syslog, CEF and Elastic use.

The level of an event type comes from EVENT_SEVERITY in src/notifications.py
-- the same ranking auto_block and threat_intel's min_severity use. An event
type that isn't listed there (ICMP_OVERSIZED, for one, or any type a future
detector adds) is "low", so it's still forwarded rather than lost.
"""

from __future__ import annotations

from typing import Dict

from src.notifications import EVENT_SEVERITY, SEVERITY_LEVELS

# the level of any event type EVENT_SEVERITY doesn't list
DEFAULT_SEVERITY = "low"

# RFC 5424 severity codes: 2 critical, 3 error, 4 warning, 5 notice
SYSLOG_SEVERITY: Dict[str, int] = {"low": 5, "medium": 4, "high": 3, "critical": 2}
# CEF severity, 0 (lowest) to 10 (highest)
CEF_SEVERITY: Dict[str, int] = {"low": 3, "medium": 5, "high": 8, "critical": 10}
# a 0-100 score, for JSON's severity_score and ECS event.severity
SEVERITY_SCORE: Dict[str, int] = {"low": 25, "medium": 50, "high": 75, "critical": 100}

# RFC 5424 facility codes, by the names config.yaml's siem.facility takes
SYSLOG_FACILITIES: Dict[str, int] = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "ntp": 12,
    "security": 13,
    "console": 14,
    "solaris-cron": 15,
    **{f"local{number}": 16 + number for number in range(8)},
}


def event_severity(event_type: str) -> str:
    """The NetSentry level (low, medium, high or critical) of an event type."""
    return EVENT_SEVERITY.get(event_type, DEFAULT_SEVERITY)


def meets_min_severity(severity: str, min_severity: str) -> bool:
    """True if severity is at or above min_severity. Unknown levels count
    as the lowest, so nothing is silently held back."""
    rank = SEVERITY_LEVELS.index(severity) if severity in SEVERITY_LEVELS else 0
    minimum = SEVERITY_LEVELS.index(min_severity) if min_severity in SEVERITY_LEVELS else 0
    return rank >= minimum


def syslog_severity(severity: str) -> int:
    """The RFC 5424 severity code for a NetSentry level."""
    return SYSLOG_SEVERITY.get(severity, SYSLOG_SEVERITY[DEFAULT_SEVERITY])


def cef_severity(severity: str) -> int:
    """The CEF 0-10 severity for a NetSentry level."""
    return CEF_SEVERITY.get(severity, CEF_SEVERITY[DEFAULT_SEVERITY])


def severity_score(severity: str) -> int:
    """The 0-100 score for a NetSentry level."""
    return SEVERITY_SCORE.get(severity, SEVERITY_SCORE[DEFAULT_SEVERITY])


def facility_code(name: str) -> int:
    """The RFC 5424 facility code for a facility name like "local0".
    Raises ValueError for a name that isn't one."""
    try:
        return SYSLOG_FACILITIES[str(name).strip().lower()]
    except KeyError:
        raise ValueError(
            f"unknown syslog facility {name!r}, expected one of {list(SYSLOG_FACILITIES)}"
        ) from None


def syslog_priority(facility: int, severity: str) -> int:
    """The PRI value, facility * 8 + severity code."""
    return facility * 8 + syslog_severity(severity)
