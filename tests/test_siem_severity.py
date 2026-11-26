"""Tests for :mod:`src.siem.severity`."""

from __future__ import annotations

import pytest

from src.notifications import EVENT_SEVERITY, SEVERITY_LEVELS
from src.siem.severity import (
    CEF_SEVERITY,
    SEVERITY_SCORE,
    SYSLOG_SEVERITY,
    cef_severity,
    event_severity,
    facility_code,
    meets_min_severity,
    severity_score,
    syslog_priority,
    syslog_severity,
)
from src.web import EVENT_TYPES


@pytest.mark.parametrize(
    ("level", "syslog", "cef", "score"),
    [
        ("low", 5, 3, 25),
        ("medium", 4, 5, 50),
        ("high", 3, 8, 75),
        ("critical", 2, 10, 100),
    ],
)
def test_mapping_table(level: str, syslog: int, cef: int, score: int) -> None:
    assert syslog_severity(level) == syslog
    assert cef_severity(level) == cef
    assert severity_score(level) == score


def test_every_level_is_mapped_and_ordered() -> None:
    for table in (SYSLOG_SEVERITY, CEF_SEVERITY, SEVERITY_SCORE):
        assert set(table) == set(SEVERITY_LEVELS)
    # higher NetSentry level -> more severe in every scheme (syslog counts down)
    syslog = [SYSLOG_SEVERITY[level] for level in SEVERITY_LEVELS]
    assert syslog == sorted(syslog, reverse=True)
    assert [CEF_SEVERITY[level] for level in SEVERITY_LEVELS] == sorted(CEF_SEVERITY.values())
    assert [SEVERITY_SCORE[level] for level in SEVERITY_LEVELS] == sorted(SEVERITY_SCORE.values())


def test_every_known_event_type_has_a_level() -> None:
    for event_type in EVENT_TYPES:
        assert event_severity(event_type) in SEVERITY_LEVELS


def test_event_severity_follows_the_notifications_ranking() -> None:
    for event_type, level in EVENT_SEVERITY.items():
        assert event_severity(event_type) == level
    assert event_severity("SYN_FLOOD") == "critical"


def test_unlisted_and_future_event_types_are_low() -> None:
    assert event_severity("ICMP_OVERSIZED") == "low"
    assert event_severity("SOME_FUTURE_DETECTOR") == "low"


@pytest.mark.parametrize(
    ("severity", "minimum", "expected"),
    [
        ("low", "low", True),
        ("high", "medium", True),
        ("medium", "high", False),
        ("critical", "critical", True),
        ("low", "critical", False),
        ("whatever", "low", True),
    ],
)
def test_meets_min_severity(severity: str, minimum: str, expected: bool) -> None:
    assert meets_min_severity(severity, minimum) is expected


def test_unknown_levels_fall_back_to_low() -> None:
    assert syslog_severity("bogus") == 5
    assert cef_severity("bogus") == 3
    assert severity_score("bogus") == 25


@pytest.mark.parametrize(
    ("name", "code"), [("kern", 0), ("user", 1), ("auth", 4), ("local0", 16), ("LOCAL7", 23), (" daemon ", 3)]
)
def test_facility_code(name: str, code: int) -> None:
    assert facility_code(name) == code


def test_unknown_facility_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown syslog facility"):
        facility_code("local8")


def test_syslog_priority() -> None:
    # local0 (16) * 8 + critical (2)
    assert syslog_priority(16, "critical") == 130
    # kern (0) * 8 + low/notice (5)
    assert syslog_priority(0, "low") == 5
    assert syslog_priority(23, "high") == 187
