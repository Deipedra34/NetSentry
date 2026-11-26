"""Tests for :mod:`src.siem.sanitize`."""

from __future__ import annotations

import pytest

from src.siem.sanitize import (
    TRUNCATION_MARK,
    cef_extension_value,
    cef_header_value,
    clean_text,
    sd_name,
    sd_param_value,
    syslog_header_token,
    to_text,
    truncate,
    truncate_utf8,
)

FORGED_LINE = "evil.example.com\n<13>1 2026-01-01T00:00:00Z attacker app - - - forged"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\nb", "a\\nb"),
        ("a\r\nb", "a\\r\\nb"),
        ("a\tb", "a\\tb"),
        ("a\x00b", "a\\x00b"),
        ("a\x1b[31mb", "a\\x1b[31mb"),
        ("a\x7fb", "a\\x7fb"),
        ("a\x85b", "a\\x85b"),
        ("a b c", "a\\u2028b\\u2029c"),
        ("plain text, 100% ok", "plain text, 100% ok"),
        ("São Paulo", "São Paulo"),
    ],
)
def test_clean_text_escapes_control_characters(raw: str, expected: str) -> None:
    assert clean_text(raw) == expected


def test_clean_text_never_lets_a_newline_through() -> None:
    cleaned = clean_text(FORGED_LINE)
    assert "\n" not in cleaned and "\r" not in cleaned
    assert cleaned.startswith("evil.example.com\\n<13>1")


def test_clean_text_caps_the_length() -> None:
    cleaned = clean_text("x" * 1000, max_length=50)
    assert len(cleaned) == 50
    assert cleaned.endswith(TRUNCATION_MARK)


def test_truncate_leaves_short_text_alone() -> None:
    assert truncate("short", 10) == "short"
    assert truncate("exactly-10", 10) == "exactly-10"


def test_to_text_replaces_invalid_utf8_bytes() -> None:
    assert to_text(b"ok \xff\xfe end") == "ok �� end"


def test_to_text_makes_lone_surrogates_encodable() -> None:
    # what b"\xff" becomes when decoded with errors="surrogateescape"
    text = to_text("bad \udcff byte")
    assert text == "bad \\udcff byte"
    text.encode("utf-8")  # must not raise


def test_to_text_stringifies_other_values() -> None:
    assert to_text(42) == "42"


def test_truncate_utf8_never_splits_a_character() -> None:
    data = "aéé".encode("utf-8")  # 1 + 2 + 2 bytes
    assert truncate_utf8(data, 4) == "aé".encode("utf-8")
    assert truncate_utf8(data, 2) == b"a"
    assert truncate_utf8(data, 10) == data


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("sensor-1.example.com", "sensor-1.example.com"),
        ("my host", "my_host"),
        ("evil\nhost", "evil_host"),
        ("höst", "h_st"),
        ("", "-"),
    ],
)
def test_syslog_header_token(raw: str, expected: str) -> None:
    assert syslog_header_token(raw, 255) == expected


def test_syslog_header_token_caps_the_length() -> None:
    assert syslog_header_token("A" * 100, 32) == "A" * 32


def test_sd_name_strips_characters_that_would_end_the_name() -> None:
    assert sd_name('a=b c]d"e') == "a_b_c_d_e"
    assert len(sd_name("n" * 40)) == 32


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('say "hi"', 'say \\"hi\\"'),
        ("back\\slash", "back\\\\slash"),
        ("close]bracket", "close\\]bracket"),
        ('x"] [forged@1 a="b', 'x\\"\\] [forged@1 a=\\"b'),
        ("line\nbreak", "line\\\\nbreak"),
    ],
)
def test_sd_param_value_escapes_per_rfc5424(raw: str, expected: str) -> None:
    assert sd_param_value(raw) == expected


def test_sd_param_value_cannot_end_the_element() -> None:
    value = sd_param_value('"] evil')
    # every quote and bracket is preceded by an (unescaped) backslash
    assert value == '\\"\\] evil'


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Port|Scan", "Port\\|Scan"),
        ("a\\b", "a\\\\b"),
        ("a\nb", "a\\\\nb"),
        ("x=y", "x=y"),
    ],
)
def test_cef_header_value(raw: str, expected: str) -> None:
    assert cef_header_value(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a=b", "a\\=b"),
        ("a\\b", "a\\\\b"),
        ("line1\nline2", "line1\\nline2"),
        ("line1\r\nline2", "line1\\nline2"),
        ("a\rb", "a\\rb"),
        ("a|b", "a|b"),
        ("tab\there", "tab\\\\there"),
        ("esc\x1b", "esc\\\\x1b"),
    ],
)
def test_cef_extension_value(raw: str, expected: str) -> None:
    assert cef_extension_value(raw) == expected


def test_cef_extension_value_cannot_add_a_key() -> None:
    value = cef_extension_value("example.com cs6Label=injected cs6=yes")
    assert "cs6Label=" not in value and "cs6=" not in value
    assert value == "example.com cs6Label\\=injected cs6\\=yes"
    assert "\n" not in cef_extension_value(FORGED_LINE)


def test_cef_extension_value_caps_the_length() -> None:
    value = cef_extension_value("=" * 500, max_length=100)
    assert len(value) == 100
    assert value.endswith(TRUNCATION_MARK)
