"""Tests for the never-block safety rules in :mod:`src.block_management` and
the local address lookup they use (:func:`src.sniffer.local_network_addresses`)."""

from __future__ import annotations

import socket
import sys
import types
from typing import Optional
from unittest.mock import patch

import pytest

from src.block_management import (
    BlockRefused,
    ProtectedAddresses,
    check_blockable,
    parse_target,
    parse_whitelist,
)
from src.sniffer import local_network_addresses

PROTECTED = ProtectedAddresses.from_strings(
    own=["45.33.9.9", "2606:4700:9::9", "192.168.1.20", "fe80::1%eth0"],
    gateways=["45.33.9.1", "2606:4700:9::1"],
)
WHITELIST = parse_whitelist(["45.33.7.0/24", "2606:4700:7::/64", "45.33.8.8"])


def refused_rule(target: str, requester: Optional[str] = None) -> str:
    with pytest.raises(BlockRefused) as excinfo:
        check_blockable(parse_target(target), WHITELIST, PROTECTED, requester)
    return excinfo.value.rule


@pytest.mark.parametrize(
    "target",
    ["45.33.12.7", "45.33.12.0/24", "45.34.0.0/16", "2606:4700:12::1", "2606:4701::/48"],
)
def test_public_targets_are_allowed(target: str) -> None:
    check_blockable(parse_target(target), WHITELIST, PROTECTED, requester_ip="45.33.100.100")


@pytest.mark.parametrize(
    "target, rule",
    [
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("127.0.0.1", "loopback"),
        ("127.1.2.0/24", "loopback"),
        ("::1", "loopback"),
        ("169.254.10.10", "link-local"),
        ("fe80::1234", "link-local"),
        ("224.0.0.251", "multicast"),
        ("239.255.255.250", "multicast"),
        ("ff02::fb", "multicast"),
        ("255.255.255.255", "broadcast"),
        ("10.1.2.3", "private"),
        ("172.16.5.5", "private"),
        ("172.31.0.0/16", "private"),
        ("192.168.1.1", "private"),
        ("100.64.0.1", "private"),
        ("fd00::1", "private"),
        ("::ffff:45.33.12.7", "ipv4_mapped"),
        ("203.0.113.9", "non_public"),
        ("198.51.100.0/24", "non_public"),
        ("2001:db8::1", "non_public"),
        ("240.0.0.1", "non_public"),
    ],
)
def test_special_address_classes_are_never_blocked(target: str, rule: str) -> None:
    assert refused_rule(target) == rule


def test_whitelisted_addresses_and_overlapping_ranges_are_never_blocked() -> None:
    assert refused_rule("45.33.7.10") == "whitelist"
    assert refused_rule("45.33.8.8") == "whitelist"
    # a range that merely contains or overlaps a whitelist entry is refused too
    assert refused_rule("45.33.0.0/16") == "whitelist"
    assert refused_rule("2606:4700:7::/48") == "whitelist"


def test_own_addresses_are_never_blocked() -> None:
    assert refused_rule("45.33.9.9") == "own_address"
    assert refused_rule("45.33.9.0/24") == "own_address"
    assert refused_rule("2606:4700:9::9") == "own_address"


def test_gateway_is_never_blocked() -> None:
    assert refused_rule("45.33.9.1") == "gateway"
    assert refused_rule("2606:4700:9::1") == "gateway"


def test_requesters_own_address_is_never_blocked() -> None:
    assert refused_rule("45.33.100.100", requester="45.33.100.100") == "requester"
    assert refused_rule("45.33.100.0/24", requester="45.33.100.100") == "requester"
    # a dual-stack server sees IPv4 clients as IPv4-mapped IPv6 addresses
    assert refused_rule("45.33.100.0/24", requester="::ffff:45.33.100.100") == "requester"
    assert refused_rule("2606:4700:100::/64", requester="2606:4700:100::7") == "requester"


def test_requester_elsewhere_or_unknown_does_not_matter() -> None:
    check_blockable(parse_target("45.33.12.7"), requester_ip="45.33.100.100")
    check_blockable(parse_target("45.33.12.7"), requester_ip="127.0.0.1")
    check_blockable(parse_target("45.33.12.7"), requester_ip=None)
    check_blockable(parse_target("45.33.12.7"), requester_ip="not an ip")


def test_refusal_messages_name_the_target() -> None:
    with pytest.raises(BlockRefused, match=r"45\.33\.9\.1.*default gateway"):
        check_blockable(parse_target("45.33.9.1"), protected=PROTECTED)


def test_malformed_whitelist_entries_are_skipped() -> None:
    assert [str(n) for n in parse_whitelist(["45.33.7.0/24", "nonsense", "", "45.33.8.8"])] == [
        "45.33.7.0/24",
        "45.33.8.8/32",
    ]


# --- local_network_addresses -------------------------------------------------------------


def _fake_scapy(routes, routes6):  # type: ignore[no-untyped-def]
    conf = types.SimpleNamespace(
        route=types.SimpleNamespace(routes=routes), route6=types.SimpleNamespace(routes=routes6)
    )
    module = types.ModuleType("scapy.all")
    module.conf = conf  # type: ignore[attr-defined]
    return module


def test_local_network_addresses_reads_routes_and_hostname() -> None:
    scapy = _fake_scapy(
        routes=[
            (0, 0, "45.33.9.1", "eth0", "45.33.9.9", 1),  # default route
            (0x2D210900, 0xFFFFFF00, "0.0.0.0", "eth0", "45.33.9.9", 1),
            (0x7F000000, 0xFF000000, "0.0.0.0", "lo", "127.0.0.1", 1),
        ],
        routes6=[("::", 0, "2606:4700:9::1", "eth0", ["2606:4700:9::9"], 1)],
    )
    resolved = [(socket.AF_INET6, 0, 0, "", ("fe80::1%eth0", 0, 0, 2))]
    with patch.dict(sys.modules, {"scapy.all": scapy}), patch("socket.getaddrinfo", return_value=resolved):
        own, gateways = local_network_addresses()
    assert own == {"45.33.9.9", "127.0.0.1", "2606:4700:9::9", "fe80::1"}
    assert gateways == {"45.33.9.1", "2606:4700:9::1"}


def test_local_network_addresses_never_raises() -> None:
    with patch.dict(sys.modules, {"scapy.all": None}), patch("socket.getaddrinfo", side_effect=OSError("no dns")):
        assert local_network_addresses() == (set(), set())
