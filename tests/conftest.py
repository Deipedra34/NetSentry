"""Shared pytest fixtures and helpers for the NetSentry test suite."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import pytest

# Allow `import src...` when tests are run from the project root without
# installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database import Database  # noqa: E402
from src.packet_info import PacketInfo  # noqa: E402


def make_packet(
    timestamp: float,
    src_ip: Optional[str] = "10.0.0.1",
    dst_ip: Optional[str] = "10.0.0.2",
    protocol: Optional[str] = "TCP",
    src_port: Optional[int] = 12345,
    dst_port: Optional[int] = 80,
    tcp_flags: Optional[str] = "S",
    src_mac: Optional[str] = "aa:aa:aa:aa:aa:aa",
    dst_mac: Optional[str] = "bb:bb:bb:bb:bb:bb",
    is_arp: bool = False,
    arp_op: Optional[int] = None,
    length: int = 60,
) -> PacketInfo:
    """Build a :class:`PacketInfo` for tests without touching Scapy at all."""
    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        is_arp=is_arp,
        arp_op=arp_op,
        length=length,
    )


@pytest.fixture()
def in_memory_db() -> Database:
    """An ephemeral in-memory SQLite database for tests."""
    db = Database(":memory:")
    yield db
    db.close()
