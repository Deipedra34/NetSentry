"""Unit tests for :mod:`src.pcap_export`."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

scapy = pytest.importorskip("scapy.all")

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.utils import rdpcap  # noqa: E402

from src.config import Config  # noqa: E402
from src.database import Event  # noqa: E402
from src.packet_info import PacketInfo  # noqa: E402
from src.pcap_export import PcapExporter  # noqa: E402


def _make_config(tmp_path: Path, capture_window_seconds: float = 10.0, cooldown: float = 300.0) -> Config:
    config = Config()
    config.pcap_export.enabled = True
    config.pcap_export.output_dir = str(tmp_path)
    config.pcap_export.capture_window_seconds = capture_window_seconds
    config.notifications.cooldown = cooldown
    return config


def _make_scapy_packet(src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2") -> object:
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=1234, dport=80, flags="S")


def _make_packet_info(timestamp: float, src_ip: str = "10.0.0.1", with_raw: bool = True) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="10.0.0.2",
        protocol="TCP",
        src_port=1234,
        dst_port=80,
        tcp_flags="S",
        raw_packet=_make_scapy_packet(src_ip) if with_raw else None,
    )


def _time_sequence(values: List[float]):
    """Returns a side_effect callable that yields `values` in order, then
    keeps repeating the last one -- patching the global time.time() also
    affects stdlib logging (it timestamps every LogRecord), so a plain
    list-based side_effect runs out and raises StopIteration on the extra
    calls those log lines make."""
    remaining = iter(values)
    last = [values[-1]]

    def _next() -> float:
        try:
            last[0] = next(remaining)
        except StopIteration:
            pass
        return last[0]

    return _next


def _make_event(event_type: str = "SYN_FLOOD", source_ip: str = "10.0.0.1", timestamp: float = 1000.0) -> Event:
    return Event(
        event_type=event_type,
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc),
    )


def test_critical_event_creates_pcap_file(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)
    exporter.export(_make_event(timestamp=1000.0), packet)

    pcap_files = list(tmp_path.glob("*.pcap"))
    assert len(pcap_files) == 1
    assert pcap_files[0].name.startswith("SYN_FLOOD_10.0.0.1_")

    packets = rdpcap(str(pcap_files[0]))
    assert len(packets) == 1


def test_non_critical_event_does_not_export(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)
    exporter.export(_make_event(event_type="NOT_A_REAL_EVENT", timestamp=1000.0), packet)

    assert list(tmp_path.glob("*.pcap")) == []


def test_cooldown_prevents_duplicate_exports_within_window(tmp_path: Path) -> None:
    config = _make_config(tmp_path, cooldown=300.0)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)

    with patch("src.pcap_export.time.time", side_effect=_time_sequence([1000.0, 1010.0])):
        exporter.export(_make_event(timestamp=1000.0), packet)
        exporter.export(_make_event(timestamp=1010.0), packet)  # same ip/type, within cooldown

    assert len(list(tmp_path.glob("*.pcap"))) == 1


def test_cooldown_resets_after_window_elapses(tmp_path: Path) -> None:
    config = _make_config(tmp_path, cooldown=5.0)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)

    with patch("src.pcap_export.time.time", side_effect=_time_sequence([1000.0, 1010.0])):
        exporter.export(_make_event(timestamp=1000.0), packet)
        exporter.export(_make_event(timestamp=1010.0), packet)  # cooldown has elapsed

    assert len(list(tmp_path.glob("*.pcap"))) == 2


def test_disabled_exporter_never_writes(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    config.pcap_export.enabled = False
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)
    exporter.export(_make_event(timestamp=1000.0), packet)

    assert list(tmp_path.glob("*.pcap")) == []


def test_buffer_includes_pre_event_context_packets(tmp_path: Path) -> None:
    config = _make_config(tmp_path, capture_window_seconds=10.0)
    exporter = PcapExporter(config)

    # Context packets from just before the event, plus the triggering one.
    context_packets = [_make_packet_info(timestamp=995.0 + i, src_ip="10.0.0.1") for i in range(5)]
    for pkt in context_packets:
        exporter.add_packet(pkt)
    trigger_packet = _make_packet_info(timestamp=1000.0, src_ip="10.0.0.1")
    exporter.add_packet(trigger_packet)

    exporter.export(_make_event(timestamp=1000.0), trigger_packet)

    pcap_files = list(tmp_path.glob("*.pcap"))
    assert len(pcap_files) == 1
    exported = rdpcap(str(pcap_files[0]))
    # 5 context packets + the triggering packet itself.
    assert len(exported) == 6


def test_buffer_drops_packets_older_than_capture_window(tmp_path: Path) -> None:
    config = _make_config(tmp_path, capture_window_seconds=10.0)
    exporter = PcapExporter(config)

    old_packet = _make_packet_info(timestamp=900.0, src_ip="10.0.0.1")
    exporter.add_packet(old_packet)
    trigger_packet = _make_packet_info(timestamp=1000.0, src_ip="10.0.0.1")
    exporter.add_packet(trigger_packet)  # pushes cutoff past the old packet's timestamp

    exporter.export(_make_event(timestamp=1000.0), trigger_packet)

    pcap_files = list(tmp_path.glob("*.pcap"))
    exported = rdpcap(str(pcap_files[0]))
    assert len(exported) == 1


def test_packets_without_raw_packet_are_not_buffered(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0, with_raw=False)
    exporter.add_packet(packet)
    exporter.export(_make_event(timestamp=1000.0), packet)

    # No raw packets ever buffered, so there's nothing to export.
    assert list(tmp_path.glob("*.pcap")) == []


def test_output_dir_is_created_if_missing(tmp_path: Path) -> None:
    output_dir = tmp_path / "nested" / "captures"
    config = _make_config(output_dir)
    exporter = PcapExporter(config)

    packet = _make_packet_info(timestamp=1000.0)
    exporter.add_packet(packet)
    exporter.export(_make_event(timestamp=1000.0), packet)

    assert output_dir.is_dir()
    assert len(list(output_dir.glob("*.pcap"))) == 1
