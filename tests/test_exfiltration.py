"""Unit tests for :class:`src.detectors.ExfiltrationDetector`."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, List
from unittest.mock import MagicMock, patch

from src.auto_block import AutoBlocker
from src.config import Config, load_config
from src.database import Database, Event
from src.detectors import Detector, ExfiltrationDetector
from src.engine import DETECTOR_NAMES, DetectionEngine, build_detectors
from src.notifications import CRITICAL_EVENT_TYPES, EVENT_SEVERITY
from src.packet_info import PacketInfo
from src.threat_intel import ABUSEIPDB_URL, ThreatIntelLookup
from src.web import EVENT_TYPES
from tests.conftest import make_packet

MB = 1024 * 1024
KB = 1024
HOST = "192.168.1.20"
# any publicly routable address works as the external end -- documentation
# ranges like 203.0.113.0/24 count as private, so they'd be ignored
DST = "45.33.12.7"
OTHER_DST = "45.33.99.8"


def pkt(
    timestamp: float,
    src_ip: str = HOST,
    dst_ip: str = DST,
    size: int = MB,
    src_port: int = 50000,
    dst_port: int = 443,
) -> PacketInfo:
    """One TCP data packet (synthetic sizes, up to a megabyte each)."""
    return make_packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags="PA",
        length=size,
    )


def upload(start: float, mb: int, dst: str = DST, src: str = HOST, **kwargs: Any) -> List[PacketInfo]:
    """mb one-megabyte packets from src to dst, 10ms apart."""
    return [pkt(start + i * 0.01, src_ip=src, dst_ip=dst, **kwargs) for i in range(mb)]


def download(start: float, mb: float, dst: str = DST, src: str = HOST, port: int = 443) -> List[PacketInfo]:
    """A small request from src to dst, then mb megabytes back."""
    packets = [pkt(start, src_ip=src, dst_ip=dst, size=KB, dst_port=port)]
    if mb >= 1:
        packets += [
            pkt(start + 0.001 + i * 0.01, src_ip=dst, dst_ip=src, src_port=port, dst_port=50000)
            for i in range(int(mb))
        ]
    else:
        packets.append(pkt(start + 0.001, src_ip=dst, dst_ip=src, size=int(mb * MB), src_port=port, dst_port=50000))
    return packets


def run(detector: Detector, packets: Iterable[PacketInfo]) -> List[Event]:
    events: List[Event] = []
    for packet in packets:
        events += detector.process_packet(packet)
    return events


def test_normal_small_traffic_does_not_alert() -> None:
    detector = ExfiltrationDetector()
    packets: List[PacketInfo] = []
    for i in range(200):
        t = 1000.0 + i
        packets.append(pkt(t, size=1400))
        packets += [pkt(t + 0.1 + j * 0.01, src_ip=DST, dst_ip=HOST, size=1400, src_port=443, dst_port=50000) for j in range(10)]
    assert run(detector, packets) == []


def test_total_volume_alert() -> None:
    detector = ExfiltrationDetector()
    destinations = [f"45.33.12.{i}" for i in range(10, 15)]
    packets: List[PacketInfo] = []
    for i, dst in enumerate(destinations):
        packets += download(1000.0 + i, 5, dst=dst)  # keeps out/in well under 10
    for i, dst in enumerate(destinations):
        packets += upload(1010.0 + i, 22, dst=dst)  # 22 MB each, under 50
    events = run(detector, packets)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "DATA_EXFILTRATION"
    assert event.source_ip == HOST
    assert event.details.startswith(
        f"Possible exfiltration: {HOST} sent 100 MB to 5 external hosts in 300s, 22 MB of it to "
    )
    assert event.details.endswith("(out/in ratio 4.0); triggered: total volume over 100 MB")
    assert event.destination_ip in destinations


def test_single_destination_alert() -> None:
    detector = ExfiltrationDetector()
    events = run(detector, download(1000.0, 10) + upload(1001.0, 60))
    assert len(events) == 1
    assert events[0].details == (
        f"Possible exfiltration: {HOST} sent 50 MB to {DST} in 300s (out/in ratio 5.0); "
        "triggered: over 50 MB to one destination"
    )
    assert events[0].destination_ip == DST


def test_upload_heavy_ratio_alert() -> None:
    detector = ExfiltrationDetector()
    events = run(detector, download(1000.0, 0.5) + upload(1001.0, 12))
    assert len(events) == 1
    assert "(out/in ratio 20)" in events[0].details
    assert events[0].details.endswith("triggered: out/in ratio over 10")


def test_upload_without_any_inbound_reports_no_inbound_traffic() -> None:
    events = run(ExfiltrationDetector(), upload(1000.0, 12))
    assert len(events) == 1
    assert "(out/in ratio no inbound traffic)" in events[0].details


def test_large_download_does_not_alert() -> None:
    detector = ExfiltrationDetector()
    packets: List[PacketInfo] = []
    for i in range(400):
        packets += download(1000.0 + i * 0.5, 1)  # 400 requests, 400 MB down
    assert run(detector, packets) == []


def test_ratio_check_skipped_below_min_bytes() -> None:
    assert run(ExfiltrationDetector(min_bytes_for_ratio=10 * MB), upload(1000.0, 9)) == []


def _period(start: float, mb: int, dst: str = DST) -> List[PacketInfo]:
    """One baseline period's worth of traffic: mb down, then mb up."""
    return download(start, mb, dst=dst) + upload(start + 1.0, mb, dst=dst)


def _learn(detector: ExfiltrationDetector, periods: int, mb: int = 3) -> float:
    """Feeds `periods` normal 300s periods; returns the next period's start."""
    for p in range(periods):
        assert run(detector, _period(1000.0 + p * 300.0, mb)) == []
    return 1000.0 + periods * 300.0


def test_baseline_alert_after_min_samples() -> None:
    detector = ExfiltrationDetector(baseline_min_samples=24, baseline_multiplier=5.0)
    start = _learn(detector, 24)
    events = run(detector, _period(start, 16))
    assert len(events) == 1
    assert "5.3x its baseline" in events[0].details
    assert events[0].details.endswith("triggered: over 5x its baseline")


def test_baseline_not_trusted_before_min_samples() -> None:
    detector = ExfiltrationDetector(baseline_min_samples=24)
    start = _learn(detector, 10)
    assert run(detector, _period(start, 16)) == []


def test_baseline_multiplier_not_exceeded() -> None:
    detector = ExfiltrationDetector(baseline_min_samples=24, baseline_multiplier=5.0)
    start = _learn(detector, 24)
    assert run(detector, _period(start, 15)) == []  # 15 MB is 5.0x, not above


def test_baseline_disabled() -> None:
    detector = ExfiltrationDetector(baseline_enabled=False)
    start = _learn(detector, 24)
    assert run(detector, _period(start, 16)) == []


def test_alerting_windows_do_not_update_baseline() -> None:
    detector = ExfiltrationDetector(baseline_min_samples=24)
    start = _learn(detector, 24)
    host = detector._hosts[HOST]
    learned = host.baseline
    assert learned is not None and abs(learned - (3 * MB + KB)) < 1
    # an alerting period, then a normal one
    assert len(run(detector, _period(start, 40))) == 1
    assert run(detector, _period(start + 300.0, 3)) == []
    run(detector, [pkt(start + 600.0, size=KB)])  # closes the normal period
    assert host.baseline_samples == 25  # the alerting period was never learned
    assert host.baseline == learned
    # so the same exfiltration again is still anomalous
    events = run(detector, _period(start + 600.0, 40))
    assert len(events) == 1
    assert "baseline" in events[0].details


def test_private_inbound_and_public_to_public_traffic_is_ignored() -> None:
    detector = ExfiltrationDetector()
    packets = upload(1000.0, 200, dst="192.168.1.10")  # internal to internal
    packets += upload(1010.0, 200, src=DST, dst=HOST)  # inbound only
    packets += upload(1020.0, 200, src=OTHER_DST, dst=DST)  # public to public
    packets += upload(1030.0, 200, dst="224.0.0.251")  # multicast isn't external
    assert run(detector, packets) == []
    assert detector._hosts == {}


def test_ignored_destinations_are_skipped() -> None:
    detector = ExfiltrationDetector(ignore_destinations=["45.33.12.0/24"])
    assert run(detector, upload(1000.0, 200)) == []
    # a destination outside the ignored range is still checked
    assert {e.destination_ip for e in run(detector, upload(1010.0, 60, dst=OTHER_DST))} == {OTHER_DST}


def test_ignored_ports_are_skipped() -> None:
    detector = ExfiltrationDetector(ignore_ports=[22])
    assert run(detector, upload(1000.0, 200, dst_port=22)) == []
    assert detector._hosts == {}


def test_whitelisted_source_is_skipped(in_memory_db: Database) -> None:
    engine = DetectionEngine(in_memory_db, [ExfiltrationDetector()], whitelist=["192.168.1.0/24"])
    for packet in upload(1000.0, 200):
        engine.handle_packet(packet)
    assert in_memory_db.get_events() == []
    for packet in upload(1010.0, 60, src="10.0.0.5"):
        engine.handle_packet(packet)
    # the same upload from a host that isn't whitelisted alerts (ratio, then
    # single destination)
    assert {(e.event_type, e.source_ip) for e in in_memory_db.get_events()} == {
        ("DATA_EXFILTRATION", "10.0.0.5")
    }


def test_old_buckets_expire() -> None:
    detector = ExfiltrationDetector(window_seconds=300.0)
    assert run(detector, download(1000.0, 10) + upload(1001.0, 40)) == []
    # 400s later the first 40 MB have aged out, so another 40 stays under 50
    assert run(detector, download(1400.0, 10) + upload(1401.0, 40)) == []
    host = detector._hosts[HOST]
    assert abs(host.outbound - (40 * MB + KB)) < 1
    assert abs(host.inbound - 10 * MB) < 1
    assert abs(host.destinations[DST].total - (40 * MB + KB)) < 1


def test_cooldown_is_per_condition() -> None:
    detector = ExfiltrationDetector(cooldown=60.0)
    events = run(detector, download(1000.0, 0.5) + upload(1001.0, 12))
    assert [e.details.split("triggered: ")[1] for e in events] == ["out/in ratio over 10"]
    # still upload-heavy (on cooldown), but now over the single-destination
    # limit too -- that's a new condition, so it alerts on its own
    events = run(detector, upload(1002.0, 40))
    assert [e.details.split("triggered: ")[1] for e in events] == ["over 50 MB to one destination"]
    assert run(detector, upload(1003.0, 5)) == []
    # once the cooldown has passed, both still-ongoing conditions alert again
    events = run(detector, upload(1070.0, 1))
    assert len(events) == 1
    assert "out/in ratio" in events[0].details.split("triggered: ")[1]
    assert "to one destination" in events[0].details.split("triggered: ")[1]


def test_tracked_hosts_and_destinations_are_capped() -> None:
    detector = ExfiltrationDetector()
    detector.MAX_TRACKED_SOURCES = 100
    detector.MAX_DESTINATIONS_PER_SOURCE = 5
    # lots of internal sources...
    run(detector, [pkt(1000.0 + i * 0.001, src_ip=f"10.0.{i // 250}.{i % 250 + 1}", size=KB) for i in range(1000)])
    assert len(detector._hosts) <= 100
    # ...and one host talking to lots of destinations: the biggest are kept
    big = {f"45.33.12.{i}": i for i in range(5, 10)}  # 5..9 MB each
    for dst, mb in big.items():
        run(detector, upload(2000.0, mb, dst=dst))
    run(detector, [pkt(2001.0 + i * 0.001, dst_ip=f"45.33.50.{i}", size=KB) for i in range(50)])
    destinations = detector._hosts[HOST].destinations
    assert len(destinations) <= 5
    assert {f"45.33.12.{i}" for i in range(6, 10)} <= set(destinations)


def test_ip_length_is_preferred_over_frame_length() -> None:
    detector = ExfiltrationDetector()
    packets = []
    for i in range(11):
        packet = pkt(1000.0 + i * 0.01, size=60)
        packet.ip_length = MB
        packets.append(packet)
    assert len(run(detector, packets)) == 1  # 11 MB by ip_length, 660 bytes by frame
    # a 0 ip_length (capture offload) falls back to the frame length
    packet = pkt(2000.0, src_ip="10.0.0.9", size=1500)
    packet.ip_length = 0
    run(detector, [packet])
    assert detector._hosts["10.0.0.9"].outbound == 1500


def test_sniffer_sets_ip_length() -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    from src.sniffer import parse_packet

    raw = Ether(bytes(Ether() / IP(src=HOST, dst=DST) / TCP(sport=50000, dport=443) / Raw(b"x" * 100)))
    info = parse_packet(raw)
    assert info is not None
    assert info.ip_length == 20 + 20 + 100
    assert info.length == 14 + 20 + 20 + 100


def test_exfiltration_is_registered_everywhere() -> None:
    assert "DATA_EXFILTRATION" in CRITICAL_EVENT_TYPES
    assert EVENT_SEVERITY["DATA_EXFILTRATION"] == "high"
    assert "DATA_EXFILTRATION" in EVENT_TYPES
    assert "exfiltration" in DETECTOR_NAMES
    detectors = build_detectors(Config(), enabled=["exfiltration"])
    assert [type(d) for d in detectors] == [ExfiltrationDetector]


def test_config_section_is_passed_through(tmp_path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
exfiltration:
  window_seconds: 600
  max_outbound_mb: 500
  min_out_in_ratio: 20
  baseline_enabled: false
  ignore_destinations: ["45.33.12.0/24"]
  ignore_ports: [873]
  cooldown: 900
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.exfiltration.enabled is True
    assert config.exfiltration.max_single_destination_mb == 50.0
    assert config.exfiltration.min_bytes_for_ratio == 10 * MB
    (detector,) = [d for d in build_detectors(config) if isinstance(d, ExfiltrationDetector)]
    assert detector.window_seconds == 600
    assert detector.max_outbound_mb == 500
    assert detector.min_out_in_ratio == 20
    assert detector.baseline_enabled is False
    assert detector.ignore_ports == {873}
    assert detector.cooldown == 900
    assert run(detector, upload(1000.0, 200)) == []  # ignored destination


# --- pipeline -----------------------------------------------------------------


ABUSEIPDB_PAYLOAD = {"data": {"abuseConfidenceScore": 87, "totalReports": 42}}


def _threat_intel_config() -> Config:
    config = Config()
    config.threat_intel.enabled = True
    config.threat_intel.min_severity = "high"
    config.threat_intel.abuseipdb.enabled = True
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    return config


def _abuseipdb_response() -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = ABUSEIPDB_PAYLOAD
    return response


def test_internal_source_flows_through_pipeline_and_destination_is_enriched(in_memory_db: Database) -> None:
    config = _threat_intel_config()
    config.auto_block.enabled = True
    config.auto_block.dry_run = False  # live: would really call the firewall
    config.auto_block.min_severity = "low"
    notifier = MagicMock()
    engine = DetectionEngine(
        in_memory_db,
        [ExfiltrationDetector()],
        notifier=notifier,
        auto_blocker=AutoBlocker(config, in_memory_db),
        threat_intel=ThreatIntelLookup(config, in_memory_db),
    )
    with patch("src.auto_block.subprocess.run") as mock_run, \
            patch("src.threat_intel.requests.get", return_value=_abuseipdb_response()) as mock_get:
        for packet in upload(1000.0, 12):
            engine.handle_packet(packet)

    (event,) = in_memory_db.get_events()
    assert (event.event_type, event.source_ip) == ("DATA_EXFILTRATION", HOST)
    assert event.details.endswith(f"[destination {DST}: AbuseIPDB: 87% confidence, 42 reports]")
    assert notifier.notify.call_count == 1
    assert notifier.notify.call_args.args[0].details == event.details
    # the internal source is never looked up or blocked; the destination is looked up
    assert [c.kwargs["params"]["ipAddress"] for c in mock_get.call_args_list] == [DST]
    assert mock_get.call_args.args[0] == ABUSEIPDB_URL
    mock_run.assert_not_called()
    assert in_memory_db.get_blocked_ips() == []


def _event(source_ip: str, destination_ip: str) -> Event:
    return Event(
        event_type="DATA_EXFILTRATION",
        source_ip=source_ip,
        details="something sketchy happened",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        destination_ip=destination_ip,
    )


def test_threat_intel_skips_private_destinations(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_threat_intel_config(), in_memory_db)
    event = _event(HOST, "10.0.0.9")
    with patch("src.threat_intel.requests.get") as mock_get:
        assert lookup.enrich(event, now=1_800_000_000.0) is None
    mock_get.assert_not_called()
    assert event.details == "something sketchy happened"


def test_threat_intel_enriches_public_source_and_destination(in_memory_db: Database) -> None:
    lookup = ThreatIntelLookup(_threat_intel_config(), in_memory_db)
    event = _event(OTHER_DST, DST)
    with patch("src.threat_intel.requests.get", return_value=_abuseipdb_response()) as mock_get:
        result = lookup.enrich(event, now=1_800_000_000.0)
    assert result is not None
    assert [c.kwargs["params"]["ipAddress"] for c in mock_get.call_args_list] == [OTHER_DST, DST]
    assert event.details == (
        "something sketchy happened [AbuseIPDB: 87% confidence, 42 reports] "
        f"[destination {DST}: AbuseIPDB: 87% confidence, 42 reports]"
    )
