"""Unit tests for :class:`src.detectors.BeaconingDetector`."""

from __future__ import annotations

import random
from typing import Iterable, List
from unittest.mock import MagicMock, patch

from src.auto_block import AutoBlocker
from src.config import Config, load_config
from src.database import Database, Event
from src.detectors import BeaconingDetector, Detector
from src.engine import DETECTOR_NAMES, DetectionEngine, build_detectors
from src.notifications import CRITICAL_EVENT_TYPES, EVENT_SEVERITY
from src.packet_info import PacketInfo
from src.threat_intel import ThreatIntelLookup
from src.web import EVENT_TYPES
from tests.conftest import make_packet

HOST = "192.168.1.20"
# any publicly routable address works as the "C2 server" -- documentation
# ranges like 203.0.113.0/24 count as private, so they'd be skipped
C2 = "45.33.12.7"
OTHER_C2 = "45.33.99.8"


def conn(
    timestamp: float,
    src_ip: str = HOST,
    dst_ip: str = C2,
    dst_port: int = 443,
    protocol: str = "TCP",
    tcp_flags: str = "S",
    src_port: int = 50000,
) -> PacketInfo:
    """A new outbound connection (TCP SYN by default, or a UDP packet)."""
    return make_packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags if protocol == "TCP" else None,
    )


def beacon(times: Iterable[float], **kwargs) -> List[PacketInfo]:
    return [conn(t, **kwargs) for t in times]


def every(interval: float, count: int, start: float = 1000.0) -> List[float]:
    return [start + i * interval for i in range(count)]


def run(detector: Detector, packets: Iterable[PacketInfo]) -> List[Event]:
    events: List[Event] = []
    for packet in packets:
        events += detector.process_packet(packet)
    return events


def test_perfectly_regular_beacon_alerts() -> None:
    detector = BeaconingDetector()
    events = run(detector, beacon(every(60.0, 31)))
    # one alert, at the 12th connection -- the rest are on cooldown
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "BEACONING"
    assert event.source_ip == HOST
    assert event.destination_ip == C2
    assert event.details.startswith(
        f"Beaconing: {HOST} -> {C2}:443 every ~60s (jitter 0%, 12 connections over 11 min)"
    )
    assert "median interval 60.0s" in event.details


def test_mild_jitter_within_threshold_alerts() -> None:
    offsets = [0, 3, -4, 5, -2, 1, -5, 4, -3, 2, 0, -1, 3, -4, 5]
    times = [1000.0 + i * 60.0 + offset for i, offset in enumerate(offsets)]
    events = run(BeaconingDetector(max_jitter_ratio=0.15), beacon(times))
    assert len(events) == 1
    assert "every ~59s (jitter 10%, 12 connections" in events[0].details


def test_jitter_above_threshold_does_not_alert() -> None:
    offsets = [0, 3, -4, 5, -2, 1, -5, 4, -3, 2, 0, -1, 3, -4, 5]
    times = [1000.0 + i * 60.0 + offset for i, offset in enumerate(offsets)]
    assert run(BeaconingDetector(max_jitter_ratio=0.05), beacon(times)) == []


def test_irregular_intervals_do_not_alert() -> None:
    rng = random.Random(1234)
    times = [1000.0]
    for _ in range(60):
        times.append(times[-1] + rng.uniform(5.0, 300.0))
    detector = BeaconingDetector(observation_window_seconds=86400.0)
    assert run(detector, beacon(times)) == []


def test_fewer_than_min_connections_do_not_alert() -> None:
    assert run(BeaconingDetector(min_connections=12), beacon(every(60.0, 11))) == []


def test_bursts_of_parallel_connections_collapse_into_one() -> None:
    detector = BeaconingDetector(min_connections=12)
    packets: List[PacketInfo] = []
    for beat in every(60.0, 11):
        # four parallel sockets opened within 0.3s, one beat
        packets += [conn(beat + i * 0.1, src_port=50000 + i) for i in range(4)]
    assert run(detector, packets) == []  # 44 SYNs, but only 11 connection events
    events = run(detector, [conn(1000.0 + 11 * 60.0 + i * 0.1, src_port=50000 + i) for i in range(4)])
    assert len(events) == 1
    assert "12 connections" in events[0].details


def test_established_session_packets_are_not_connections() -> None:
    detector = BeaconingDetector()
    # one connection, then its ACK/PSH packets at a perfectly regular beat
    packets = [conn(1000.0)] + [conn(t, tcp_flags=flags) for t in every(60.0, 30, 1060.0) for flags in ("A", "PA")]
    assert run(detector, packets) == []


def test_udp_beacon_counts_first_packet_of_each_flow() -> None:
    detector = BeaconingDetector()
    packets: List[PacketInfo] = []
    for beat in every(30.0, 12):
        # each check-in is a short UDP exchange of five packets
        packets += [conn(beat + i * 0.2, protocol="UDP", dst_port=4444) for i in range(5)]
    events = run(detector, packets)
    assert len(events) == 1
    assert f"-> {C2}:4444 every ~30s" in events[0].details
    assert "12 connections" in events[0].details


def test_continuous_udp_stream_is_one_connection() -> None:
    detector = BeaconingDetector()
    stream = [conn(1000.0 + i * 0.5, protocol="UDP", dst_port=4444) for i in range(2000)]
    assert run(detector, stream) == []
    assert len(detector._tracks[(HOST, C2, 4444)].events) == 1


def test_missed_beats_do_not_break_detection() -> None:
    times = every(60.0, 18)
    # beat 3 missing (one 120s gap), beats 6 and 7 missing (one 180s gap)
    times = [t for i, t in enumerate(times) if i not in (3, 6, 7)]
    events = run(BeaconingDetector(), beacon(times))
    assert len(events) == 1
    assert "every ~60s (jitter 0%" in events[0].details
    assert "3 missed beats" in events[0].details


def test_single_outlier_connection_does_not_break_detection() -> None:
    times = every(60.0, 13)
    times.insert(5, times[4] + 20.0)  # one manual visit between two beats
    events = run(BeaconingDetector(), beacon(times))
    assert len(events) == 1
    assert "every ~60s (jitter 0%" in events[0].details
    assert "2 irregular intervals ignored" in events[0].details


def test_intervals_below_min_interval_are_ignored() -> None:
    detector = BeaconingDetector(min_interval_seconds=5.0)
    assert run(detector, beacon(every(2.0, 200))) == []


def test_intervals_above_max_interval_are_ignored() -> None:
    detector = BeaconingDetector(max_interval_seconds=900.0, observation_window_seconds=86400.0)
    assert run(detector, beacon(every(1200.0, 40))) == []


def test_out_of_range_gap_is_skipped_not_counted_against_the_beat() -> None:
    detector = BeaconingDetector(observation_window_seconds=7200.0)
    times = every(60.0, 8) + every(60.0, 8, start=1000.0 + 7 * 60.0 + 2000.0)
    events = run(detector, beacon(times))
    assert len(events) == 1
    assert "irregular" not in events[0].details


def test_ignored_ports_are_skipped() -> None:
    detector = BeaconingDetector(ignore_ports=[53, 123, 8443])
    packets = beacon(every(60.0, 20), protocol="UDP", dst_port=123)
    packets += beacon(every(60.0, 20), dst_port=8443)
    # replies from a DNS server land on an ephemeral port, but come from 53
    packets += beacon(every(60.0, 20), protocol="UDP", src_ip=C2, dst_ip=HOST, src_port=53, dst_port=40000)
    assert run(detector, packets) == []


def test_default_ignore_ports() -> None:
    detector = BeaconingDetector()
    for port in (53, 123, 67, 68, 5353, 1900):
        assert run(detector, beacon(every(60.0, 20), protocol="UDP", dst_port=port)) == []


def test_ignored_destinations_are_skipped() -> None:
    detector = BeaconingDetector(ignore_destinations=["45.33.12.0/24"])
    assert run(detector, beacon(every(60.0, 20))) == []
    # a destination outside the ignored range is still checked
    assert len(run(detector, beacon(every(60.0, 20), dst_ip=OTHER_C2))) == 1


def test_private_to_private_skipped_unless_include_internal() -> None:
    internal = beacon(every(60.0, 20), dst_ip="192.168.1.10")
    multicast = beacon(every(60.0, 20), protocol="UDP", dst_ip="239.255.255.250", dst_port=3702)
    assert run(BeaconingDetector(), internal + multicast) == []
    events = run(BeaconingDetector(include_internal=True), internal)
    assert len(events) == 1
    assert "-> 192.168.1.10:443" in events[0].details


def test_public_source_is_checked() -> None:
    # e.g. NetSentry running on a host with a public address
    events = run(BeaconingDetector(), beacon(every(60.0, 12), src_ip="45.33.50.1"))
    assert [e.source_ip for e in events] == ["45.33.50.1"]


def test_whitelisted_source_is_skipped(in_memory_db: Database) -> None:
    engine = DetectionEngine(in_memory_db, [BeaconingDetector()], whitelist=["192.168.1.0/24"])
    for packet in beacon(every(60.0, 20)):
        engine.handle_packet(packet)
    assert in_memory_db.get_events() == []
    # the same traffic from a host that isn't whitelisted does alert
    for packet in beacon(every(60.0, 20), src_ip="10.0.0.5"):
        engine.handle_packet(packet)
    assert [(e.event_type, e.source_ip) for e in in_memory_db.get_events()] == [("BEACONING", "10.0.0.5")]


def test_old_timestamps_expire() -> None:
    detector = BeaconingDetector(observation_window_seconds=3600.0)
    assert run(detector, beacon(every(60.0, 11))) == []
    # back after more than an hour: the old connections have aged out, so
    # these few don't complete a 12-connection series with them
    later = every(60.0, 5, start=1000.0 + 10 * 60.0 + 4000.0)
    assert run(detector, beacon(later)) == []
    assert len(detector._tracks[(HOST, C2, 443)].events) == 5


def test_idle_triples_expire() -> None:
    detector = BeaconingDetector(observation_window_seconds=3600.0)
    run(detector, [conn(1000.0, dst_ip=C2)])
    run(detector, [conn(1000.0 + 3601.0, dst_ip=OTHER_C2)])
    assert list(detector._tracks) == [(HOST, OTHER_C2, 443)]


def test_evaluation_is_throttled() -> None:
    def count_evaluations(evaluate_every: float) -> int:
        detector = BeaconingDetector(
            min_interval_seconds=5.0, evaluate_every_seconds=evaluate_every
        )
        calls = []
        detector._measure = lambda events: calls.append(events)  # type: ignore[method-assign]
        run(detector, beacon(every(5.0, 60, start=0.0)))
        return len(calls)

    # connections 12..60 arrive at t=55..295; with a 30s throttle only
    # t=55, 85, ..., 295 are evaluated
    assert count_evaluations(30.0) == 9
    assert count_evaluations(0.0) == 49


def test_cooldown_is_per_triple() -> None:
    detector = BeaconingDetector(cooldown=600.0)
    packets: List[PacketInfo] = []
    for t in every(60.0, 40):
        packets += [conn(t, dst_ip=C2), conn(t + 0.5, dst_ip=OTHER_C2)]
    events = run(detector, packets)
    # each beacon alerts at its 12th connection and again every 600s after,
    # and one beacon's cooldown never hides the other
    per_destination = [sum(f"-> {dst}:" in e.details for e in events) for dst in (C2, OTHER_C2)]
    assert per_destination == [3, 3]


def test_tracked_triples_and_events_are_capped() -> None:
    detector = BeaconingDetector()
    detector.MAX_TRACKED_KEYS = 100
    detector._max_events = 50
    # scanning one host across many ports...
    run(detector, [conn(1000.0 + i * 0.001, dst_port=1000 + i) for i in range(1000)])
    assert len(detector._tracks) <= 100
    # ...and one triple connecting a lot
    run(detector, beacon(every(10.0, 300, start=2000.0), dst_port=9999))
    assert len(detector._tracks[(HOST, C2, 9999)].events) <= 50


def test_beaconing_is_registered_everywhere() -> None:
    assert "BEACONING" in CRITICAL_EVENT_TYPES
    assert EVENT_SEVERITY["BEACONING"] == "high"
    assert "BEACONING" in EVENT_TYPES
    assert "beaconing" in DETECTOR_NAMES
    detectors = build_detectors(Config(), enabled=["beaconing"])
    assert [type(d) for d in detectors] == [BeaconingDetector]


def test_config_section_is_passed_through(tmp_path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
beaconing:
  min_connections: 20
  max_jitter_ratio: 0.1
  ignore_ports: [8443]
  ignore_destinations: ["45.33.12.0/24"]
  include_internal: true
  cooldown: 120
""",
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.beaconing.enabled is True
    assert config.beaconing.observation_window_seconds == 3600
    (detector,) = [d for d in build_detectors(config) if isinstance(d, BeaconingDetector)]
    assert detector.min_connections == 20
    assert detector.max_jitter_ratio == 0.1
    assert detector.ignore_ports == {8443}
    assert detector.include_internal is True
    assert detector.cooldown == 120
    assert run(detector, beacon(every(60.0, 25))) == []  # ignored destination


def _live_pipeline_config() -> Config:
    config = Config()
    config.auto_block.enabled = True
    config.auto_block.dry_run = False  # live: would really call the firewall
    config.auto_block.min_severity = "high"
    config.threat_intel.enabled = True
    config.threat_intel.min_severity = "high"
    config.threat_intel.abuseipdb.enabled = True
    config.threat_intel.abuseipdb.api_key = "abuse-key"
    return config


def test_internal_source_flows_through_pipeline_but_is_never_blocked(in_memory_db: Database) -> None:
    config = _live_pipeline_config()
    notifier = MagicMock()
    engine = DetectionEngine(
        in_memory_db,
        [BeaconingDetector()],
        notifier=notifier,
        auto_blocker=AutoBlocker(config, in_memory_db),
        threat_intel=ThreatIntelLookup(config, in_memory_db),
    )
    response = MagicMock(status_code=200)
    response.json.return_value = {"data": {"abuseConfidenceScore": 87, "totalReports": 42}}
    with patch("src.auto_block.subprocess.run") as mock_run, \
            patch("src.threat_intel.requests.get", return_value=response) as mock_get:
        for packet in beacon(every(60.0, 12)):
            engine.handle_packet(packet)
    events = in_memory_db.get_events()
    assert [(e.event_type, e.source_ip) for e in events] == [("BEACONING", HOST)]
    assert notifier.notify.call_count == 1
    # the existing auto_block / threat intel rules: private sources are
    # never blocked or looked up -- but the C2 destination is looked up
    mock_run.assert_not_called()
    assert [c.kwargs["params"]["ipAddress"] for c in mock_get.call_args_list] == [C2]
    assert events[0].details.endswith(f"[destination {C2}: AbuseIPDB: 87% confidence, 42 reports]")
    assert in_memory_db.get_blocked_ips() == []


def test_public_source_follows_the_normal_auto_block_rules(in_memory_db: Database) -> None:
    config = _live_pipeline_config()
    config.threat_intel.enabled = False
    engine = DetectionEngine(
        in_memory_db, [BeaconingDetector()], auto_blocker=AutoBlocker(config, in_memory_db)
    )
    with patch("src.auto_block.platform.system", return_value="Linux"), \
            patch("src.auto_block.subprocess.run") as mock_run:
        for packet in beacon(every(60.0, 12), src_ip="45.33.50.1"):
            engine.handle_packet(packet)
    mock_run.assert_called_once()
    assert "45.33.50.1" in mock_run.call_args[0][0]
