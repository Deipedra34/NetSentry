"""Unit tests for :class:`src.detectors.TrafficAnomalyDetector`.

The detector evaluates a window only once the *next* window's first packet
arrives (it is a simple tumbling-window implementation), so these tests
feed one extra trailing "flush" packet after the window(s) under test to
force evaluation of the final window.
"""

from __future__ import annotations

from typing import List, Optional

from src.detectors import TrafficAnomalyDetector
from tests.conftest import make_packet


def _feed_window(detector: TrafficAnomalyDetector, start: float, count: int, src_ip: str = "10.0.0.1"):
    """Feed `count` packets spaced within one window starting at `start`."""
    events = []
    step = (detector.window_seconds / max(count, 1)) * 0.5
    for i in range(count):
        events += detector.process_packet(make_packet(timestamp=start + i * step, src_ip=src_ip))
    return events


def _feed_windows(
    detector: TrafficAnomalyDetector,
    window_counts: List[int],
    src_ips: Optional[List[str]] = None,
):
    """Feed several consecutive windows, then flush to close the final one."""
    n = len(window_counts)
    if src_ips is None:
        src_ips = ["10.0.0.1"] * n
    events = []
    for w, (count, ip) in enumerate(zip(window_counts, src_ips)):
        events += _feed_window(detector, start=w * detector.window_seconds, count=count, src_ip=ip)
    # Force the last window closed by delivering a packet in the next one.
    events += detector.process_packet(
        make_packet(timestamp=n * detector.window_seconds, src_ip=src_ips[-1])
    )
    return events


def test_no_alert_while_baseline_is_warming_up() -> None:
    detector = TrafficAnomalyDetector(
        window_seconds=10.0, baseline_windows=6, multiplier=3.0, min_baseline_samples=3
    )
    # Only two completed windows -- fewer than min_baseline_samples, so no
    # alert should fire even though the second window is a big spike.
    events = _feed_windows(detector, window_counts=[10, 200])
    assert events == []


def test_alert_on_volume_spike_after_baseline_established() -> None:
    detector = TrafficAnomalyDetector(
        window_seconds=10.0, baseline_windows=6, multiplier=3.0, min_baseline_samples=3
    )
    # Three steady windows establish the baseline, then a large spike.
    events = _feed_windows(detector, window_counts=[10, 10, 10, 100])
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "TRAFFIC_ANOMALY"
    assert "baseline average" in event.details


def test_steady_traffic_never_triggers() -> None:
    detector = TrafficAnomalyDetector(
        window_seconds=10.0, baseline_windows=6, multiplier=3.0, min_baseline_samples=3
    )
    events = _feed_windows(detector, window_counts=[20] * 10)
    assert events == []


def test_top_source_ip_reported_in_spike() -> None:
    detector = TrafficAnomalyDetector(
        window_seconds=10.0, baseline_windows=6, multiplier=2.0, min_baseline_samples=2
    )
    events = _feed_windows(
        detector,
        window_counts=[10, 10, 80],
        src_ips=["10.0.0.5", "10.0.0.5", "10.0.0.99"],
    )
    assert len(events) == 1
    assert events[0].source_ip == "10.0.0.99"
