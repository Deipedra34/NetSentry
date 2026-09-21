"""Unit tests for :mod:`src.ml_features` and
:class:`src.detectors.MLAnomalyDetector`.

Models used here are tiny synthetic IsolationForest/RandomForestClassifier
instances fit on a handful of hand-built feature vectors -- fast enough to
fit inline in a test, and never touching the real training pipeline in
scripts/train_ml_model.py.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

import joblib
import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from src import ml_features
from src.detectors import MLAnomalyDetector
from tests.conftest import make_packet

WINDOW_SECONDS = 2.0

# Center of the "normal" traffic cluster and a clearly different "outlier"
# vector, both expressed directly as FEATURE_NAMES-shaped vectors.
NORMAL_VECTOR = [2.5, 1.0, 1.0, 500.0, 1.0, 0.0, 0.0, 0.0]
OUTLIER_VECTOR = [50.0, 80.0, 1.0, 40.0, 1.0, 0.0, 0.0, 1.0]


def _burst(
    src_ip: str, count: int, *, dst_port_start: int, length: int, syn: bool, start: float = 0.0
) -> List:
    """count packets spread evenly over [start, start + WINDOW_SECONDS), plus
    one packet right at the window boundary to close it out. Distinct
    destination ports per packet when dst_port_start is not fixed."""
    step = WINDOW_SECONDS / count
    packets = [
        make_packet(
            timestamp=start + i * step,
            src_ip=src_ip,
            dst_ip="203.0.113.1",
            protocol="TCP",
            dst_port=dst_port_start if dst_port_start == 80 else dst_port_start + i,
            tcp_flags="S" if syn else "A",
            length=length,
        )
        for i in range(count)
    ]
    # closes the window: arrives >= WINDOW_SECONDS after the first packet
    packets.append(
        make_packet(
            timestamp=start + WINDOW_SECONDS,
            src_ip=src_ip,
            dst_ip="203.0.113.1",
            protocol="TCP",
            dst_port=dst_port_start,
            tcp_flags="A",
            length=length,
        )
    )
    return packets


def normal_burst(src_ip: str = "10.0.0.5", start: float = 0.0) -> List:
    """5 packets/2s, one port, one dest, 500-byte packets, no SYNs --
    matches NORMAL_VECTOR."""
    return _burst(src_ip, count=5, dst_port_start=80, length=500, syn=False, start=start)


def outlier_burst(src_ip: str = "10.0.0.99", start: float = 0.0) -> List:
    """100 packets/2s fanned out across 80+ ports, small SYN packets --
    matches OUTLIER_VECTOR (port-scan-ish, high rate, all SYNs)."""
    return _burst(src_ip, count=100, dst_port_start=1, length=40, syn=True, start=start)


def _fit_isolation_forest_bundle(tmp_path: Path) -> Tuple[str, float]:
    """Fits a tiny IsolationForest on jittered copies of NORMAL_VECTOR,
    scores OUTLIER_VECTOR against it, and picks a threshold squarely between
    the two so the test doesn't depend on exact sklearn-version scoring
    internals -- only on the (well-established) fact that IsolationForest
    ranks a far-out point below a tight normal cluster."""
    import random

    rng = random.Random(0)
    normal_samples = [
        [
            NORMAL_VECTOR[0] + rng.uniform(-0.2, 0.2),
            NORMAL_VECTOR[1],
            NORMAL_VECTOR[2],
            NORMAL_VECTOR[3] + rng.uniform(-5, 5),
            NORMAL_VECTOR[4],
            NORMAL_VECTOR[5],
            NORMAL_VECTOR[6],
            NORMAL_VECTOR[7],
        ]
        for _ in range(40)
    ]

    model = IsolationForest(contamination=0.02, random_state=1, n_estimators=300)
    model.fit(normal_samples)

    normal_scores = model.decision_function(normal_samples)
    outlier_score = model.decision_function([OUTLIER_VECTOR])[0]
    assert outlier_score < min(normal_scores), "test fixture must separate cleanly"
    threshold = (min(normal_scores) + outlier_score) / 2

    bundle = {
        "algorithm": "isolation_forest",
        "model": model,
        "feature_names": ml_features.FEATURE_NAMES,
        "feature_mean": [sum(c) / len(c) for c in zip(*normal_samples)],
        "feature_std": [0.1] * ml_features.FEATURE_COUNT,
    }
    model_path = tmp_path / "ml_model.joblib"
    joblib.dump(bundle, model_path)
    return str(model_path), threshold


# ---------------------------------------------------------------------------
# src.ml_features
# ---------------------------------------------------------------------------


def test_feature_vector_has_expected_shape() -> None:
    windows = ml_features.SourceIPFeatureWindows(WINDOW_SECONDS, min_packets=3)
    vector = None
    for packet in normal_burst():
        vector = windows.add_packet(packet) or vector

    assert vector is not None
    assert len(vector) == len(ml_features.FEATURE_NAMES) == ml_features.FEATURE_COUNT


def test_feature_vector_values_match_synthetic_traffic() -> None:
    windows = ml_features.SourceIPFeatureWindows(WINDOW_SECONDS, min_packets=3)
    vector = None
    for packet in normal_burst():
        vector = windows.add_packet(packet) or vector

    assert vector == pytest.approx(NORMAL_VECTOR)


def test_window_below_min_packets_is_dropped() -> None:
    windows = ml_features.SourceIPFeatureWindows(WINDOW_SECONDS, min_packets=10)
    vector = None
    for packet in normal_burst():  # only 5 packets, below min_packets=10
        vector = windows.add_packet(packet) or vector
    assert vector is None


def test_windows_are_isolated_per_source_ip() -> None:
    # normal_burst has 6 packets (5 traffic + 1 closer); outlier_burst has
    # 101 (100 + 1 closer). zip() truncates to 6 pairs, so source A's window
    # closes on the 6th pair while source B's (still mid-burst) doesn't --
    # and A's result must be unaffected by B's very different traffic.
    windows = ml_features.SourceIPFeatureWindows(WINDOW_SECONDS, min_packets=3)
    results = []
    for packet_a, packet_b in zip(normal_burst("10.0.0.1"), outlier_burst("10.0.0.2")):
        results.append(windows.add_packet(packet_a))
        results.append(windows.add_packet(packet_b))

    assert all(result is None for result in results[:-2])
    assert results[-1] is None  # source B's window is still open
    assert results[-2] == pytest.approx(NORMAL_VECTOR)  # source A's, unaffected by B


# ---------------------------------------------------------------------------
# MLAnomalyDetector
# ---------------------------------------------------------------------------


def test_detector_loads_model_and_does_not_flag_normal_traffic(tmp_path: Path) -> None:
    model_path, threshold = _fit_isolation_forest_bundle(tmp_path)
    detector = MLAnomalyDetector(
        model_path=model_path,
        feature_window_seconds=WINDOW_SECONDS,
        anomaly_score_threshold=threshold,
    )

    events = []
    for packet in normal_burst():
        events.extend(detector.process_packet(packet))

    assert events == []


def test_event_generated_when_feature_vector_crosses_threshold(tmp_path: Path) -> None:
    model_path, threshold = _fit_isolation_forest_bundle(tmp_path)
    detector = MLAnomalyDetector(
        model_path=model_path,
        feature_window_seconds=WINDOW_SECONDS,
        anomaly_score_threshold=threshold,
    )

    events = []
    for packet in outlier_burst():
        events.extend(detector.process_packet(packet))

    assert len(events) == 1
    assert events[0].event_type == "ML_ANOMALY"
    assert events[0].source_ip == "10.0.0.99"
    assert "score" in events[0].details


def test_cooldown_suppresses_repeat_alerts(tmp_path: Path) -> None:
    model_path, threshold = _fit_isolation_forest_bundle(tmp_path)
    detector = MLAnomalyDetector(
        model_path=model_path,
        feature_window_seconds=WINDOW_SECONDS,
        anomaly_score_threshold=threshold,
        cooldown=1000.0,
    )

    first_events = []
    for packet in outlier_burst():
        first_events.extend(detector.process_packet(packet))
    assert len(first_events) == 1

    # A second full burst from the same source IP, starting right where the
    # first one's leftover window begins (WINDOW_SECONDS), should still be
    # suppressed by the cooldown even though it closes its own new window.
    second_events = []
    for packet in outlier_burst(start=WINDOW_SECONDS):
        second_events.extend(detector.process_packet(packet))
    assert second_events == []


def test_missing_model_file_disables_detector_without_crash(tmp_path: Path, caplog) -> None:
    missing_path = tmp_path / "does_not_exist.joblib"
    with caplog.at_level(logging.WARNING, logger="netsentry.detectors"):
        detector = MLAnomalyDetector(model_path=str(missing_path), feature_window_seconds=WINDOW_SECONDS)

    events = []
    for packet in outlier_burst():
        events.extend(detector.process_packet(packet))

    assert events == []
    assert any("train_ml_model.py" in record.message for record in caplog.records)


def test_corrupt_model_file_disables_detector_without_crash(tmp_path: Path, caplog) -> None:
    bad_path = tmp_path / "corrupt.joblib"
    bad_path.write_bytes(b"not a valid joblib file")

    with caplog.at_level(logging.WARNING, logger="netsentry.detectors"):
        detector = MLAnomalyDetector(model_path=str(bad_path), feature_window_seconds=WINDOW_SECONDS)

    assert detector.process_packet(make_packet(timestamp=0.0)) == []


def test_random_forest_algorithm_scoring(tmp_path: Path) -> None:
    """Covers the random_forest branch of MLAnomalyDetector._score, which
    maps predict_proba onto the same negative-is-anomalous scale
    IsolationForest.decision_function already uses."""
    X = [NORMAL_VECTOR] * 5 + [OUTLIER_VECTOR] * 5
    y = [0] * 5 + [1] * 5
    model = RandomForestClassifier(random_state=1, n_estimators=50)
    model.fit(X, y)

    bundle = {
        "algorithm": "random_forest",
        "model": model,
        "feature_names": ml_features.FEATURE_NAMES,
    }
    model_path = tmp_path / "rf_model.joblib"
    joblib.dump(bundle, model_path)

    detector = MLAnomalyDetector(
        model_path=str(model_path),
        algorithm="random_forest",
        feature_window_seconds=WINDOW_SECONDS,
        anomaly_score_threshold=-0.5,
    )

    normal_events = []
    for packet in normal_burst():
        normal_events.extend(detector.process_packet(packet))
    assert normal_events == []

    anomaly_events = []
    for packet in outlier_burst():
        anomaly_events.extend(detector.process_packet(packet))
    assert len(anomaly_events) == 1
    assert anomaly_events[0].event_type == "ML_ANOMALY"
