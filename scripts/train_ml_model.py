#!/usr/bin/env python3
"""Offline trainer for NetSentry's MLAnomalyDetector (src/detectors.py).

Trains an IsolationForest or RandomForestClassifier on per-source-IP traffic
feature vectors (src/ml_features.py) and saves the result with joblib to
`ml_anomaly.model_path` (data/ml_model.joblib by default). This script is
completely standalone -- it never imports src.engine or src.sniffer's live
capture loop, and NetSentry itself never imports this script, so it has no
effect on startup whether or not `ml_anomaly.enabled` is true.

Two ways to build the training dataset:

  --csv PATH
      A CSV whose columns match src.ml_features.FEATURE_NAMES exactly, plus
      an optional 'label' column (0 = normal, 1 = anomalous) for supervised
      random_forest training. This is the most direct option: whatever
      produced the CSV controls the feature values exactly, so there's no
      ambiguity about whether they match what MLAnomalyDetector scores at
      runtime.

  --db PATH (+ --pcap-dir DIR)
      Reuses src/database.py's existing `events` table -- NOT a new schema
      -- but only for *labels*: it treats any source IP that ever triggered
      a logged event as a weak positive example. src/database.py's schema
      deliberately doesn't store raw per-packet traffic (see its `events`
      table: timestamp/source_ip/event_type/details only), so there's no
      way to derive real packet-rate/port-fan-out/etc. features from the
      database alone. The actual feature vectors come from replaying the
      .pcap files NetSentry's own pcap_export feature already writes
      (captures/ by default) through the exact same src/ml_features.py
      extraction MLAnomalyDetector uses at inference time, via
      src/sniffer.py's parse_packet -- so this mode needs some traffic
      already captured with `pcap_export.enabled: true` (see README.md).

For IsolationForest, training is unsupervised -- labels are ignored even if
present. For RandomForestClassifier, labels are required and both classes
(0 and 1) must be present.

Usage:
    python scripts/train_ml_model.py --csv training_features.csv
    python scripts/train_ml_model.py --db netsentry.db --pcap-dir captures/
    python scripts/train_ml_model.py --csv features.csv --algorithm random_forest
"""

from __future__ import annotations

import argparse
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

# Allow `import src...` when run directly as `python scripts/train_ml_model.py`
# from anywhere, the same way tests/conftest.py does for the test suite.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib  # noqa: E402

from src import ml_features  # noqa: E402
from src.config import load_config  # noqa: E402

Dataset = Tuple[List[List[float]], Optional[List[int]]]


def _load_csv_dataset(csv_path: str) -> Dataset:
    """Reads a CSV of pre-extracted features. Columns must match
    ml_features.FEATURE_NAMES; an optional 'label' column (0/1) enables
    supervised random_forest training."""
    import csv

    with open(csv_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        missing = [name for name in ml_features.FEATURE_NAMES if name not in fieldnames]
        if missing:
            raise SystemExit(
                f"{csv_path} is missing required feature column(s): {missing}. "
                f"Expected columns: {ml_features.FEATURE_NAMES} (+ optional 'label')."
            )
        has_label = "label" in fieldnames

        X: List[List[float]] = []
        y: Optional[List[int]] = [] if has_label else None
        for row in reader:
            X.append([float(row[name]) for name in ml_features.FEATURE_NAMES])
            if has_label and y is not None:
                y.append(int(row["label"]))

    if not X:
        raise SystemExit(f"{csv_path} has no data rows.")
    return X, y


def _build_dataset_from_pcaps_and_db(pcap_dir: str, db_path: str, window_seconds: float) -> Dataset:
    """Builds real feature vectors from captured .pcap files (via the exact
    same extraction MLAnomalyDetector uses at inference), weakly labeled by
    whether the producing source IP ever triggered a logged event in the
    database. See the module docstring for why this needs pcap files rather
    than reading features out of the database directly."""
    from scapy.utils import rdpcap

    from src import sniffer
    from src.database import Database

    pcap_files = sorted(Path(pcap_dir).glob("*.pcap")) + sorted(Path(pcap_dir).glob("*.pcapng"))
    if not pcap_files:
        raise SystemExit(
            f"No .pcap/.pcapng files found in {pcap_dir}. Enable pcap_export "
            "and capture some traffic first (see README.md 'PCAP Export'), "
            "or use --csv with pre-extracted features instead."
        )

    db = Database(db_path)
    try:
        event_ips = {event.source_ip for event in db.get_events(limit=1_000_000)}
    finally:
        db.close()

    windows = ml_features.SourceIPFeatureWindows(window_seconds)
    X: List[List[float]] = []
    y: List[int] = []
    for pcap_file in pcap_files:
        for raw_packet in rdpcap(str(pcap_file)):
            info = sniffer.parse_packet(raw_packet)
            if info is None:
                continue
            vector = windows.add_packet(info)
            if vector is None:
                continue
            X.append(vector)
            y.append(1 if info.src_ip in event_ips else 0)

    if not X:
        raise SystemExit(
            f"No source IP in {pcap_dir} produced a full {window_seconds:.0f}s "
            "window of traffic -- capture more traffic and try again."
        )
    return X, y


def _feature_stats(X: Sequence[Sequence[float]]) -> Tuple[List[float], List[float]]:
    """Per-feature mean/std across the whole training set, stored in the
    model bundle so MLAnomalyDetector can report which raw features were
    most unusual (z-score) alongside an anomaly score."""
    columns = list(zip(*X))
    mean = [statistics.fmean(column) for column in columns]
    std = [statistics.pstdev(column) for column in columns]
    return mean, std


def train(
    X: List[List[float]],
    y: Optional[List[int]],
    algorithm: str,
    contamination: float,
) -> object:
    """Fits and returns the model, printing the summary stats the task asks
    for along the way."""
    print(f"Training samples: {len(X)}, features per sample: {len(ml_features.FEATURE_NAMES)}")

    if algorithm == "isolation_forest":
        from sklearn.ensemble import IsolationForest

        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(X)
        predictions = model.predict(X)
        anomaly_count = int(sum(1 for p in predictions if p == -1))
        print(f"Algorithm: IsolationForest (contamination={contamination})")
        print(f"Anomalies flagged in training set: {anomaly_count}/{len(X)}")
        return model

    if algorithm == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, precision_score, recall_score
        from sklearn.model_selection import train_test_split

        if y is None or len(set(y)) < 2:
            raise SystemExit(
                "random_forest requires labeled data with both classes (0 and 1) "
                "present -- provide a CSV with a 'label' column, or use --db mode "
                "with traffic that includes both clean periods and logged events."
            )

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        model = RandomForestClassifier(random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        print("Algorithm: RandomForestClassifier")
        print(
            f"Test set ({len(X_test)} samples): "
            f"accuracy={accuracy_score(y_test, y_pred):.3f} "
            f"precision={precision_score(y_test, y_pred, zero_division=0):.3f} "
            f"recall={recall_score(y_test, y_pred, zero_division=0):.3f}"
        )
        return model

    raise SystemExit(f"Unknown algorithm {algorithm!r} (expected isolation_forest or random_forest)")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="train_ml_model",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--csv", help="CSV of pre-extracted features (see module docstring).")
    source.add_argument(
        "--db",
        help="Path to NetSentry's SQLite database, used for labels (default: config.yaml's database.path).",
    )
    parser.add_argument(
        "--pcap-dir",
        help="Directory of .pcap files to build features from, used with --db (default: config.yaml's pcap_export.output_dir).",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config.yaml, used for defaults not given on the CLI (default: config.yaml).",
    )
    parser.add_argument(
        "--model-path",
        help="Where to save the trained model (default: config.yaml's ml_anomaly.model_path).",
    )
    parser.add_argument(
        "--algorithm",
        choices=["isolation_forest", "random_forest"],
        help="Model to train (default: config.yaml's ml_anomaly.algorithm).",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        help="Expected proportion of anomalous traffic, IsolationForest only (default: config.yaml's ml_anomaly.contamination).",
    )
    parser.add_argument(
        "--feature-window-seconds",
        type=float,
        help="Size of the per-source-IP feature window in seconds (default: config.yaml's ml_anomaly.feature_window_seconds).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    config = load_config(args.config)

    algorithm = args.algorithm or config.ml_anomaly.algorithm
    contamination = args.contamination if args.contamination is not None else config.ml_anomaly.contamination
    model_path = args.model_path or config.ml_anomaly.model_path
    window_seconds = args.feature_window_seconds or config.ml_anomaly.feature_window_seconds

    if args.csv:
        X, y = _load_csv_dataset(args.csv)
        source_desc = f"CSV file {args.csv}"
    else:
        db_path = args.db or config.database.path
        pcap_dir = args.pcap_dir or config.pcap_export.output_dir
        X, y = _build_dataset_from_pcaps_and_db(pcap_dir, db_path, window_seconds)
        source_desc = f"database {db_path} + pcaps in {pcap_dir}"

    if len(X) < 2:
        raise SystemExit(f"Not enough training samples ({len(X)}) from {source_desc} -- capture more traffic first.")

    print(f"Data source: {source_desc}")
    model = train(X, y, algorithm, contamination)
    feature_mean, feature_std = _feature_stats(X)

    bundle = {
        "algorithm": algorithm,
        "model": model,
        "feature_names": list(ml_features.FEATURE_NAMES),
        "feature_mean": feature_mean,
        "feature_std": feature_std,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": len(X),
    }

    output_path = Path(model_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    print(f"Saved model to {output_path}")


if __name__ == "__main__":
    main()
