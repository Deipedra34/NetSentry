"""Tests for main.py's --siem-test: one synthetic, clearly labeled event per
destination, a result line for each, and no packet capture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List
from unittest.mock import MagicMock, patch

import pytest
import yaml

import main
from tests.siem_helpers import Collector, UdpCollector, make_pki, split_octet_counted


@pytest.fixture(autouse=True)
def no_capture() -> Iterator[MagicMock]:
    """Fails loudly if anything tries to start capture, open the database or
    build detectors, and keeps setup_logging from reconfiguring logging."""
    with patch("main.NetworkSniffer") as sniffer, patch("main.build_detectors") as detectors, \
            patch("main.Database") as database, patch("main.setup_logging"):
        yield sniffer
        sniffer.assert_not_called()
        detectors.assert_not_called()
        database.assert_not_called()


def _write_config(tmp_path: Path, destinations: List[Dict[str, Any]], enabled: bool = True) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump({"siem": {"enabled": enabled, "hostname": "sensor-1", "destinations": destinations}}),
        encoding="utf-8",
    )
    return path


def _lines(output: str) -> List[str]:
    return [line.strip() for line in output.splitlines() if line.strip().startswith("[")]


def test_sends_one_labeled_event_to_every_destination(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    udp = UdpCollector()
    tcp = Collector()
    try:
        config = _write_config(tmp_path, [
            {"name": "syslog", "format": "rfc5424", "transport": "udp", "host": "127.0.0.1", "port": udp.port},
            {"name": "arcsight", "format": "cef", "transport": "tcp", "host": "127.0.0.1", "port": tcp.port},
            {"name": "wazuh", "format": "json", "transport": "file", "path": str(tmp_path / "siem" / "events.ndjson")},
        ])
        assert main.main(["-c", str(config), "--siem-test"]) == 0
        assert udp.wait_for(1)
        assert tcp.wait_for(lambda c: len(c.messages()) == 1)
    finally:
        udp.stop()
        tcp.stop()

    output = capsys.readouterr().out
    assert "synthetic 'siem_test' event (not a real detection) to 3 destination(s)" in output
    assert _lines(output) == [
        f"[OK] syslog (rfc5424 over udp to 127.0.0.1:{udp.port}): sent (UDP: delivery is not confirmed)",
        f"[OK] arcsight (cef over tcp to 127.0.0.1:{tcp.port}): sent",
        "[OK] wazuh (json over file to events.ndjson): sent",
    ]
    assert "siem.enabled is false" not in output

    # every format carries the test label
    assert b" siem_test " in udp.datagrams[0]
    assert b'test="true"' in udp.datagrams[0]
    cef = tcp.messages()[0]
    assert b"|siem_test|SIEM test|" in cef and b"cs6=test" in cef
    document = json.loads((tmp_path / "siem" / "events.ndjson").read_bytes())
    assert document["event_type"] == "siem_test"
    assert document["test"] is True
    assert "not a real detection" in document["details"]


def test_reports_each_failure_and_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pki = make_pki(tmp_path)
    tls = Collector(context=pki.server_context())
    refused = Collector()
    refused_port = refused.port
    refused.stop()
    try:
        config = _write_config(tmp_path, [
            {"name": "down", "format": "rfc5424", "transport": "tcp", "host": "127.0.0.1", "port": refused_port},
            # the certificate is for "localhost", not 127.0.0.1
            {"name": "elastic", "format": "json", "transport": "tls", "host": "127.0.0.1", "port": tls.port,
             "ca_file": str(pki.ca_file)},
            {"name": "typo", "format": "leef", "transport": "udp", "host": "x"},
        ])
        assert main.main(["-c", str(config), "--siem-test"]) == 1
    finally:
        tls.stop()

    lines = _lines(capsys.readouterr().out)
    assert lines[0].startswith("[FAILED] (invalid): siem destination 'typo' is invalid and skipped")
    assert lines[1] == f"[FAILED] down (rfc5424 over tcp to 127.0.0.1:{refused_port}): connection refused"
    assert lines[2].startswith(
        f"[FAILED] elastic (json over tls to 127.0.0.1:{tls.port}): TLS certificate verification failed"
    )


def test_unverified_tls_is_flagged_in_the_result(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pki = make_pki(tmp_path)
    tls = Collector(context=pki.server_context())
    try:
        config = _write_config(tmp_path, [
            {"name": "lab", "format": "cef", "transport": "tls", "host": "127.0.0.1", "port": tls.port, "verify": False},
        ])
        assert main.main(["-c", str(config), "--siem-test"]) == 0
        assert tls.wait_for(lambda c: len(split_octet_counted(c.data)) == 1)
    finally:
        tls.stop()
    assert _lines(capsys.readouterr().out) == [
        f"[OK] lab (cef over tls to 127.0.0.1:{tls.port}): sent (WARNING: certificate not verified)"
    ]


def test_works_before_siem_is_enabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _write_config(
        tmp_path,
        [{"name": "file", "format": "rfc5424", "transport": "file", "path": str(tmp_path / "events.log")}],
        enabled=False,
    )
    assert main.main(["-c", str(config), "--siem-test"]) == 0
    output = capsys.readouterr().out
    assert "[OK] file" in output
    assert "siem.enabled is false, so events are not forwarded during capture yet" in output
    assert b"siem_test" in (tmp_path / "events.log").read_bytes()


def test_no_destinations(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main.main(["-c", str(_write_config(tmp_path, [])), "--siem-test"]) == 1
    assert "No SIEM destinations are configured" in capsys.readouterr().out


def test_starts_no_sender_threads(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path, [{"name": "f", "format": "json", "transport": "file", "path": str(tmp_path / "e.ndjson")}]
    )
    with patch("src.siem.sender.DestinationSender.start") as start:
        assert main.main(["-c", str(config), "--siem-test"]) == 0
    start.assert_not_called()
