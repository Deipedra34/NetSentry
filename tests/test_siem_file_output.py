"""Tests for :mod:`src.siem.file_output`, in temporary directories only."""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src.siem.file_output import FileTransport
from src.siem.sender import STATE_RETRYING, DestinationSender
from tests.siem_helpers import FakeClock


def _line(n: int) -> bytes:
    return json.dumps({"n": n, "pad": "x" * 80}).encode("utf-8")


def test_one_event_per_line_with_lf_endings(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    transport = FileTransport(str(path))
    transport.send(b'{"a":1}')
    transport.send(b'{"b":"\xc3\xa9"}')
    transport.close()
    assert path.read_bytes() == b'{"a":1}\n{"b":"\xc3\xa9"}\n'


def test_the_directory_is_created(tmp_path: Path) -> None:
    path = tmp_path / "siem" / "nested" / "events.ndjson"
    transport = FileTransport(str(path))
    transport.send(b"{}")
    transport.close()
    assert path.read_bytes() == b"{}\n"


def test_appends_to_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"old":true}\n')
    transport = FileTransport(str(path))
    transport.send(b'{"new":true}')
    transport.close()
    assert path.read_bytes() == b'{"old":true}\n{"new":true}\n'


def test_rotation_keeps_backup_count_old_files(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    # about 10 lines per file
    transport = FileTransport(str(path), max_size_mb=1000 / (1024 * 1024), backup_count=2)
    for n in range(100):
        transport.send(_line(n))
    transport.close()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["events.ndjson", "events.ndjson.1", "events.ndjson.2"]
    for name in ("events.ndjson", "events.ndjson.1", "events.ndjson.2"):
        content = (tmp_path / name).read_bytes()
        assert len(content) <= 1100
        for line in content.splitlines():
            json.loads(line)  # never a split line
    newest = [json.loads(line)["n"] for line in path.read_bytes().splitlines()]
    assert newest[-1] == 99


def test_backup_count_zero_starts_the_file_over(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    transport = FileTransport(str(path), max_size_mb=1000 / (1024 * 1024), backup_count=0)
    for n in range(100):
        transport.send(_line(n))
    transport.close()
    assert [p.name for p in tmp_path.iterdir()] == ["events.ndjson"]
    assert path.stat().st_size <= 1100
    assert json.loads(path.read_bytes().splitlines()[-1])["n"] == 99


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_the_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    transport = FileTransport(str(path))
    transport.send(b"{}")
    transport.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_target_shows_only_the_file_name(tmp_path: Path) -> None:
    transport = FileTransport(str(tmp_path / "private" / "events.ndjson"))
    assert transport.target == "events.ndjson"


def test_a_full_disk_raises_instead_of_printing(tmp_path: Path) -> None:
    transport = FileTransport(str(tmp_path / "events.ndjson"))
    transport.send(b"{}")
    with patch.object(transport._sock.stream, "write", side_effect=OSError(28, "No space left on device")):
        with pytest.raises(OSError, match="No space left on device"):
            transport.send(b'{"lost":true}')
    assert not transport.connected


class _FullDisk:
    """A file stream whose every write fails like a full disk."""

    def write(self, text: str) -> int:
        raise OSError(28, "No space left on device")

    def flush(self) -> None:
        pass

    def tell(self) -> int:
        return 0

    def seek(self, *args: Any) -> int:
        return 0

    def close(self) -> None:
        pass


def test_a_full_disk_never_crashes_the_sender(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    transport = FileTransport(str(tmp_path / "events.ndjson"))
    sender = DestinationSender("wazuh", transport, lambda record: json.dumps(record).encode(), clock=clock)
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        with patch("src.siem.file_output._EventFileHandler._open", return_value=_FullDisk()):
            for n in range(10):
                sender.submit({"n": n})
                clock.advance(120)
                sender.step()
        assert sender.state == STATE_RETRYING
        assert sender.last_error == "No space left on device"
        # the disk has room again
        clock.advance(120)
        while sender.step():
            pass
    assert sender.queued == 0
    lines = [json.loads(line)["n"] for line in (tmp_path / "events.ndjson").read_bytes().splitlines()]
    # events given up on after repeated failed writes are counted, not lost silently
    assert len(lines) + sender.failed == 10
    assert lines == sorted(lines)
    outage_lines = [r for r in caplog.records if "cannot deliver" in r.getMessage()]
    assert len(outage_lines) == 1  # logged once, not once per failed write
