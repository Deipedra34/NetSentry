"""The "file" transport: events appended to a local rotating file, one per
line, for Wazuh, Filebeat, the Splunk Universal Forwarder or any other
agent that tails a log file.

Built on the standard library's RotatingFileHandler: the file is rotated
at max_size_mb, keeping backup_count old files (0 keeps none: the file
starts over instead). The directory is created if it's missing, and on
systems with POSIX permissions the file is readable by its owner only. A
write that fails (a full disk, a read-only mount) raises like any other
transport failure, so the sender retries with backoff and logs it once
instead of crashing or flooding the log.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from src.siem.transports import Transport

# file lines aren't limited by a network protocol; this only guards
# against a runaway event
FILE_MAX_BYTES = 65536


def _restrict(path: str, mode: int) -> None:
    """chmod where the OS supports it; Windows ACLs are left alone."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class _EventFileHandler(RotatingFileHandler):
    """A RotatingFileHandler that reports write errors to its caller
    instead of printing them, and keeps its files owner-only."""

    def __init__(self, path: Path, max_bytes: int, backup_count: int) -> None:
        super().__init__(
            path, mode="a", maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8", delay=True
        )
        self.setFormatter(logging.Formatter("%(message)s"))
        self.error: Optional[BaseException] = None

    def _open(self) -> Any:
        stream = super()._open()
        _restrict(self.baseFilename, 0o600)
        return stream

    def doRollover(self) -> None:
        if self.backupCount > 0:
            super().doRollover()
            return
        # no old files to keep: start the file over
        if self.stream:
            self.stream.close()
        self.stream = open(self.baseFilename, "w", encoding="utf-8")  # noqa: SIM115
        _restrict(self.baseFilename, 0o600)

    def handleError(self, record: logging.LogRecord) -> None:
        self.error = sys.exc_info()[1]


class FileTransport(Transport):
    """Writes each message as one line of a rotating file."""

    kind = "file"
    max_bytes = FILE_MAX_BYTES

    def __init__(self, path: str, max_size_mb: float = 50, backup_count: int = 5) -> None:
        super().__init__(host="", port=0)
        self.path = Path(path)
        self.max_size_bytes = max(int(max_size_mb * 1024 * 1024), 1)
        self.backup_count = backup_count

    @property
    def target(self) -> str:
        """Only the file name: the dashboard has no business showing paths."""
        return self.path.name

    def connect(self) -> None:
        self.close()
        directory = self.path.parent
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._sock = _EventFileHandler(self.path, self.max_size_bytes, self.backup_count)

    def send(self, payload: bytes) -> None:
        if self._sock is None:
            self.connect()
        handler: _EventFileHandler = self._sock
        handler.error = None
        line = payload[: self.max_bytes].decode("utf-8", errors="replace")
        handler.emit(logging.LogRecord("netsentry.siem.file", logging.INFO, __file__, 0, line, None, None))
        if handler.error is not None:
            error = handler.error
            self.close()
            if isinstance(error, OSError):
                raise error
            raise OSError(str(error) or error.__class__.__name__) from error
