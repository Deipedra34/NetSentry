"""Tests for the persistent session secret key in :mod:`src.auth`."""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from src import auth


def test_key_is_created_once_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "data" / "secret_key"  # parent folder doesn't exist yet
    first = auth.load_or_create_secret_key(path)
    assert path.exists()
    assert len(first) >= auth.SECRET_KEY_BYTES
    assert path.read_bytes() == first

    second = auth.load_or_create_secret_key(path)
    assert second == first


def test_keys_differ_between_installs(tmp_path: Path) -> None:
    assert auth.load_or_create_secret_key(tmp_path / "a") != auth.load_or_create_secret_key(tmp_path / "b")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_key_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "secret_key"
    auth.load_or_create_secret_key(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_short_existing_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "secret_key"
    path.write_bytes(b"too-short")
    with pytest.raises(RuntimeError, match="shorter than"):
        auth.load_or_create_secret_key(path)
    assert path.read_bytes() == b"too-short"  # never silently replaced


def test_key_is_never_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        key = auth.load_or_create_secret_key(tmp_path / "secret_key")
    assert key.hex() not in caplog.text
    assert repr(key) not in caplog.text
