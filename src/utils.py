"""Random small helpers that didn't really belong anywhere else."""

from __future__ import annotations

from datetime import datetime, timezone


def to_datetime(epoch_seconds: float) -> datetime:
    """epoch float -> UTC datetime. scapy gives us epoch timestamps, but the
    db/events want real datetime objects, so this bridges the two."""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
