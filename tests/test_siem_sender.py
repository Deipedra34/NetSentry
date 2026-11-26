"""Tests for :mod:`src.siem.sender`: the bounded queue, overflow, backoff,
reconnects and shutdown. Time is a fake clock; the threaded tests use local
sockets and event-driven waits, never a fixed sleep."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List

import pytest

from src.siem.sender import (
    MAX_SEND_ATTEMPTS,
    STATE_CONNECTED,
    STATE_CONNECTING,
    STATE_RETRYING,
    STATE_STOPPED,
    Backoff,
    DestinationSender,
)
from src.siem.transports import TcpTransport, Transport
from tests.siem_helpers import Collector, FakeClock


class _FakeSocket:
    def close(self) -> None:
        pass


class FakeTransport(Transport):
    """In-memory transport whose collector can be switched off and on."""

    kind = "tcp"

    def __init__(self, up: bool = True) -> None:
        super().__init__("collector.test", 514)
        self.up = up
        self.delivered: List[bytes] = []
        self.connects = 0
        self.fail_sends = False

    def connect(self) -> None:
        self.connects += 1
        if not self.up:
            raise ConnectionRefusedError()
        self._sock = _FakeSocket()

    def send(self, payload: bytes) -> None:
        if not self.up or self.fail_sends:
            self._sock = None
            raise ConnectionResetError()
        self.delivered.append(payload)


def _render(record: Dict[str, Any]) -> bytes:
    return str(record["n"]).encode("ascii")


def _sender(transport: Transport, clock: FakeClock, **kwargs: Any) -> DestinationSender:
    return DestinationSender("test", transport, _render, clock=clock, wall_clock=lambda: 1_800_000_000.0, **kwargs)


def _drain(sender: DestinationSender) -> None:
    while sender.step():
        pass


# --- backoff -------------------------------------------------------------


def test_backoff_doubles_up_to_the_cap() -> None:
    backoff = Backoff(1.0, 60.0)
    assert [backoff.next_delay() for _ in range(9)] == [1, 2, 4, 8, 16, 32, 60, 60, 60]
    backoff.reset()
    assert backoff.next_delay() == 1


# --- delivery ------------------------------------------------------------


def test_records_are_delivered_in_order() -> None:
    transport = FakeTransport()
    sender = _sender(transport, FakeClock())
    for n in range(3):
        sender.submit({"n": n})
    assert sender.queued == 3
    _drain(sender)
    assert transport.delivered == [b"0", b"1", b"2"]
    assert (sender.sent, sender.queued, sender.state) == (3, 0, STATE_CONNECTED)
    assert sender.step() is False  # nothing left


def test_a_down_collector_backs_off_and_keeps_the_record(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    transport = FakeTransport(up=False)
    sender = _sender(transport, clock)
    sender.submit({"n": 1})

    with caplog.at_level(logging.DEBUG, logger="netsentry.siem"):
        assert sender.step() is True
        assert sender.state == STATE_RETRYING
        assert sender.last_error == "connection refused"
        assert sender.status()["last_error_at"] == "2027-01-15T08:00:00+00:00"
        # still in the 1s backoff: nothing is attempted
        assert sender.step() is False
        assert transport.connects == 1
        delays = []
        for _ in range(8):
            before = clock.now
            while not sender.step():
                clock.advance(0.5)
            delays.append(clock.now - before)
    # 1s after the first failure, then 2, 4, 8, ... capped at 60
    assert delays == [1, 2, 4, 8, 16, 32, 60, 60]
    assert sender.queued == 1  # the record is never lost to retries
    assert (sender.sent, sender.failed, sender.dropped) == (0, 0, 0)

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1  # one line for the outage, not one per retry
    assert "cannot deliver to collector.test:514 (connection refused)" in warnings[0].getMessage()


def test_connection_restored_after_an_outage(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    transport = FakeTransport()
    sender = _sender(transport, clock)
    with caplog.at_level(logging.INFO, logger="netsentry.siem"):
        sender.submit({"n": 1})
        _drain(sender)
        transport.up = False
        sender.submit({"n": 2})
        sender.submit({"n": 3})
        sender.step()
        assert sender.state == STATE_RETRYING
        for _ in range(5):
            clock.advance(60)
            sender.step()
        transport.up = True
        clock.advance(60)
        _drain(sender)

    assert transport.delivered == [b"1", b"2", b"3"]
    assert sender.state == STATE_CONNECTED
    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "SIEM destination 'test': connected to collector.test:514",
        "SIEM destination 'test': lost connection to collector.test:514 (connection lost); retrying with backoff",
        "SIEM destination 'test': connection to collector.test:514 restored",
    ]
    # the backoff starts over after a success
    assert sender.backoff.next_delay() == 1


def test_a_message_that_keeps_failing_is_given_up_on() -> None:
    clock = FakeClock()
    transport = FakeTransport()
    transport.fail_sends = True
    sender = _sender(transport, clock)
    sender.submit({"n": 1})
    sender.submit({"n": 2})
    for _ in range(MAX_SEND_ATTEMPTS):
        clock.advance(60)
        sender.step()
    assert sender.failed == 1
    assert sender.queued == 1
    transport.fail_sends = False
    clock.advance(60)
    _drain(sender)
    assert transport.delivered == [b"2"]


def test_an_unreachable_udp_collector_never_discards_events() -> None:
    clock = FakeClock()
    transport = FakeTransport()
    transport.kind = "udp"
    transport.fail_sends = True  # ICMP port unreachable on every send
    sender = _sender(transport, clock)
    sender.submit({"n": 1})
    for _ in range(MAX_SEND_ATTEMPTS * 3):
        clock.advance(60)
        sender.step()
    assert (sender.failed, sender.queued, sender.state) == (0, 1, STATE_RETRYING)


def test_a_record_that_cannot_be_formatted_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    transport = FakeTransport()
    sender = _sender(transport, FakeClock())
    sender.submit({"wrong": "shape"})
    sender.submit({"n": 2})
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        _drain(sender)
    assert transport.delivered == [b"2"]
    assert sender.failed == 1
    assert "could not format an event" in caplog.text


# --- overflow ------------------------------------------------------------


def test_queue_overflow_drops_the_oldest_and_counts(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    transport = FakeTransport()
    sender = _sender(transport, clock, queue_size=100)
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        for n in range(150):
            sender.submit({"n": n})
    assert sender.queued == 100
    assert sender.dropped == 50
    _drain(sender)
    # the 50 oldest went, the newest 100 stayed
    assert transport.delivered[0] == b"50" and transport.delivered[-1] == b"149"

    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 1  # rate-limited, not one per dropped event
    assert "queue full (100 events), dropped 1 of the oldest event(s)" in warnings[0]


def test_drop_warnings_are_rate_limited_per_interval(caplog: pytest.LogCaptureFixture) -> None:
    clock = FakeClock()
    sender = _sender(FakeTransport(), clock, queue_size=1, drop_warning_interval=60.0)
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        for n in range(10):
            sender.submit({"n": n})
        clock.advance(30)
        sender.submit({"n": 10})
        clock.advance(30)
        sender.submit({"n": 11})
    assert sender.dropped == 11
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 2
    assert "dropped 11 of the oldest" not in messages[0]
    assert "dropped 10 of the oldest event(s) to make room (11 dropped in total)" in messages[1]


# --- threads and shutdown ------------------------------------------------


class BlockingTransport(FakeTransport):
    """connect() hangs until released, like a collector that never answers."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()
        self.entered = threading.Event()

    def connect(self) -> None:
        self.entered.set()
        self.release.wait(10)
        super().connect()


def test_submit_never_waits_for_a_stuck_collector() -> None:
    transport = BlockingTransport()
    sender = DestinationSender("stuck", transport, _render, queue_size=10000)
    sender.start()
    try:
        sender.submit({"n": 0})
        assert transport.entered.wait(5)  # the sender thread is now stuck
        started = time.perf_counter()
        for n in range(1, 5001):
            sender.submit({"n": n})
        elapsed = time.perf_counter() - started
        assert elapsed < 1.0
        assert sender.queued == 5000
    finally:
        transport.release.set()
        sender.stop(flush_timeout=5.0)
    assert sender.state == STATE_STOPPED


def test_stop_flushes_the_queue_to_a_real_collector() -> None:
    collector = Collector()
    try:
        transport = TcpTransport("127.0.0.1", collector.port)
        sender = DestinationSender("tcp", transport, _render)
        # queued before the thread even starts, so stop() has to flush them
        for n in range(3):
            sender.submit({"n": n})
        sender.start()
        sender.stop(flush_timeout=5.0)
        assert collector.wait_for(lambda c: c.messages() == [b"0", b"1", b"2"])
        assert sender.state == STATE_STOPPED
        assert sender._thread is not None and not sender._thread.is_alive()
        assert not transport.connected
    finally:
        collector.stop()


def test_stop_does_not_hang_when_the_collector_is_down(caplog: pytest.LogCaptureFixture) -> None:
    transport = FakeTransport(up=False)
    sender = DestinationSender("down", transport, _render)
    sender.start()
    sender.submit({"n": 1})
    sender.submit({"n": 2})
    with caplog.at_level(logging.WARNING, logger="netsentry.siem"):
        started = time.perf_counter()
        sender.stop(flush_timeout=0.5)
        assert time.perf_counter() - started < 2.0
    assert sender.state == STATE_STOPPED
    assert sender.queued == 0
    assert sender.dropped == 2
    assert "2 queued event(s) not delivered at shutdown" in caplog.text


def test_events_after_stop_are_counted_as_dropped() -> None:
    sender = _sender(FakeTransport(), FakeClock())
    sender.stop()
    sender.submit({"n": 1})
    assert (sender.dropped, sender.queued) == (1, 0)


def test_status_has_counters_only() -> None:
    sender = _sender(FakeTransport(), FakeClock())
    assert sender.status() == {
        "name": "test",
        "state": STATE_CONNECTING,
        "sent": 0,
        "dropped": 0,
        "failed": 0,
        "queued": 0,
        "last_error": None,
        "last_error_at": None,
    }
