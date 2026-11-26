"""The per-destination queue and background sender for SIEM forwarding.

The engine only ever calls submit(), which appends to a bounded in-memory
queue and returns at once -- it never waits on the network. One daemon
thread per destination drains the queue, so a destination that's down or
slow never holds up another one, notifications, pcap export or the
dashboard.

When the queue is full the OLDEST queued event is dropped to make room:
during an outage the most recent events are usually the ones worth
having. Drops are counted, and logged at most once a minute.

A destination that can't be reached is retried forever, with exponential
backoff (1s, 2s, 4s, ... capped at 60s). Only state changes are logged --
the first failure, a lost connection, a restored one -- never every retry.
Message payloads are never logged above DEBUG.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Optional

from src.siem.transports import Transport, describe_error

logger = logging.getLogger("netsentry.siem")

STATE_CONNECTING = "connecting"
STATE_CONNECTED = "connected"
STATE_RETRYING = "retrying"
STATE_DISABLED = "disabled"
STATE_STOPPED = "stopped"

# a message that fails this many sends on a fresh connection is given up
# on (counted as failed), so one bad message can't block the queue forever
MAX_SEND_ATTEMPTS = 5
DROP_WARNING_INTERVAL = 60.0
DEFAULT_FLUSH_TIMEOUT = 2.0


class Backoff:
    """Exponential backoff: initial, then doubling up to maximum."""

    def __init__(self, initial: float = 1.0, maximum: float = 60.0) -> None:
        self.initial = initial
        self.maximum = maximum
        self._next = initial

    def next_delay(self) -> float:
        delay = self._next
        self._next = min(self._next * 2, self.maximum)
        return delay

    def reset(self) -> None:
        self._next = self.initial


def _iso(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class DestinationSender:
    """Queues normalized records for one destination and delivers them,
    rendered by render(), through transport.

    clock (monotonic) drives the backoff and the drop warning, wall_clock
    the last-error time shown on the dashboard; both are injectable so
    tests can move time forward instead of sleeping. step() does one unit
    of work without ever blocking, which is what the thread runs and
    what tests call directly.
    """

    def __init__(
        self,
        name: str,
        transport: Transport,
        render: Callable[[Dict[str, Any]], bytes],
        queue_size: int = 10000,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        backoff: Optional[Backoff] = None,
        drop_warning_interval: float = DROP_WARNING_INTERVAL,
    ) -> None:
        self.name = name
        self.transport = transport
        self.render = render
        self.queue_size = max(int(queue_size), 1)
        self.clock = clock
        self.wall_clock = wall_clock
        self.backoff = backoff or Backoff()
        self.drop_warning_interval = drop_warning_interval

        self._queue: Deque[Dict[str, Any]] = deque()
        self._changed = threading.Condition()
        self._thread: Optional[threading.Thread] = None
        self._stopping = False
        self._retry_at = float("-inf")
        self._head_attempts = 0
        self._ever_connected = False

        self.state = STATE_CONNECTING
        self.sent = 0
        self.dropped = 0
        self.failed = 0
        self.last_error: Optional[str] = None
        self.last_error_at: Optional[float] = None
        self._drops_since_warning = 0
        self._last_drop_warning = float("-inf")
        self._flush_timeout = DEFAULT_FLUSH_TIMEOUT

    # --- engine side ------------------------------------------------------

    def submit(self, record: Dict[str, Any]) -> None:
        """Queues record for delivery and returns at once. Never raises,
        never blocks on the network."""
        warn = False
        with self._changed:
            if self._stopping:
                self.dropped += 1
                return
            if len(self._queue) >= self.queue_size:
                self._queue.popleft()
                self.dropped += 1
                self._drops_since_warning += 1
                now = self.clock()
                if now - self._last_drop_warning >= self.drop_warning_interval:
                    warn = True
                    dropped_now = self._drops_since_warning
                    self._drops_since_warning = 0
                    self._last_drop_warning = now
            self._queue.append(record)
            self._changed.notify()
        if warn:
            logger.warning(
                "SIEM destination %r: queue full (%d events), dropped %d of the oldest "
                "event(s) to make room (%d dropped in total)",
                self.name,
                self.queue_size,
                dropped_now,
                self.dropped,
            )

    @property
    def queued(self) -> int:
        with self._changed:
            return len(self._queue)

    # --- sender side ------------------------------------------------------

    def step(self) -> bool:
        """Delivers (or tries to deliver) the oldest queued record. Returns
        False if there was nothing to do right now: the queue is empty, or
        the destination is still in its backoff after a failure."""
        with self._changed:
            if not self._queue or self.clock() < self._retry_at:
                return False
            record = self._queue.popleft()
        self._deliver(record)
        return True

    def _deliver(self, record: Dict[str, Any]) -> bool:
        try:
            payload = self.render(record)
        except Exception:  # noqa: BLE001 - a broken record must not stop the sender
            logger.warning("SIEM destination %r: could not format an event; skipped", self.name, exc_info=True)
            self.failed += 1
            return True

        connected_now = False
        try:
            if not self.transport.connected:
                self.transport.connect()
                connected_now = True
            self.transport.send(payload)
        except Exception as exc:  # noqa: BLE001 - every failure is retried
            # a send that fails on a working (or freshly opened stream)
            # connection may be this message's fault; a collector that
            # can't be reached at all never is. UDP "connects" without
            # contacting anyone, so a fresh UDP socket proves nothing.
            fresh_stream = connected_now and self.transport.kind != "udp"
            self._on_failure(exc, record, self.state == STATE_CONNECTED or fresh_stream)
            return False

        # connected only once something was actually delivered -- for UDP,
        # connect() alone says nothing about the collector
        self._on_connected()
        self.sent += 1
        self._head_attempts = 0
        self.backoff.reset()
        logger.debug("SIEM destination %r: sent %d bytes", self.name, len(payload))
        return True

    def _on_connected(self) -> None:
        if self.state == STATE_CONNECTED:
            return
        if self._ever_connected:
            logger.info("SIEM destination %r: connection to %s restored", self.name, self.transport.target)
        else:
            logger.info("SIEM destination %r: connected to %s", self.name, self.transport.target)
        self._ever_connected = True
        self.state = STATE_CONNECTED

    def _on_failure(self, exc: BaseException, record: Dict[str, Any], counts_against_record: bool) -> None:
        self.transport.close()
        reason = describe_error(exc)
        self.last_error = reason
        self.last_error_at = self.wall_clock()
        delay = self.backoff.next_delay()
        if self.state == STATE_CONNECTED:
            logger.warning(
                "SIEM destination %r: lost connection to %s (%s); retrying with backoff",
                self.name, self.transport.target, reason,
            )
        elif self.state == STATE_CONNECTING:
            logger.warning(
                "SIEM destination %r: cannot deliver to %s (%s); retrying with backoff, "
                "events are queued meanwhile",
                self.name, self.transport.target, reason,
            )
        else:
            logger.debug("SIEM destination %r: retry failed (%s), next in %.0fs", self.name, reason, delay)
        if self.state != STATE_STOPPED:
            self.state = STATE_RETRYING

        if counts_against_record:
            self._head_attempts += 1
        with self._changed:
            self._retry_at = self.clock() + delay
            if self._head_attempts >= MAX_SEND_ATTEMPTS:
                self.failed += 1
                self._head_attempts = 0
                logger.warning(
                    "SIEM destination %r: gave up on one event after %d failed sends",
                    self.name, MAX_SEND_ATTEMPTS,
                )
            elif len(self._queue) >= self.queue_size:
                self.dropped += 1  # the queue filled up meanwhile; it was the oldest
            else:
                self._queue.appendleft(record)

    # --- thread -----------------------------------------------------------

    def start(self) -> None:
        """Starts the daemon sender thread."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name=f"netsentry-siem-{self.name}", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            with self._changed:
                while not self._stopping:
                    if self._queue:
                        wait = self._retry_at - self.clock()
                        if wait <= 0:
                            break
                        self._changed.wait(wait)
                    else:
                        self._changed.wait()
                if self._stopping:
                    break
            try:
                self.step()
            except Exception:  # noqa: BLE001 - the sender thread must keep running
                logger.exception("SIEM destination %r: unexpected sender error", self.name)
        self._flush()

    def _flush(self) -> None:
        """Best effort at shutdown: send what's queued until the deadline,
        ignoring the backoff, and give up at the first failure."""
        deadline = self.clock() + self._flush_timeout
        while self.clock() < deadline:
            with self._changed:
                if not self._queue:
                    break
                record = self._queue.popleft()
            if not self._deliver(record):
                break
        remaining = self.queued
        if remaining:
            with self._changed:
                self.dropped += len(self._queue)
                self._queue.clear()
            logger.warning(
                "SIEM destination %r: %d queued event(s) not delivered at shutdown", self.name, remaining
            )
        self.transport.close()
        self.state = STATE_STOPPED

    def request_stop(self, flush_timeout: float = DEFAULT_FLUSH_TIMEOUT) -> None:
        """Tells the sender to flush what it can within about flush_timeout
        seconds and stop, without waiting for it -- so several destinations
        can flush at the same time. join() waits for it."""
        with self._changed:
            self._flush_timeout = flush_timeout
            self._stopping = True
            self._changed.notify_all()
        if self._thread is None:
            self._flush()

    def join(self, timeout: float) -> None:
        """Waits up to timeout seconds for a requested stop to finish. Never
        hangs: a collector that blocks the flush is abandoned once the wait
        times out (the thread is a daemon)."""
        if self._thread is None:
            return
        self._thread.join(max(timeout, 0.0))
        if self._thread.is_alive():
            logger.warning("SIEM destination %r: sender still busy at shutdown; abandoned", self.name)

    def stop(self, flush_timeout: float = DEFAULT_FLUSH_TIMEOUT) -> None:
        """request_stop() and join(), with a second of slack for the last
        send in progress."""
        self.request_stop(flush_timeout)
        self.join(flush_timeout + 1.0)

    # --- status -----------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Counters for the dashboard: nothing secret, no payloads."""
        return {
            "name": self.name,
            "state": self.state,
            "sent": self.sent,
            "dropped": self.dropped,
            "failed": self.failed,
            "queued": self.queued,
            "last_error": self.last_error,
            "last_error_at": _iso(self.last_error_at),
        }
