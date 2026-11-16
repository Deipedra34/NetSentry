"""Tests for the login attempt limiter in :mod:`src.auth`."""

from __future__ import annotations

from src.auth import LoginLimiter, limiter_keys


class FakeClock:
    """A settable stand-in for time.time()."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_locks_after_max_failures() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=3, lockout_seconds=900, clock=clock)
    for _ in range(2):
        limiter.record_failure("user:alice")
        assert not limiter.is_locked("user:alice")
    limiter.record_failure("user:alice")
    assert limiter.is_locked("user:alice")
    assert not limiter.is_locked("user:bob")


def test_lockout_expires_on_its_own() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=2, lockout_seconds=900, clock=clock)
    limiter.record_failure("user:alice")
    limiter.record_failure("user:alice")
    clock.advance(899)
    assert limiter.is_locked("user:alice")
    clock.advance(1)
    assert not limiter.is_locked("user:alice")
    # and it starts counting from scratch afterwards
    limiter.record_failure("user:alice")
    assert not limiter.is_locked("user:alice")


def test_failures_outside_the_window_are_forgotten() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=3, lockout_seconds=60, clock=clock)
    limiter.record_failure("ip:10.0.0.1")
    limiter.record_failure("ip:10.0.0.1")
    clock.advance(61)
    limiter.record_failure("ip:10.0.0.1")
    assert not limiter.is_locked("ip:10.0.0.1")


def test_any_locked_key_blocks() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=2, lockout_seconds=60, clock=clock)
    # same IP trying different usernames: the IP key locks
    limiter.record_failure(*limiter_keys("alice", "10.0.0.1"))
    limiter.record_failure(*limiter_keys("bob", "10.0.0.1"))
    assert limiter.is_locked(*limiter_keys("carol", "10.0.0.1"))
    assert not limiter.is_locked(*limiter_keys("carol", "10.0.0.2"))


def test_username_key_is_case_insensitive() -> None:
    assert limiter_keys("Alice", "1.2.3.4") == limiter_keys("alice", "1.2.3.4")
    assert limiter_keys("alice", None)[1] == "ip:unknown"


def test_reset_clears_failures() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=2, lockout_seconds=60, clock=clock)
    limiter.record_failure("user:alice")
    limiter.reset("user:alice")
    limiter.record_failure("user:alice")
    assert not limiter.is_locked("user:alice")


def test_size_is_bounded() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=5, lockout_seconds=60, clock=clock, max_entries=100)
    for i in range(1000):
        limiter.record_failure(f"user:made-up-{i}")
    assert len(limiter) == 100


def test_eviction_drops_stale_entries_before_live_locks() -> None:
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=1, lockout_seconds=600, clock=clock, max_entries=2)
    limiter.record_failure("user:stale")
    clock.advance(1)
    limiter.record_failure("ip:attacker")  # max_failures=1 -> locked right away
    clock.advance(599)  # user:stale's lock (until +600) has just expired
    limiter.record_failure("user:third")
    assert limiter.is_locked("ip:attacker")
    assert len(limiter) == 2
