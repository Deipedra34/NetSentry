"""Sqlite storage for the events our detectors raise.

Just one table, events, holds everything. Database wraps it with a lock
because the sniffer thread writes to it while the Flask thread is reading
from it at the same time -- without the lock we'd get weird sqlite errors
under load (learned this the hard way while testing).
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Event:
    """One alert. event_type is the short code like "PORT_SCAN", source_ip is
    who triggered it, details is the human-readable blurb, timestamp defaults
    to right now (UTC) if you don't pass one. id stays None until it's
    actually been written to the db.
    """

    event_type: str
    source_ip: str
    details: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: Optional[int] = None
    # the remote end of the activity, for detectors where that's the
    # interesting address (e.g. where data is being exfiltrated to) --
    # in-memory only, so threat intel can look it up too; it isn't stored,
    # the details string already names it
    destination_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """for jsonify() basically, converts to plain dict"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "details": self.details,
        }


@dataclass
class BlockedIP:
    """One currently-active firewall block applied by AutoBlocker (see
    src/auto_block.py). expires_at is None for a permanent block
    (block_duration_minutes: 0). Row is deleted once the block is lifted --
    this table only ever holds *currently* blocked IPs, not history.
    """

    source_ip: str
    event_type: str
    rule_identifier: str
    blocked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """for jsonify() basically, converts to plain dict"""
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class ThreatIntelResult:
    """One cached AbuseIPDB/VirusTotal lookup for a source IP (see
    src/threat_intel.py). A service's fields stay None if it wasn't queried
    or its lookup failed. raw_response_summary is a small JSON blob of the
    parsed fields, not the full API responses.
    """

    source_ip: str
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    abuseipdb_score: Optional[int] = None
    abuseipdb_reports: Optional[int] = None
    virustotal_malicious_count: Optional[int] = None
    virustotal_total_engines: Optional[int] = None
    raw_response_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """for jsonify() basically, converts to plain dict"""
        return {
            "source_ip": self.source_ip,
            "checked_at": self.checked_at.isoformat(),
            "abuseipdb_score": self.abuseipdb_score,
            "abuseipdb_reports": self.abuseipdb_reports,
            "virustotal_malicious_count": self.virustotal_malicious_count,
            "virustotal_total_engines": self.virustotal_total_engines,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    event_type TEXT NOT NULL,
    rule_identifier TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_source_ip ON blocked_ips (source_ip);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires_at ON blocked_ips (expires_at);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    source_ip TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL,
    abuseipdb_score INTEGER,
    abuseipdb_reports INTEGER,
    virustotal_malicious_count INTEGER,
    virustotal_total_engines INTEGER,
    raw_response_summary TEXT NOT NULL DEFAULT ''
);
"""

_THREAT_INTEL_COLUMNS = (
    "source_ip, checked_at, abuseipdb_score, abuseipdb_reports, "
    "virustotal_malicious_count, virustotal_total_engines, raw_response_summary"
)


def _row_to_blocked_ip(row: sqlite3.Row) -> BlockedIP:
    return BlockedIP(
        id=row["id"],
        source_ip=row["source_ip"],
        blocked_at=datetime.fromisoformat(row["blocked_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
        event_type=row["event_type"],
        rule_identifier=row["rule_identifier"],
    )


def _row_to_threat_intel(row: sqlite3.Row) -> ThreatIntelResult:
    return ThreatIntelResult(
        source_ip=row["source_ip"],
        checked_at=datetime.fromisoformat(row["checked_at"]),
        abuseipdb_score=row["abuseipdb_score"],
        abuseipdb_reports=row["abuseipdb_reports"],
        virustotal_malicious_count=row["virustotal_malicious_count"],
        virustotal_total_engines=row["virustotal_total_engines"],
        raw_response_summary=row["raw_response_summary"],
    )


class Database:
    """Thread-safe-ish sqlite wrapper for reading/writing events."""

    def __init__(self, path: str | Path = "netsentry.db") -> None:
        # opens the db, creating the file + schema if it's not there yet.
        # pass ":memory:" for an in-memory db, useful in the tests so we don't
        # leave netsentry.db files scattered everywhere after a test run
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def log_event(self, event: Event) -> Event:
        """Saves the event, sets its id from the new row and hands back the
        same object (mutated in place, not a copy)."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO events (timestamp, source_ip, event_type, details) "
                "VALUES (?, ?, ?, ?)",
                (event.timestamp.isoformat(), event.source_ip, event.event_type, event.details),
            )
            self._conn.commit()
            event.id = cursor.lastrowid
        return event

    def update_event_details(self, event_id: int, details: str) -> None:
        """Rewrites an already-logged event's details -- used to attach
        threat intel results after the event was first written."""
        with self._lock:
            self._conn.execute("UPDATE events SET details = ? WHERE id = ?", (details, event_id))
            self._conn.commit()

    def get_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> List[Event]:
        """Grabs events newest-first, optionally filtered by type and/or
        source ip. limit caps how many rows come back."""
        query = "SELECT id, timestamp, source_ip, event_type, details FROM events"
        clauses: List[str] = []
        params: List[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()

        return [
            Event(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                details=row["details"],
            )
            for row in rows
        ]

    def count_events(self) -> int:
        """total row count, used for the stats endpoint"""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        return int(row["c"])

    def event_type_counts(
        self, since: Optional[datetime] = None, until: Optional[datetime] = None
    ) -> Dict[str, int]:
        """counts per event_type, e.g. {"PORT_SCAN": 12, "SYN_FLOOD": 3}.
        Pass since to only count events at or after that (UTC) time, and
        until to only count events before that (UTC) time."""
        query = "SELECT event_type, COUNT(*) AS c FROM events"
        clauses: List[str] = []
        params: List[Any] = []
        # timestamps are stored as UTC isoformat strings, so plain string
        # comparison sorts them correctly
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until is not None:
            clauses.append("timestamp < ?")
            params.append(until.isoformat())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " GROUP BY event_type"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return {row["event_type"]: row["c"] for row in rows}

    def top_source_ips(
        self, since: datetime, until: datetime, limit: int
    ) -> List[Tuple[str, int, Dict[str, int]]]:
        """The `limit` source IPs with the most events in [since, until), as
        (source_ip, event count, {event_type: count}), busiest first (ties
        broken by IP so the order is stable). For reports."""
        window = (since.isoformat(), until.isoformat())
        with self._lock:
            top = self._conn.execute(
                "SELECT source_ip, COUNT(*) AS c FROM events "
                "WHERE timestamp >= ? AND timestamp < ? "
                "GROUP BY source_ip ORDER BY c DESC, source_ip LIMIT ?",
                (*window, limit),
            ).fetchall()
            if not top:
                return []
            placeholders = ", ".join("?" for _ in top)
            breakdown = self._conn.execute(
                "SELECT source_ip, event_type, COUNT(*) AS c FROM events "
                "WHERE timestamp >= ? AND timestamp < ? "
                f"AND source_ip IN ({placeholders}) GROUP BY source_ip, event_type",
                (*window, *(row["source_ip"] for row in top)),
            ).fetchall()
        types: Dict[str, Dict[str, int]] = {}
        for row in breakdown:
            types.setdefault(row["source_ip"], {})[row["event_type"]] = row["c"]
        return [(row["source_ip"], row["c"], types.get(row["source_ip"], {})) for row in top]

    def get_notable_events(
        self, since: datetime, until: datetime, priority_types: List[str], limit: int
    ) -> List[Event]:
        """Up to `limit` events in [since, until): those whose type is in
        priority_types first, then the rest, newest first within each. For
        reports."""
        placeholders = ", ".join("?" for _ in priority_types) or "NULL"
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, timestamp, source_ip, event_type, details FROM events "
                "WHERE timestamp >= ? AND timestamp < ? "
                f"ORDER BY CASE WHEN event_type IN ({placeholders}) THEN 0 ELSE 1 END, "
                "timestamp DESC, id DESC LIMIT ?",
                (since.isoformat(), until.isoformat(), *priority_types, limit),
            ).fetchall()
        return [
            Event(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                details=row["details"],
            )
            for row in rows
        ]

    def get_event_details_containing(self, since: datetime, until: datetime, text: str) -> List[str]:
        """The details of every event in [since, until) whose details
        contain `text` (e.g. an enrichment tag like "[GeoIP"). For reports."""
        pattern = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        with self._lock:
            rows = self._conn.execute(
                "SELECT details FROM events WHERE timestamp >= ? AND timestamp < ? "
                "AND details LIKE ? ESCAPE '\\'",
                (since.isoformat(), until.isoformat(), pattern),
            ).fetchall()
        return [row["details"] for row in rows]

    def get_event_times_since(
        self, since: datetime, until: Optional[datetime] = None
    ) -> List[Tuple[datetime, str]]:
        """(timestamp, event_type) for every event at or after since (and
        before until, if given), oldest first -- just the two columns the
        dashboard's and reports' timeline charts need."""
        query = "SELECT timestamp, event_type FROM events WHERE timestamp >= ?"
        params: List[Any] = [since.isoformat()]
        if until is not None:
            query += " AND timestamp < ?"
            params.append(until.isoformat())
        with self._lock:
            rows = self._conn.execute(query + " ORDER BY timestamp", params).fetchall()
        return [(datetime.fromisoformat(row["timestamp"]), row["event_type"]) for row in rows]

    def add_blocked_ip(self, blocked: BlockedIP) -> BlockedIP:
        """Saves a new block, sets its id from the new row and hands back the
        same object (mutated in place, not a copy)."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO blocked_ips (source_ip, blocked_at, expires_at, event_type, rule_identifier) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    blocked.source_ip,
                    blocked.blocked_at.isoformat(),
                    blocked.expires_at.isoformat() if blocked.expires_at else None,
                    blocked.event_type,
                    blocked.rule_identifier,
                ),
            )
            self._conn.commit()
            blocked.id = cursor.lastrowid
        return blocked

    def get_blocked_ips(self) -> List[BlockedIP]:
        """Every currently-tracked block, newest first -- for the dashboard."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, source_ip, blocked_at, expires_at, event_type, rule_identifier "
                "FROM blocked_ips ORDER BY id DESC"
            ).fetchall()
        return [_row_to_blocked_ip(row) for row in rows]

    def get_active_block(self, source_ip: str) -> Optional[BlockedIP]:
        """The current block for source_ip, if any -- lets AutoBlocker skip
        re-blocking an IP that's already blocked."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, source_ip, blocked_at, expires_at, event_type, rule_identifier "
                "FROM blocked_ips WHERE source_ip = ?",
                (source_ip,),
            ).fetchone()
        return _row_to_blocked_ip(row) if row else None

    def get_expired_blocks(self, now: Optional[datetime] = None) -> List[BlockedIP]:
        """Blocks whose expires_at has passed (permanent blocks, expires_at
        IS NULL, never show up here)."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, source_ip, blocked_at, expires_at, event_type, rule_identifier "
                "FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now.isoformat(),),
            ).fetchall()
        return [_row_to_blocked_ip(row) for row in rows]

    def remove_blocked_ip(self, blocked_id: int) -> None:
        """Drops the tracking row once a block's been lifted at the firewall."""
        with self._lock:
            self._conn.execute("DELETE FROM blocked_ips WHERE id = ?", (blocked_id,))
            self._conn.commit()

    def get_threat_intel(self, source_ip: str) -> Optional[ThreatIntelResult]:
        """The cached threat intel lookup for source_ip, if any (stale or
        not -- ThreatIntelLookup decides whether it's still fresh)."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_THREAT_INTEL_COLUMNS} FROM threat_intel_cache WHERE source_ip = ?",
                (source_ip,),
            ).fetchone()
        return _row_to_threat_intel(row) if row else None

    def get_threat_intel_for_ips(self, source_ips: List[str]) -> Dict[str, ThreatIntelResult]:
        """Cached lookups for several IPs at once, keyed by IP -- IPs with
        no cached lookup are just left out. For the dashboard."""
        unique_ips = list(set(source_ips))
        if not unique_ips:
            return {}
        placeholders = ", ".join("?" for _ in unique_ips)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_THREAT_INTEL_COLUMNS} FROM threat_intel_cache "
                f"WHERE source_ip IN ({placeholders})",
                unique_ips,
            ).fetchall()
        return {row["source_ip"]: _row_to_threat_intel(row) for row in rows}

    def get_flagged_threat_intel(
        self,
        since: datetime,
        until: datetime,
        min_abuseipdb_score: int,
        min_virustotal_malicious: int,
        limit: int,
    ) -> List[Tuple[ThreatIntelResult, int]]:
        """Cached lookups at or above either threshold for IPs that were
        active in [since, until) -- raised an event then, or were looked up
        then (destination IPs never appear as an event's source) -- with
        each IP's event count in the window, worst first. For reports."""
        columns = ", ".join(f"t.{column.strip()}" for column in _THREAT_INTEL_COLUMNS.split(","))
        window = (since.isoformat(), until.isoformat())
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {columns}, COALESCE(e.c, 0) AS events FROM threat_intel_cache t "
                "LEFT JOIN (SELECT source_ip, COUNT(*) AS c FROM events "
                "WHERE timestamp >= ? AND timestamp < ? GROUP BY source_ip) e "
                "ON e.source_ip = t.source_ip "
                "WHERE (t.abuseipdb_score >= ? OR t.virustotal_malicious_count >= ?) "
                "AND (e.c IS NOT NULL OR (t.checked_at >= ? AND t.checked_at < ?)) "
                "ORDER BY COALESCE(t.abuseipdb_score, 0) DESC, "
                "COALESCE(t.virustotal_malicious_count, 0) DESC, t.source_ip LIMIT ?",
                (*window, min_abuseipdb_score, min_virustotal_malicious, *window, limit),
            ).fetchall()
        return [(_row_to_threat_intel(row), row["events"]) for row in rows]

    def save_threat_intel(self, result: ThreatIntelResult) -> None:
        """Inserts or replaces the cached lookup for result.source_ip --
        only the latest lookup per IP is kept."""
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO threat_intel_cache ({_THREAT_INTEL_COLUMNS}) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    result.source_ip,
                    result.checked_at.isoformat(),
                    result.abuseipdb_score,
                    result.abuseipdb_reports,
                    result.virustotal_malicious_count,
                    result.virustotal_total_engines,
                    result.raw_response_summary,
                ),
            )
            self._conn.commit()

    def close(self) -> None:
        """closes the connection, call this when you're done with it"""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()
