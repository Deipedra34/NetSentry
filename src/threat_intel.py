"""AbuseIPDB / VirusTotal reputation lookups for suspicious source IPs.

ThreatIntelLookup enriches a critical event's details with what AbuseIPDB
and/or VirusTotal know about its source IP (e.g. "AbuseIPDB: 87% confidence,
42 reports | VirusTotal: 12/94 engines flagged malicious"), so the context
shows up everywhere details already do -- logs, notifications, dashboard.

Both services have tight free-tier quotas, so every lookup goes through a
cache (in memory, backed by the `threat_intel_cache` table so it survives a
restart) and is only re-queried once it's older than cache_ttl_hours. Clean
results are cached too. On top of that, a per-IP cooldown (same window as
notifications/pcap_export) stops a sustained attack from firing a burst of
API calls while a lookup keeps failing.

Mirrors the disabled-by-default, best-effort pattern of the other optional
features -- a bad API key, rate limit, timeout or no internet is logged as a
warning (once per distinct failure, not per event) and never takes down
packet capture or stops the other service from being queried. Private/local
and whitelisted IPs are never looked up.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from src.auto_block import _parse_whitelist
from src.config import Config
from src.database import Database, Event, ThreatIntelResult
from src.notifications import EVENT_SEVERITY, SEVERITY_LEVELS

logger = logging.getLogger("netsentry.threat_intel")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# seconds -- lookups run inline on the capture thread, so keep this short
# enough that a slow API never meaningfully stalls packet processing
_REQUEST_TIMEOUT = 5.0

ABUSEIPDB = "abuseipdb"
VIRUSTOTAL = "virustotal"


def _is_lookup_candidate(ip_str: str) -> bool:
    """True only for publicly routable unicast addresses -- loopback,
    RFC1918, link-local, reserved etc. (and unparseable input) are never
    worth spending API quota on."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


class _LookupFailed(Exception):
    """Raised by a service query with a short, stable reason -- stable so
    repeated identical failures can be de-duplicated in the log."""


def format_summary(result: ThreatIntelResult) -> str:
    """Human-readable one-liner for whatever services returned data, e.g.
    "AbuseIPDB: 87% confidence, 42 reports | VirusTotal: 12/94 engines
    flagged malicious". Empty string if neither did."""
    parts: List[str] = []
    if result.abuseipdb_score is not None:
        parts.append(
            f"AbuseIPDB: {result.abuseipdb_score}% confidence, "
            f"{result.abuseipdb_reports or 0} reports"
        )
    if result.virustotal_malicious_count is not None:
        text = (
            f"VirusTotal: {result.virustotal_malicious_count}/"
            f"{result.virustotal_total_engines or 0} engines flagged malicious"
        )
        suspicious = _summary_field(result, VIRUSTOTAL, "suspicious")
        if suspicious:
            text += f", {suspicious} suspicious"
        parts.append(text)
    return " | ".join(parts)


def _summary_field(result: ThreatIntelResult, service: str, key: str) -> Any:
    try:
        return json.loads(result.raw_response_summary or "{}").get(service, {}).get(key)
    except (ValueError, AttributeError):
        return None


class ThreatIntelLookup:
    """Looks up the source IP of qualifying events on AbuseIPDB and/or
    VirusTotal and appends the results to the event's details.

    enrich() should be called once per event the engine raises, right after
    it's written to the database and before NotificationDispatcher.notify()
    so alerts carry the extra context.
    """

    def __init__(self, config: Config, database: Database, whitelist: Optional[List[str]] = None) -> None:
        self.config = config
        self.database = database
        self._whitelist_networks = _parse_whitelist(whitelist or [])
        # source_ip -> most recent lookup, fronting the threat_intel_cache table
        self._cache: Dict[str, ThreatIntelResult] = {}
        # source_ip -> last time we actually hit the APIs for it
        self._last_attempt: Dict[str, float] = {}
        # service -> reason of the last failure we warned about, so a
        # persistently failing service only logs once until it recovers
        self._last_failure: Dict[str, str] = {}
        self._services = self._configured_services()

    def _configured_services(self) -> List[str]:
        """Services that are enabled *and* have an API key. An enabled
        service with no key is warned about once here and then ignored."""
        intel = self.config.threat_intel
        if not intel.enabled:
            return []
        services: List[str] = []
        for name, service in ((ABUSEIPDB, intel.abuseipdb), (VIRUSTOTAL, intel.virustotal)):
            if not service.enabled:
                continue
            if not service.api_key:
                logger.warning("threat_intel.%s is enabled but has no api_key; skipping it", name)
                continue
            services.append(name)
        if not services:
            logger.warning("threat_intel is enabled but no service is usable; no lookups will run")
        return services

    def enrich(self, event: Event, now: Optional[float] = None) -> Optional[ThreatIntelResult]:
        """Appends threat intel for event.source_ip to event.details (and
        to the stored event row, if it has an id) and returns the result
        used, or None if no lookup applied. Never raises -- a failure in
        one service is logged and the other is still queried."""
        if not self._services:
            return None
        if not self._meets_min_severity(event.event_type):
            return None
        ip = event.source_ip
        if self._is_whitelisted(ip):
            logger.debug("Not looking up whitelisted source IP %s", ip)
            return None
        if not _is_lookup_candidate(ip):
            logger.debug("Not looking up private/local/reserved source IP %s", ip)
            return None

        current = now if now is not None else time.time()
        result = self._get_fresh_cached(ip, current)
        missing = [service for service in self._services if not self._has_data(result, service)]
        if missing and self._should_query(ip, current):
            result = self._query(ip, missing, result, current)

        if result is None:
            return None
        summary = format_summary(result)
        if not summary:
            return None

        event.details = f"{event.details} [{summary}]"
        if event.id is not None:
            self.database.update_event_details(event.id, event.details)
        return result

    def _meets_min_severity(self, event_type: str) -> bool:
        """Same ranking as AutoBlocker's min_severity gate."""
        if event_type not in EVENT_SEVERITY:
            return False
        min_severity = self.config.threat_intel.min_severity
        if min_severity not in SEVERITY_LEVELS:
            self._warn_once(
                "config",
                f"threat_intel.min_severity={min_severity!r} is not a recognized level "
                f"{SEVERITY_LEVELS}; skipping lookups",
            )
            return False
        return SEVERITY_LEVELS.index(EVENT_SEVERITY[event_type]) >= SEVERITY_LEVELS.index(min_severity)

    def _is_whitelisted(self, source_ip: str) -> bool:
        """Checked against the event's source_ip independently of the
        engine's packet-level filtering -- see AutoBlocker._is_whitelisted
        for why the two can differ."""
        if not self._whitelist_networks:
            return False
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(addr in network for network in self._whitelist_networks)

    def _get_fresh_cached(self, ip: str, now: float) -> Optional[ThreatIntelResult]:
        """The cached result for ip if it's younger than cache_ttl_hours,
        checking memory first and falling back to the database."""
        result = self._cache.get(ip)
        if result is None:
            result = self.database.get_threat_intel(ip)
            if result is not None:
                self._cache[ip] = result
        if result is None:
            return None
        ttl = timedelta(hours=self.config.threat_intel.cache_ttl_hours)
        if datetime.fromtimestamp(now, timezone.utc) - result.checked_at >= ttl:
            return None
        return result

    @staticmethod
    def _has_data(result: Optional[ThreatIntelResult], service: str) -> bool:
        if result is None:
            return False
        if service == ABUSEIPDB:
            return result.abuseipdb_score is not None
        return result.virustotal_malicious_count is not None

    def _should_query(self, ip: str, now: float) -> bool:
        """Per-IP cooldown, same window as notifications/pcap_export.
        Records the attempt up front so a service that keeps failing isn't
        re-queried on every event from the same attacker."""
        last = self._last_attempt.get(ip, float("-inf"))
        if now - last < self.config.notifications.cooldown:
            return False
        self._last_attempt[ip] = now
        return True

    def _query(
        self,
        ip: str,
        services: List[str],
        cached: Optional[ThreatIntelResult],
        now: float,
    ) -> Optional[ThreatIntelResult]:
        """Queries each service in `services` independently and merges the
        results onto `cached` (a fresh cached result missing some service's
        data), or a brand new result. Saved to the cache if anything came
        back, clean or not."""
        if cached is not None:
            result = replace(cached)
        else:
            result = ThreatIntelResult(source_ip=ip, checked_at=datetime.fromtimestamp(now, timezone.utc))
        summary: Dict[str, Any] = {}
        try:
            summary = json.loads(result.raw_response_summary or "{}")
        except ValueError:
            pass

        got_any = False
        for service in services:
            try:
                parsed = self._query_abuseipdb(ip) if service == ABUSEIPDB else self._query_virustotal(ip)
            except _LookupFailed as exc:
                self._warn_once(service, f"{service} lookup failed: {exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - one broken service must not stop the other
                self._warn_once(service, f"{service} lookup failed unexpectedly: {type(exc).__name__}")
                logger.debug("%s lookup for %s raised", service, ip, exc_info=True)
                continue

            if self._last_failure.pop(service, None) is not None:
                logger.info("%s lookups are working again", service)
            got_any = True
            summary[service] = parsed
            if service == ABUSEIPDB:
                result.abuseipdb_score = parsed["score"]
                result.abuseipdb_reports = parsed["reports"]
            else:
                result.virustotal_malicious_count = parsed["malicious"]
                result.virustotal_total_engines = parsed["total"]

        if not got_any:
            return cached

        result.raw_response_summary = json.dumps(summary, sort_keys=True)
        self._cache[ip] = result
        self.database.save_threat_intel(result)
        logger.info("Threat intel for %s: %s", ip, format_summary(result))
        return result

    def _query_abuseipdb(self, ip: str) -> Dict[str, int]:
        settings = self.config.threat_intel.abuseipdb
        payload = self._get_json(
            ABUSEIPDB_URL,
            headers={"Key": settings.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": settings.max_age_days},
        )
        try:
            data = payload["data"]
            return {
                "score": int(data["abuseConfidenceScore"]),
                "reports": int(data.get("totalReports") or 0),
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise _LookupFailed("unexpected response format") from exc

    def _query_virustotal(self, ip: str) -> Dict[str, int]:
        settings = self.config.threat_intel.virustotal
        payload = self._get_json(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": settings.api_key, "Accept": "application/json"},
        )
        try:
            stats = payload["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "total": sum(int(count) for count in stats.values()),
            }
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _LookupFailed("unexpected response format") from exc

    @staticmethod
    def _get_json(url: str, **kwargs: Any) -> Any:
        """GETs url and returns the decoded JSON body, raising _LookupFailed
        with a stable reason for anything that isn't a clean 200."""
        try:
            response = requests.get(url, timeout=_REQUEST_TIMEOUT, **kwargs)
        except requests.Timeout as exc:
            raise _LookupFailed("request timed out") from exc
        except requests.RequestException as exc:
            raise _LookupFailed(f"network error ({type(exc).__name__})") from exc

        status = response.status_code
        if status in (401, 403):
            raise _LookupFailed(f"API key rejected (HTTP {status})")
        if status == 429:
            raise _LookupFailed("rate limit exceeded (HTTP 429)")
        if status != 200:
            raise _LookupFailed(f"HTTP {status}")
        try:
            return response.json()
        except ValueError as exc:
            raise _LookupFailed("response was not valid JSON") from exc

    def _warn_once(self, key: str, message: str) -> None:
        """Warns the first time `key` fails with `message`; identical
        repeats drop to debug so a dead API key doesn't flood the log."""
        if self._last_failure.get(key) == message:
            logger.debug(message)
            return
        self._last_failure[key] = message
        logger.warning(message)
