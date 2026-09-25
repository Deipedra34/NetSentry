"""Config loading for NetSentry.

Everything's a dataclass with defaults baked in, so config.yaml only needs to
list the values you actually want to change -- anything missing just falls
back to whatever's below. Kept it this way so people don't have to copy a
giant yaml file around just to tweak one threshold.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass
class PortScanConfig:
    """Thresholds for port scan detection."""

    enabled: bool = True
    port_threshold: int = 15
    time_window: float = 10.0
    cooldown: float = 30.0


@dataclass
class ArpSpoofConfig:
    """Thresholds for ARP spoofing detection."""

    enabled: bool = True
    cooldown: float = 60.0


@dataclass
class DosConfig:
    """Thresholds for SYN flood / basic DoS detection."""

    enabled: bool = True
    syn_threshold: int = 100
    time_window: float = 5.0
    cooldown: float = 30.0


@dataclass
class TrafficAnomalyConfig:
    """Thresholds for general statistical traffic anomaly detection."""

    enabled: bool = True
    window_seconds: float = 10.0
    baseline_windows: int = 6
    multiplier: float = 3.0
    min_baseline_samples: int = 3


@dataclass
class DnsTunnelConfig:
    """Thresholds for DNS tunneling detection -- see src/detectors.py.

    Tunneling hides data (exfil or C2) inside DNS queries, which shows up as
    long, high-entropy subdomain labels, abnormally high query rates from one
    host, and heavy use of record types like TXT/NULL/CNAME.
    """

    enabled: bool = True
    # flag a query whose longest subdomain label exceeds this many characters
    max_subdomain_length: int = 50
    # flag a source IP issuing more DNS queries than this in a rolling 60s window
    max_queries_per_minute: int = 60
    # flag a subdomain whose Shannon entropy (bits/char) exceeds this
    entropy_threshold: float = 3.5
    # record types commonly abused for tunneling, weighted more heavily
    suspicious_query_types: List[str] = field(
        default_factory=lambda: ["TXT", "NULL", "CNAME"]
    )
    # seconds to wait before re-alerting on the same source IP
    cooldown: float = 60.0


@dataclass
class TlsAnomalyConfig:
    """Thresholds for TLS/HTTPS anomaly detection -- see src/detectors.py.

    Flags TLS handshakes on two independent fronts: a client's JA3
    fingerprint matching a known-malicious blocklist, and a server
    certificate showing signs of hastily-stood-up C2 infrastructure
    (self-signed, expired, short-lived, or very recently issued).
    """

    enabled: bool = True
    # path to a local file of known-malicious JA3 hashes, one per line
    ja3_blocklist_path: str = "data/ja3_blocklist.txt"
    # flag certificates whose issuer and subject are identical
    flag_self_signed: bool = True
    # flag certificates that are expired or not yet valid
    flag_expired_certs: bool = True
    # flag certificates valid for fewer than this many days
    flag_short_validity_days: int = 7
    # flag certificates issued more recently than this many days ago
    flag_recently_issued_days: int = 2
    # seconds to wait before re-alerting on the same source IP
    cooldown: float = 60.0


@dataclass
class MlAnomalyConfig:
    """Thresholds for ML-based anomaly detection -- see src/detectors.py
    (MLAnomalyDetector) and src/ml_features.py. Disabled by default: this
    detector needs a trained model (scripts/train_ml_model.py) before it can
    do anything, and a fresh install has no model to load yet.
    """

    enabled: bool = False
    # where MLAnomalyDetector loads its trained model from, and where
    # scripts/train_ml_model.py saves one to by default
    model_path: str = "data/ml_model.joblib"
    # "isolation_forest" or "random_forest" -- also read by
    # scripts/train_ml_model.py as its default training algorithm
    algorithm: str = "isolation_forest"
    # expected proportion of anomalous traffic in the training set; passed
    # to IsolationForest's own `contamination` parameter at training time,
    # not used at inference time
    contamination: float = 0.05
    # a window scoring below this is flagged as anomalous -- see
    # MLAnomalyDetector._score for what "score" means for each algorithm
    anomaly_score_threshold: float = -0.5
    # size (seconds) of the rolling per-source-IP window used to compute
    # traffic features -- see src/ml_features.py
    feature_window_seconds: int = 10
    # seconds to wait before re-alerting on the same source IP
    cooldown: float = 60.0


@dataclass
class DatabaseConfig:
    """SQLite event database settings."""

    path: str = "netsentry.db"


@dataclass
class LoggingConfig:
    """Application logging settings."""

    level: str = "INFO"
    file: str = "netsentry.log"


@dataclass
class DiscordConfig:
    """Discord webhook settings for critical event alerts."""

    enabled: bool = False
    webhook_url: str = ""


@dataclass
class TelegramConfig:
    """Telegram Bot API settings for critical event alerts."""

    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class EmailConfig:
    """SMTP settings for critical event alerts."""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addr: str = ""
    use_tls: bool = True


@dataclass
class NotificationsConfig:
    """Multi-channel alerting for critical events. Each channel defaults to
    disabled -- opting in means setting enabled: true plus that channel's
    fields in config.yaml."""

    # seconds to wait before re-alerting the same source IP + event type on
    # a given channel, so a sustained attack doesn't spam every packet
    cooldown: float = 300.0
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    email: EmailConfig = field(default_factory=EmailConfig)


@dataclass
class PcapExportConfig:
    """Settings for automatically exporting suspicious traffic to .pcap
    files -- see src/pcap_export.py. Disabled by default; opting in means
    setting enabled: true in config.yaml."""

    enabled: bool = False
    output_dir: str = "captures/"
    # rotate to a new file once a single export would exceed this size
    max_file_size_mb: int = 50
    # how many seconds of buffered context to keep around/export alongside
    # the packet that actually triggered a critical event
    capture_window_seconds: int = 10


@dataclass
class AutoBlockConfig:
    """Automatic firewall blocking of source IPs behind critical events --
    see src/auto_block.py. Disabled by default, and dry_run defaults to
    true even once enabled, so opting in never silently blocks real traffic
    -- see README.md "Automatic Blocking" for the full safety rundown."""

    enabled: bool = False
    # minutes a block stays in place before AutoBlocker lifts it again; 0 = permanent
    block_duration_minutes: int = 60
    # only events at or above this level get blocked -- see EVENT_SEVERITY /
    # SEVERITY_LEVELS in src/notifications.py for the ranking
    min_severity: str = "high"
    # log what WOULD be blocked instead of actually touching the firewall
    dry_run: bool = True


@dataclass
class AbuseIPDBConfig:
    """AbuseIPDB API settings for threat intel lookups."""

    enabled: bool = False
    api_key: str = ""
    # how far back (days) AbuseIPDB should look for reports on an IP
    max_age_days: int = 90


@dataclass
class VirusTotalConfig:
    """VirusTotal API settings for threat intel lookups."""

    enabled: bool = False
    api_key: str = ""


@dataclass
class ThreatIntelConfig:
    """AbuseIPDB/VirusTotal reputation lookups for the source IPs behind
    critical events -- see src/threat_intel.py. Disabled by default since
    both services need an API key the user has to supply; either one can be
    used on its own."""

    enabled: bool = False
    abuseipdb: AbuseIPDBConfig = field(default_factory=AbuseIPDBConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    # only events at or above this level get looked up, to conserve API
    # quota -- see EVENT_SEVERITY / SEVERITY_LEVELS in src/notifications.py
    min_severity: str = "high"
    # hours a lookup result for an IP is reused before querying again
    cache_ttl_hours: int = 24


@dataclass
class WebConfig:
    """Flask dashboard settings."""

    host: str = "127.0.0.1"
    port: int = 5000
    refresh_interval: int = 5
    # basic auth creds -- leave blank to disable auth entirely (default, since
    # this is meant to run on localhost anyway)
    username: str = ""
    password: str = ""
    # serves over https w/ a self-signed cert, generated automatically the
    # first time if it's not already sitting at cert_file/key_file
    https: bool = False
    cert_file: str = "certs/netsentry-cert.pem"
    key_file: str = "certs/netsentry-key.pem"


@dataclass
class Config:
    """Top-level NetSentry configuration."""

    # network interface(s) to capture on. config.yaml may specify a single
    # name (str) or a list of names -- a string is normalized into a
    # one-item list by _normalize_interfaces() below, so everything past
    # load_config() only ever deals with a list. Empty means "let Scapy pick
    # the OS default". The CLI's -i/--interface flag (main.py) takes
    # precedence over this when given.
    interfaces: List[str] = field(default_factory=list)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    arp_spoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)
    dos: DosConfig = field(default_factory=DosConfig)
    traffic_anomaly: TrafficAnomalyConfig = field(default_factory=TrafficAnomalyConfig)
    dns_tunnel: DnsTunnelConfig = field(default_factory=DnsTunnelConfig)
    tls_anomaly: TlsAnomalyConfig = field(default_factory=TlsAnomalyConfig)
    ml_anomaly: MlAnomalyConfig = field(default_factory=MlAnomalyConfig)
    # source IPs/CIDR ranges that skip detection entirely, see src/engine.py
    whitelist: List[str] = field(default_factory=list)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    web: WebConfig = field(default_factory=WebConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    pcap_export: PcapExportConfig = field(default_factory=PcapExportConfig)
    auto_block: AutoBlockConfig = field(default_factory=AutoBlockConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)


def _merge_dataclass(instance: Any, overrides: Dict[str, Any]) -> Any:
    """Recursively shoves override values from a dict onto a dataclass.

    Keys that don't match a known field are just skipped, not raised -- if
    someone typos a key in their yaml we don't want that to crash the whole
    app on startup, better to silently ignore it (yeah I know, not great for
    debugging, but this is a small tool not a bank).
    """
    for f in fields(instance):
        if f.name not in overrides:
            continue
        value = overrides[f.name]
        current = getattr(instance, f.name)
        if is_dataclass(current) and isinstance(value, dict):
            _merge_dataclass(current, value)
        else:
            setattr(instance, f.name, value)
    return instance


def _normalize_interfaces(config: Config) -> None:
    """The one place a single `interfaces: eth0` string gets turned into a
    one-item list -- every other consumer (sniffer.py, main.py) only ever
    has to deal with `config.interfaces` as a list."""
    if isinstance(config.interfaces, str):
        config.interfaces = [config.interfaces]


def load_config(path: str | Path | None) -> Config:
    """Loads config from the yaml file at `path`, defaults for anything
    that's missing. If path is None or just doesn't exist we don't error out,
    we just hand back the defaults -- makes it easy to run without a config
    file at all. Only raises if the file's there but isn't a proper yaml
    mapping (e.g. someone put a list at the top level, whatever).
    """
    config = Config()
    if path is not None:
        file_path = Path(path)
        if file_path.exists():
            with file_path.open("r", encoding="utf-8") as handle:
                raw = yaml.safe_load(handle) or {}

            if not isinstance(raw, dict):
                raise ValueError(f"Configuration file {file_path} must contain a YAML mapping")

            config = _merge_dataclass(config, copy.deepcopy(raw))

    _normalize_interfaces(config)
    return config
