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

    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    arp_spoof: ArpSpoofConfig = field(default_factory=ArpSpoofConfig)
    dos: DosConfig = field(default_factory=DosConfig)
    traffic_anomaly: TrafficAnomalyConfig = field(default_factory=TrafficAnomalyConfig)
    # source IPs/CIDR ranges that skip detection entirely, see src/engine.py
    whitelist: List[str] = field(default_factory=list)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    web: WebConfig = field(default_factory=WebConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    pcap_export: PcapExportConfig = field(default_factory=PcapExportConfig)


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


def load_config(path: str | Path | None) -> Config:
    """Loads config from the yaml file at `path`, defaults for anything
    that's missing. If path is None or just doesn't exist we don't error out,
    we just hand back the defaults -- makes it easy to run without a config
    file at all. Only raises if the file's there but isn't a proper yaml
    mapping (e.g. someone put a list at the top level, whatever).
    """
    config = Config()
    if path is None:
        return config

    file_path = Path(path)
    if not file_path.exists():
        return config

    with file_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Configuration file {file_path} must contain a YAML mapping")

    return _merge_dataclass(config, copy.deepcopy(raw))
