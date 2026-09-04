#!/usr/bin/env python3
"""Entry point for NetSentry, run this to start it up.

Some examples (from the project root):

    List available interfaces:
        python main.py --list-interfaces

    Capture on eth0 with all detectors + the web dashboard on:
        sudo python main.py -i eth0 --web

    Only care about port scans and SYN floods:
        sudo python main.py -i eth0 --detectors port_scan,dos

    Just want to browse events already in the db, no live capture:
        python main.py --web-only

Note you'll need root/admin rights for real packet capture (scapy needs it).
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
from typing import List, Optional

from src.auto_block import AutoBlocker
from src.config import Config, load_config
from src.database import Database
from src.engine import DETECTOR_NAMES, DetectionEngine, build_detectors
from src.logging_config import setup_logging
from src.notifications import NotificationDispatcher
from src.pcap_export import PcapExporter
from src.sniffer import NetworkSniffer, list_interfaces

logger = logging.getLogger("netsentry.main")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses the CLI args (defaults to sys.argv[1:] if you don't pass anything)."""
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="NetSentry: a lightweight Python network intrusion detection system.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (see --list-interfaces).",
        default=None,
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to a YAML configuration file (default: config.yaml).",
        default="config.yaml",
    )
    parser.add_argument(
        "--detectors",
        help=(
            "Comma-separated list of detectors to enable, overriding config.yaml. "
            f"Choices: {', '.join(DETECTOR_NAMES)}."
        ),
        default=None,
    )
    parser.add_argument(
        "--bpf-filter",
        help="Berkeley Packet Filter expression to restrict capture (default: 'ip or arp').",
        default="ip or arp",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Also start the Flask web dashboard alongside packet capture.",
    )
    parser.add_argument(
        "--web-only",
        action="store_true",
        help="Only run the web dashboard (no packet capture); browse an existing database.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    auto_block_group = parser.add_mutually_exclusive_group()
    auto_block_group.add_argument(
        "--auto-block-dry-run",
        action="store_true",
        help="Force auto_block into dry-run mode (log only, never touch the firewall), overriding config.yaml.",
    )
    auto_block_group.add_argument(
        "--auto-block-live",
        action="store_true",
        help=(
            "Force auto_block into live mode (actually apply firewall rules), overriding "
            "config.yaml. Only use this once you're sure -- see README.md 'Automatic Blocking'."
        ),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the NetSentry version and exit.",
    )
    return parser.parse_args(argv)


def run_web_dashboard(database: Database, config: Config, blocking: bool) -> Optional[threading.Thread]:
    """Starts the Flask dashboard.

    blocking=True runs it in the current thread and never comes back (until
    you Ctrl+C it). blocking=False spins it up on a daemon thread instead and
    returns right away, which is what we want when the sniffer also needs the
    main thread.
    """
    from src.web import create_app

    app = create_app(
        database,
        refresh_interval=config.web.refresh_interval,
        username=config.web.username,
        password=config.web.password,
    )

    ssl_context = None
    scheme = "http"
    if config.web.https:
        from src.web import ensure_self_signed_cert

        cert_file, key_file = ensure_self_signed_cert(config.web.cert_file, config.web.key_file)
        ssl_context = (str(cert_file), str(key_file))
        scheme = "https"

    def _run() -> None:
        app.run(
            host=config.web.host,
            port=config.web.port,
            debug=False,
            use_reloader=False,
            ssl_context=ssl_context,
        )

    url = f"{scheme}://{config.web.host}:{config.web.port}"
    if blocking:
        logger.info("Starting web dashboard at %s", url)
        _run()
        return None

    thread = threading.Thread(target=_run, name="netsentry-web", daemon=True)
    thread.start()
    logger.info("Web dashboard running at %s", url)
    return thread


def main(argv: Optional[List[str]] = None) -> int:
    """Actual entry point. Parses args, loads config, wires everything
    together and kicks off capture (or just the dashboard if --web-only).
    Returns 0 on success, something else if it blew up.
    """
    args = parse_args(argv)

    if args.version:
        from src import __version__
        print(f"NetSentry {__version__} - by Deipedra")
        return 0

    if args.list_interfaces:
        try:
            interfaces = list_interfaces()
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        if not interfaces:
            print("No network interfaces were found.")
        else:
            print("Available network interfaces:")
            for name in interfaces:
                print(f"  - {name}")
        return 0

    try:
        config: Config = load_config(args.config)
    except ValueError as exc:
        print(f"Error: invalid configuration file: {exc}", file=sys.stderr)
        return 1

    if args.auto_block_dry_run:
        config.auto_block.dry_run = True
    elif args.auto_block_live:
        config.auto_block.dry_run = False

    setup_logging(level=config.logging.level, log_file=config.logging.file)
    logger.info("NetSentry starting up")

    if config.auto_block.enabled:
        if config.auto_block.dry_run:
            logger.info("Auto-block is enabled in DRY-RUN mode -- no firewall rules will be applied.")
        else:
            logger.warning(
                "Auto-block is enabled in LIVE mode -- firewall rules WILL be applied to block source IPs."
            )

    database = Database(config.database.path)

    if args.web_only:
        run_web_dashboard(database, config, blocking=True)
        return 0

    detector_names = args.detectors.split(",") if args.detectors else None
    detector_names = [name.strip() for name in detector_names] if detector_names else None
    try:
        detectors = build_detectors(config, enabled=detector_names)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not detectors:
        print("Error: no detectors are enabled; nothing to do.", file=sys.stderr)
        return 1

    logger.info("Active detectors: %s", ", ".join(d.name for d in detectors))
    notifier = NotificationDispatcher(config)
    pcap_exporter = PcapExporter(config)
    auto_blocker = AutoBlocker(config, database, whitelist=config.whitelist)
    engine = DetectionEngine(
        database,
        detectors,
        whitelist=config.whitelist,
        notifier=notifier,
        pcap_exporter=pcap_exporter,
        auto_blocker=auto_blocker,
    )

    if args.web:
        run_web_dashboard(database, config, blocking=False)

    sniffer = NetworkSniffer(
        interface=args.interface,
        packet_handler=engine.handle_packet,
        bpf_filter=args.bpf_filter,
    )

    try:
        sniffer.start()
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logger.error("Permission error starting capture: %s", exc)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logger.error("Failed to start capture: %s", exc)
        return 1
    except KeyboardInterrupt:
        logger.info("Capture stopped by user (Ctrl+C)")
        print("\nStopping NetSentry...")
        return 0
    finally:
        logger.info(
            "Session summary: %d packets processed, %d events raised",
            engine.packet_count,
            engine.event_count,
        )
        database.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
