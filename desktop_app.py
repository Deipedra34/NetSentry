#!/usr/bin/env python3
"""Desktop launcher for NetSentry -- opens a native window instead of a browser tab.

Same engine as main.py under the hood (capture + detectors + Flask dashboard),
just wrapped in a pywebview window so it feels like a real app instead of a
CLI tool you have to remember flags for.

Some examples (from the project root):

    Auto-pick the default interface and open the app window:
        python desktop_app.py

    Capture on a specific interface:
        python desktop_app.py -i "Ethernet"

    Just browse an existing database, no live capture:
        python desktop_app.py --web-only

Needs admin/root for live capture, same as main.py. Requires the extra
`pywebview` dependency -- see requirements-desktop.txt.

Unlike `main.py --web`, this always serves the dashboard over plain HTTP on
a loopback-only port with no Basic Auth, regardless of what config.yaml says
under `web:`. Self-signed HTTPS and a login prompt make sense for a page you
open in a real browser -- they're pointless (and often broken) for a page
this same process is loading into its own native window.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
from typing import List, Optional

from src.config import load_config
from src.database import Database
from src.engine import DetectionEngine, build_detectors
from src.logging_config import setup_logging
from src.sniffer import NetworkSniffer

logger = logging.getLogger("netsentry.desktop")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses the CLI args for the desktop launcher (a small subset of main.py's)."""
    parser = argparse.ArgumentParser(
        prog="netsentry-desktop",
        description="NetSentry desktop app: capture + dashboard in a native window.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (see 'python main.py --list-interfaces').",
        default=None,
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to a YAML configuration file (default: config.yaml).",
        default="config.yaml",
    )
    parser.add_argument(
        "--web-only",
        action="store_true",
        help="Only open the dashboard window (no packet capture); browse an existing database.",
    )
    return parser.parse_args(argv)


def _find_free_port(preferred: int) -> int:
    """Finds a free loopback port starting at `preferred`.

    Doesn't touch config.web.port -- that one's for the browser-facing
    dashboard from `main.py --web`, which might already be running. Picking
    our own port means the two never fight over the same one.
    """
    for port in range(preferred, preferred + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError("Could not find a free local port for the dashboard.")


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point: parses args, loads config, starts capture + dashboard in
    the background, and blocks on a native window until it's closed."""
    args = parse_args(argv)

    try:
        import webview
    except ImportError:
        print(
            "Error: pywebview is not installed. Install it with "
            "'pip install -r requirements-desktop.txt'.",
            file=sys.stderr,
        )
        return 1

    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"Error: invalid configuration file: {exc}", file=sys.stderr)
        return 1

    setup_logging(level=config.logging.level, log_file=config.logging.file)
    logger.info("NetSentry desktop app starting up")

    database = Database(config.database.path)

    sniffer: Optional[NetworkSniffer] = None
    if not args.web_only:
        try:
            detectors = build_detectors(config, enabled=None)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            database.close()
            return 1

        if detectors:
            engine = DetectionEngine(database, detectors)
            sniffer = NetworkSniffer(interface=args.interface, packet_handler=engine.handle_packet)

            def _capture() -> None:
                try:
                    sniffer.start()  # type: ignore[union-attr]
                except (PermissionError, RuntimeError) as exc:
                    logger.error("Live capture didn't start: %s", exc)
                    logger.info("Continuing in dashboard-only mode.")

            threading.Thread(target=_capture, name="netsentry-capture", daemon=True).start()

    from src.web import create_app

    app = create_app(database, refresh_interval=config.web.refresh_interval)
    port = _find_free_port(config.web.port)

    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        name="netsentry-web",
        daemon=True,
    ).start()

    webview.create_window(
        "NetSentry",
        f"http://127.0.0.1:{port}/",
        width=1100,
        height=750,
        min_size=(800, 500),
    )
    webview.start()

    if sniffer is not None:
        sniffer.stop()
    database.close()
    logger.info("NetSentry desktop app closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
