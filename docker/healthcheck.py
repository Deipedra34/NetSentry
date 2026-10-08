"""Docker HEALTHCHECK for NetSentry: pings the dashboard's /healthz endpoint.

Reads the same config the app does (config.yaml plus the NETSENTRY_* env
overrides), so it follows whatever port, http/https and basic auth settings
are actually in use. Only uses the standard library for the request itself,
so the image doesn't need curl. Exits 0 when healthy, 1 otherwise.
"""

from __future__ import annotations

import base64
import ssl
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.config import load_config  # noqa: E402


def main() -> int:
    config = load_config(REPO_ROOT / "config.yaml")

    # 0.0.0.0 / :: aren't connectable addresses, loopback reaches them fine
    host = config.web.host if config.web.host not in ("", "0.0.0.0", "::") else "127.0.0.1"
    scheme = "https" if config.web.https else "http"
    request = urllib.request.Request(f"{scheme}://{host}:{config.web.port}/healthz")

    if config.web.username and config.web.password:
        token = base64.b64encode(f"{config.web.username}:{config.web.password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")

    context = None
    if config.web.https:
        # the dashboard's cert is self-signed, nothing to verify it against
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(request, timeout=4, context=context) as response:
            return 0 if response.status == 200 else 1
    except Exception as exc:  # noqa: BLE001 - any failure just means unhealthy
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
