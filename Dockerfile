# NetSentry container image. docker-compose.yml next to this file is the
# easy way to run it -- see README.md "Docker" for the full rundown.
#
# Pinned to bookworm: the entrypoint relies on setpriv from its util-linux,
# and libpcap0.8 below is bookworm's package name.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Container-only overrides on top of config.yaml (see _ENV_OVERRIDES in
# src/config.py): serve the dashboard on all interfaces instead of
# 127.0.0.1 so it's reachable from outside the container, and keep the
# database and log file inside the bind-mounted data/ and logs/ folders.
ENV NETSENTRY_WEB_HOST=0.0.0.0 \
    NETSENTRY_DATABASE_PATH=data/netsentry.db \
    NETSENTRY_LOG_FILE=logs/netsentry.log

# libpcap + tcpdump for Scapy's live capture (Scapy also shells out to
# tcpdump to compile BPF filters such as the default "ip or arp").
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user NetSentry runs as. The container starts as root only so
# docker/entrypoint.sh can fix ownership of the bind-mounted folders, then
# it drops to this user for everything else. Live packet capture needs the
# NET_RAW / NET_ADMIN capabilities: grant them at runtime (cap_add in
# docker-compose.yml, or --cap-add on the docker CLI) rather than running as
# root or --privileged -- the entrypoint carries them over to this user.
# Dashboard-only mode (--web-only) needs neither.
RUN groupadd --gid 1000 netsentry \
    && useradd --uid 1000 --gid netsentry --home-dir /app --no-create-home \
        --shell /usr/sbin/nologin netsentry

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN mkdir -p data logs captures certs \
    && chown netsentry:netsentry data logs captures certs \
    && chmod +x docker/entrypoint.sh

# Dashboard port (web.port in config.yaml)
EXPOSE 5000

# SIGINT makes main.py shut down cleanly (session summary + db close) on
# `docker stop`, same as Ctrl+C on a native run
STOPSIGNAL SIGINT

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "docker/healthcheck.py"]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
# Capture on Scapy's default interface + the dashboard. Auto-block is forced
# into dry-run here no matter what config.yaml says -- see the warning in
# docker-compose.yml before changing that.
CMD ["python", "main.py", "--web", "--auto-block-dry-run"]
