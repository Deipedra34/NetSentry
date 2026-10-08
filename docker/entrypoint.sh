#!/bin/sh
# Container entrypoint for NetSentry.
#
# The container starts as root only long enough to prepare the bind-mounted
# folders, then drops to the unprivileged "netsentry" user before running
# the actual command (CMD in the Dockerfile / `command` in docker-compose.yml).
set -e

cd /app

if [ "$(id -u)" != "0" ]; then
    # already started as a non-root user (e.g. `docker run --user netsentry`),
    # nothing to fix up -- fine for --web-only, but live capture won't have
    # its capabilities this way
    exec "$@"
fi

# data/, logs/ and captures/ are bind mounts, and Docker creates any that
# don't exist on the host yet as root:root -- hand them to the netsentry
# user so the database, logs and pcap exports can actually be written.
mkdir -p data logs captures
chown netsentry:netsentry data logs captures

# A non-root process doesn't keep root's capabilities, so cap_add alone
# isn't enough for capture as netsentry. Carry NET_RAW/NET_ADMIN over as
# ambient capabilities, but only the ones this container was granted
# (NET_RAW is in Docker's default set, NET_ADMIN only comes from cap_add).
bounding=$(awk '/^CapBnd:/ {print $2}' /proc/self/status)
caps=""
if [ $(( 0x$bounding >> 13 & 1 )) -eq 1 ]; then
    caps="+net_raw"
fi
if [ $(( 0x$bounding >> 12 & 1 )) -eq 1 ]; then
    caps="${caps:+$caps,}+net_admin"
fi

if [ -n "$caps" ]; then
    exec setpriv --reuid=netsentry --regid=netsentry --init-groups \
        --inh-caps="$caps" --ambient-caps="$caps" "$@"
fi
exec setpriv --reuid=netsentry --regid=netsentry --init-groups "$@"
