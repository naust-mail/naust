#!/bin/bash
# Beszel hub container entrypoint.
#
# Runs the beszel component itself (creates the beszel system user,
# generates the hub<->agent Ed25519 keypair + hub.env/agent.env/config.yml
# onto the shared storage volume), then starts the hub. Self-contained,
# matching munin's Docker pattern - management runs no Python setup
# component of its own in Docker, so nothing else generates these files.

set -euo pipefail

NAUST=/opt/naust
source "$NAUST/deploy/docker/common-entrypoint.sh"

install_systemctl_stub
write_naust_conf

export RUNTIME=docker

cd "$NAUST"

source /etc/naust.conf
mkdir -p "$STORAGE_ROOT"

echo "Configuring Beszel..."
cd "$NAUST/setup"
python3 -m components.runner beszel
cd "$NAUST"

HUB_ENV="${STORAGE_ROOT}/beszel/hub.env"
if [ ! -f "$HUB_ENV" ]; then
    echo "ERROR: ${HUB_ENV} was not generated - is MONITORING_TOOL=beszel set?" >&2
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "$HUB_ENV"
set +a

echo "Beszel hub configured. Starting..."
exec beszel serve --http "0.0.0.0:8090" --dir "${STORAGE_ROOT}/beszel"
