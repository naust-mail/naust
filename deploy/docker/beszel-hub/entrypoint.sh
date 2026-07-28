#!/bin/bash
# Beszel hub container entrypoint.
#
# Runs the beszel component itself (creates the beszel system user,
# generates the hub<->agent Ed25519 keypair + agent.env/config.yml and the
# seed script onto the shared storage volume), then starts the hub. Self-
# contained, matching munin's Docker pattern - management runs no Python setup
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

SEED_SCRIPT="/usr/local/lib/beszel-seed.py"
if [ ! -f "$SEED_SCRIPT" ]; then
    echo "ERROR: ${SEED_SCRIPT} was not generated - is MONITORING_TOOL=beszel set?" >&2
    exit 1
fi

echo "Beszel hub configured. Starting..."
# Seed the single trusted-header user once the hub is listening. Backgrounded
# because the hub must be serving the create-user API first; the script polls
# for it and no-ops if a user already exists. No password is ever persisted.
# Docker's init (tini) reaps this short-lived process when it exits.
python3 "$SEED_SCRIPT" &
exec beszel serve --http "0.0.0.0:8090" --dir "${STORAGE_ROOT}/beszel"
