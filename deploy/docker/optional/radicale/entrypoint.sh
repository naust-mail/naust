#!/bin/bash
# Radicale CardDAV/CalDAV container entrypoint.
#
# Writes /etc/naust.conf from env vars, then runs the component runner
# for the radicale component (venv, plugin, config, log, namespace steps).
# The component reads MANAGEMENT_HOST and RUNTIME from the conf file and
# writes /etc/radicale/config with the correct bind address and management
# host - no sed patching needed.
#
# Environment variables:
#   PRIMARY_HOSTNAME   - required by write_naust_conf
#   STORAGE_ROOT       - path to persistent data volume
#   MANAGEMENT_HOST    - management container service name (default: management)
#   WEBMAIL_CLIENT     - which webmail is running (default: rav); controls
#                        whether the rav SQLite storage plugin is used

set -euo pipefail

NAUST=/opt/naust
source "$NAUST/deploy/docker/common-entrypoint.sh"

install_systemctl_stub
write_naust_conf

export RUNTIME=docker
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

source /etc/naust.conf
mkdir -p "$STORAGE_ROOT"

echo "Configuring Radicale..."
cd "$NAUST/setup"
python3 -m components.runner radicale

echo "Radicale setup complete. Starting Radicale..."

# RAV_DATA_DIR is only needed when using the rav SQLite storage backend.
if [ "${WEBMAIL_CLIENT:-rav}" = "rav" ]; then
    export RAV_DATA_DIR="$STORAGE_ROOT/rav"
fi

# The radicale_naust plugin lives outside the venv; mirror what the systemd unit sets.
export PYTHONPATH=/usr/local/lib/radicale-naust
exec /usr/local/lib/radicale/bin/python3 -m radicale \
    --config /etc/radicale/config
