#!/bin/bash
# FileBrowser container entrypoint.
#
# Runs the filebrowser component (downloads binary, writes auth hook,
# initialises database), then starts FileBrowser.
# The auth hook calls the management daemon's /auth/verify endpoint - no
# Dovecot dependency.
#
# Environment variables:
#   PRIMARY_HOSTNAME   - used by the setup script for branding
#   STORAGE_ROOT       - path to the persistent data volume
#   MANAGEMENT_HOST    - management container service name (default: management)

set -euo pipefail

NAUST=/opt/naust
source "$NAUST/deploy/docker/common-entrypoint.sh"

install_systemctl_stub
write_naust_conf

export RUNTIME=docker

cd "$NAUST"

export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

source /etc/naust.conf
mkdir -p "$STORAGE_ROOT"

echo "Configuring FileBrowser..."
cd "$NAUST/setup"
python3 -m components.runner filebrowser
cd "$NAUST"

echo "FileBrowser setup complete. Starting FileBrowser and control socket server via supervisord..."
exec /usr/bin/supervisord -c /opt/naust/deploy/docker/optional/filebrowser/supervisord.conf
