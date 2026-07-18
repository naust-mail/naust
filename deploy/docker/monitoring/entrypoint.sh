#!/bin/bash
# Munin monitoring container entrypoint.
#
# Runs the munin component to write configuration and activate plugins,
# then starts munin and munin-node via supervisord.

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

# Redirect munin's HTML output to the shared storage volume so the management
# daemon (on a separate container) can serve it at /admin/munin/.
mkdir -p "$STORAGE_ROOT/munin/www"
chown munin:munin "$STORAGE_ROOT/munin/www" 2>/dev/null || true
rm -rf /var/cache/munin/www
mkdir -p /var/cache/munin
ln -sfn "$STORAGE_ROOT/munin/www" /var/cache/munin/www

# munin-cgi-graph renders into this scratch dir; muninweb runs as the
# munin user, so it must exist and be writable before supervisord starts
# (same requirement the bare-metal muninweb unit satisfies with mkdir).
mkdir -p /var/lib/munin/cgi-tmp
chown munin:munin /var/lib/munin/cgi-tmp

echo "Configuring Munin..."
cd "$NAUST/setup"
python3 -m components.runner munin
cd "$NAUST"

echo "Munin setup complete. Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
